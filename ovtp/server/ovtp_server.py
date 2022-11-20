import json
import os
import rsa
import pathlib
import ovcrypt
import asyncio
import ov_aes_cipher
import oe_common
from ovtp.server import cfg, short_key_to_full, get_short_rsa_key


class OvtpServer:
    class Handler:
        def __init__(self, server, reader, writer):
            self.server = server
            self.reader = reader
            self.writer = writer
            self.new_message_timeout = 30
            self.aes = None
            self.cr = ovcrypt.OvCrypt()

        def check_key_is_master(self, key):
            auth_keys_path = os.path.join(cfg['auth_keys_dir'], 'authorized_keys')
            os.makedirs(cfg['auth_keys_dir'], exist_ok=True)
            # oe_common.check_create_dir(auth_keys_path)
            saved_master_keys = []
            if os.path.isfile(auth_keys_path):
                with open(auth_keys_path, 'rb') as f:
                    for line in f:
                        if self.server.debug:
                            print(f'found saved rsa key: {line}')
                        saved_master_keys.append(rsa.PublicKey.load_pkcs1(short_key_to_full(line)))
            if key not in saved_master_keys:
                master_keys = self.cr.get_master_keys()
                for m_key in master_keys:
                    if m_key not in saved_master_keys:
                        saved_master_keys.append(m_key)
                with open(auth_keys_path, 'wb') as f:
                    f.write(b'\n'.join([get_short_rsa_key(rsa.PublicKey.save_pkcs1(k).replace(b'\n', b'')) for k in
                                        saved_master_keys]))
            if key in saved_master_keys:
                if self.server.debug:
                    print(f'Key found in master keys: {key}')
                return True, True
            if self.server.verbose:
                print('Key not found in master keys')
            return False, 'no_key'

        @staticmethod
        def unpad_ov_header(s):
            return bytes(s).rstrip(b'\x00')

        async def parse_header(self, read_bytes):
            length = int.from_bytes(await asyncio.wait_for(self.reader.read(read_bytes), timeout=30), byteorder='big')
            if length > 0:
                return await asyncio.wait_for(self.reader.read(length), timeout=30)
            else:
                return None

        async def receive_headers(self):
            # Waiting for self.headers_timeout, then set up it to standard 30 seconds
            # This needed to make long timeout between messages, without closing the connection
            data_type = self.unpad_ov_header(
                await asyncio.wait_for(self.reader.read(10), timeout=self.new_message_timeout)
            )
            self.new_message_timeout = 30
            if self.server.debug:
                print(f'Data type is {data_type}')

            filename_b = await self.parse_header(4)
            filename = oe_common.fix_block_encoding_errors(filename_b) if filename_b else ''
            header_key = await self.parse_header(4)
            header_iv = await self.parse_header(4)
            header_signed = True if await asyncio.wait_for(self.reader.read(1), timeout=5) else False  # y/n
            if data_type == b'file':
                header_filesize = int.from_bytes(await asyncio.wait_for(self.reader.read(14), timeout=30),
                                                 byteorder='big')
            else:
                header_filesize = None

            return data_type, filename, header_key, header_iv, header_signed, header_filesize

        async def read_with_prefix(self):
            prefix = (await asyncio.wait_for(self.reader.readline(), timeout=30)).rstrip()
            pk_data = b''
            if prefix != b'':
                msg_len = int(prefix[:-3])
                pk_data = await asyncio.wait_for(self.reader.readexactly(msg_len), timeout=5)
            return pk_data

        async def write_with_prefix(self, data, prefix=False):
            if prefix:
                prefix_pad = b'pad'
            else:
                prefix_pad = b'\x00' * 3
            self.writer.write(b'%d%b\n%b' % (len(data), prefix_pad, data))
            await self.writer.drain()

        async def close_connection(self, address):
            print(f'Closing connection with {self.str_ip(address)}')
            self.writer.write_eof()
            await self.writer.drain()
            self.writer.close()
            await self.writer.wait_closed()

        @staticmethod
        def str_ip(address):
            if isinstance(address, tuple) and len(address) > 1:
                return f'{address[0]}:{address[1]}'
            else:
                return 'Unknown'

        async def handle_packet(self):
            ov_sign = None
            address = self.writer.get_extra_info('peername')
            print(f"Connection from {self.str_ip(address)}")
            while True:
                try:
                    (data_type,
                     filename,
                     header_key,
                     header_iv,
                     header_signed,
                     header_filesize) = await self.receive_headers()
                except (asyncio.exceptions.TimeoutError, ConnectionResetError) as e:
                    print(f'{type(e).__name__}({e}) occurred')
                    await self.close_connection(address)
                    return False

                read_part_counter = 0
                received_len = 0

                data = b''
                data_parts = []
                # last_part = False

                if header_iv and header_key:
                    self.aes = ov_aes_cipher.AESCipher(
                        hash_key=rsa.decrypt(header_key, self.cr.private_key),
                        iv=rsa.decrypt(header_iv, self.cr.private_key)
                    )
                else:
                    self.aes = ov_aes_cipher.AESCipher('pass')

                if data_type == b'file' and os.path.isfile(filename):
                    os.remove(filename)

                if address in self.server.saved_keys:
                    ov_sign = ovcrypt.OvSign(self.server.saved_keys[address].key)
                part_data = b''
                msg_pad = b''
                dc = oe_common.DinConsole()
                sc = oe_common.SpeedChecker('bits / second', 4096)
                rx_bytes = 0
                file_size_str = oe_common.convert_size(header_filesize) if header_filesize else 'no size'

                if self.reader.at_eof():
                    print(f'Received eof from {self.str_ip(address)}')
                    await self.close_connection(address)
                    return False

                while True:
                    read_part_counter += 1

                    if data_type == b'':
                        print('Data type empty, closing...')
                        await self.close_connection(address)
                        return False
                    elif data_type == b'public_key':
                        # print('Request for public key')
                        prefix = (await asyncio.wait_for(self.reader.readline(), timeout=5)).rstrip()
                        # print(f'prefix: {prefix}')
                        pk_data = b''
                        if prefix != b'':
                            msg_len = int(prefix[:-3])
                            # print(f'Receiving {msg_len} bytes')
                            pk_data = await asyncio.wait_for(self.reader.readexactly(msg_len), timeout=5)
                        # print(f'received: {pk_data}')
                        self.server.saved_keys[address] = self.cr.Key(rsa.PublicKey.load_pkcs1(
                            pk_data))
                        # self.writer.write(rsa.PublicKey.save_pkcs1(self.cr.public_key))
                        await self.write_with_prefix(rsa.PublicKey.save_pkcs1(self.cr.public_key))
                        break
                    elif data_type == b'auth_req':
                        prefix = (await asyncio.wait_for(self.reader.readline(), timeout=5)).rstrip()
                        pk_data = b''
                        if prefix != b'':
                            msg_len = int(prefix[:-3])
                            # print(f'Receiving {msg_len} bytes')
                            pk_data = await asyncio.wait_for(self.reader.readexactly(msg_len), timeout=5)
                        if self.server.debug:
                            print(f'pk_data: {pk_data}')
                        v_string = oe_common.get_rnd_string(100).encode()
                        self.server.saved_keys[address].verification_string = v_string
                        # self.writer.write(rsa.encrypt(v_string, self.server.saved_keys[address].key))
                        await self.write_with_prefix(rsa.encrypt(v_string, self.server.saved_keys[address].key))
                        if self.server.debug:
                            print(f'generated string: {v_string}')
                        r = await self.read_with_prefix()
                        sign = await self.reader.read(256)
                        break
                    elif data_type == b'auth_resp':
                        if self.server.debug:
                            print(f'Received auth resp')
                    else:
                        if address in self.server.saved_keys and self.server.saved_keys[address].auth:
                            if self.server.debug:
                                print(f'Data type: {data_type}')
                                print('Key already authorized')
                            if data_type == b'get_file':
                                if self.server.debug:
                                    print(f'Get file request: {filename}')
                                if os.path.isfile(filename):
                                    ov_sign = ovcrypt.OvSign(self.cr.private_key)
                                    file_size = os.path.getsize(filename)
                                    tx_bytes = 0
                                    with open(filename, 'rb') as f:
                                        for chunk in iter(lambda: f.read(4096), b''):
                                            ov_sign.update_hash(chunk)
                                            await self.write_with_prefix(
                                                self.aes.encrypt_part(self.aes.pad(chunk)),
                                                prefix=True
                                            )
                                            # await self.writer.drain()
                                            tx_bytes = tx_bytes + len(chunk)
                                            if self.server.debug or self.server.verbose:
                                                dc.update('  Sent %s / %s, %s%%, speed: %s' % (
                                                    oe_common.convert_size(tx_bytes),
                                                    file_size_str,
                                                    round(tx_bytes / file_size * 100),
                                                    sc.get_speed()
                                                ))
                                    # sign_message = b'ovsign'
                                    # padded_sign_message = sign_message + b'\x00' * (256 - len(sign_message))
                                    # await self.write_with_prefix(padded_sign_message)
                                    await self.write_with_prefix(self.cr.ov_pad(b'ov_sign', 256))
                                    self.writer.write(ov_sign.get_sign())
                                    await self.writer.drain()
                                else:
                                    await self.write_with_prefix(self.cr.ov_pad(b'file_not_exists', 256))
                                    # await self.write_with_prefix(self.cr.ov_pad(b'transmission_ended', 256))
                                    # raise RuntimeError(f'Requested from {address} file not exists: {filename}')
                                break
                            elif data_type == b'get_hash':
                                if self.server.debug:
                                    print(f'Get file hash request: {filename}')
                                if os.path.isfile(filename):
                                    ov_sign = ovcrypt.OvSign()  # key is not needed, we don't get sign, only hash
                                    with open(filename, 'rb') as f:
                                        for chunk in iter(lambda: f.read(4096), b''):
                                            ov_sign.update_hash(chunk)
                                        # await self.write_with_prefix(self.aes.encrypt(ov_sign.get_hash()))
                                        await self.write_with_prefix(rsa.encrypt(
                                            ov_sign.get_hash(),
                                            self.server.saved_keys[address].key
                                        ))
                                else:
                                    await self.write_with_prefix(rsa.encrypt(
                                        b'file_not_exists',
                                        self.server.saved_keys[address].key
                                    ))
                                    # raise RuntimeError(f'Requested from {address} file not exists: {filename}')
                                break
                        else:
                            # self.writer.write(aes.encrypt('Access denied'.encode()))
                            # self.writer.drain()
                            await self.write_with_prefix(self.aes.encrypt('Access denied'.encode()))
                            self.writer.close()
                            await self.writer.wait_closed()
                            raise RuntimeError('Error, key not authorized!')

                    try:
                        # part_data = await self.reader.readexactly(4096)
                        prefix = (await asyncio.wait_for(self.reader.readline(), timeout=5)).rstrip()
                        # print(f'prefix: {prefix}')
                        if prefix != b'':
                            msg_pad = prefix[-3:]
                            msg_len = int(prefix[:-3])
                            # print(f'Receiving {msg_len} bytes')
                            part_data = await asyncio.wait_for(self.reader.readexactly(msg_len), timeout=5)
                            if self.server.debug:
                                print(f'Received: {part_data}')
                    except asyncio.exceptions.IncompleteReadError as e:
                        # part_data = e.partial
                        # last_part = True
                        raise RuntimeError("incomplete read is not supported")

                    if len(part_data) > 0:
                        # data += part_data
                        if len(part_data) == 256:
                            # print('len is 256, breaking')
                            if part_data.rstrip(b'\x00') == b'ovsign':
                                received_sign = await asyncio.wait_for(self.reader.readexactly(256), timeout=5)
                                if self.server.debug:
                                    print('ovsign received (%sB): %s' % (len(received_sign), received_sign))
                                if data_type != b'auth_resp':
                                    if ov_sign.get_verification_result(received_sign):
                                        # self.writer.write(aes.encrypt(b'File sign ok'))
                                        if self.server.debug:
                                            print(f'Sign ok, expected {ov_sign.get_hash()}')
                                        await self.write_with_prefix(self.aes.encrypt(b'Sign ok'))
                                    else:
                                        # self.writer.write(aes.encrypt(b'File sign error'))
                                        if self.server.debug:
                                            print(f'Sign error, expected {ov_sign.get_hash()}')
                                        await self.write_with_prefix(self.aes.encrypt(b'Sign error'))
                                        return
                                break
                        if data_type == b'file':
                            if filename[0] != '/':
                                filename = os.path.join(pathlib.Path().absolute(), filename)
                            oe_common.check_create_dir(filename)
                            part_data_decoded = self.aes.decrypt_part(part_data)
                            if msg_pad == b'pad':
                                part_data_decoded = self.aes.unpad(part_data_decoded)
                            ov_sign.update_hash(part_data_decoded)
                            with open(filename, 'ab') as f:
                                f.write(part_data_decoded)
                                # print(f'part {read_part_counter} writed')
                        else:
                            part_data_decoded = self.aes.decrypt(part_data)
                            if msg_pad == b'pad':
                                part_data_decoded = self.aes.unpad(part_data_decoded)
                            if self.server.debug:
                                print(f'Decoded part data: {part_data_decoded}')
                            data_parts.append(part_data_decoded)
                            ov_sign.update_hash(part_data_decoded)
                        received_len += len(part_data)

                        if received_len and header_filesize:
                            rx_bytes = rx_bytes + len(part_data)
                            if self.server.debug or self.server.verbose:
                                dc.update('  Received %s / %s, %s%%, speed: %s' % (
                                    oe_common.convert_size(rx_bytes),
                                    file_size_str,
                                    round(rx_bytes / (header_filesize if header_filesize else 0) * 100),
                                    sc.get_speed()
                                ))
                        else:
                            if self.server.debug or self.server.verbose:
                                print(f'  Received {read_part_counter}')
                if self.server.debug or self.server.verbose:
                    dc.clear()
                if self.server.debug or self.server.verbose:
                    print(f'Received {oe_common.convert_size(received_len)} from {address}')
                if data_type == b'message':
                    data = b''.join(data_parts)
                    del data_parts
                    dec_data = oe_common.fix_block_encoding_errors(data)
                    if self.server.debug or self.server.verbose:
                        print('message:', dec_data)
                    status, description = self.server.callback(True, dec_data)
                    d = json.dumps({'status': status, 'description': description}).encode()
                    await self.write_with_prefix(self.aes.encrypt(d))
                    self.new_message_timeout = cfg['new_message_timeout'] * 60
                elif data_type == b'auth_resp':
                    data = b''.join(data_parts)
                    del data_parts
                    if self.server.debug:
                        print(f'auth resp is: {data}')
                    if data == self.server.saved_keys[address].verification_string:
                        status, response = self.check_key_is_master(self.server.saved_keys[address].key)
                        if status:
                            # self.writer.write(aes.encrypt('auth successful'.encode()))
                            await self.write_with_prefix(self.aes.encrypt('auth successful'.encode()))
                            self.server.saved_keys[address].auth = True
                        else:
                            if self.server.verbose:
                                print(f'Auth failed: {response}')
                            # self.writer.write(self.aes.encrypt('auth failed 1'.encode()))
                            await self.write_with_prefix(self.aes.encrypt('auth failed 1'.encode()))
                    else:
                        if self.server.verbose:
                            print(f'Verification string is not valid')
                        # self.writer.write(self.aes.encrypt('auth failed 2'.encode()))
                        await self.write_with_prefix(self.aes.encrypt('auth failed 2'.encode()))
                await self.writer.drain()
                if self.server.debug:
                    print(f'End of packet {address}')

    def __init__(self, callback, verbose=None, debug=None):
        self.server = None
        self.callback = callback
        self.saved_keys = {}
        self.verbose = verbose
        self.debug = debug

    async def run_packet_handler(self, reader, writer):
        handler = self.Handler(self, reader, writer)
        await handler.handle_packet()

    def get_sockets(self):
        return ', '.join(str(sock.getsockname()) for sock in self.server.sockets)

    async def run_server(self):
        self.server = await asyncio.start_server(
            self.run_packet_handler, cfg['server_ip'], cfg['server_port']
        )
        # print(f'Serving on {self.get_sockets}')
        async with self.server:
            await self.server.serve_forever()
