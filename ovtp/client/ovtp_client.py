import os
import rsa
import pathlib
import ovcrypt
import asyncio
import oe_common
import ov_aes_cipher
import json
from ovtp.client import cfg


script_run = True


class OvtpClient:
    def __init__(self, server_ip, server_port=None, debug=False, verbose=False):
        self.uid = oe_common.get_rnd_string(10).lower()
        self.cr = ovcrypt.OvCrypt()
        self.reader = None
        self.writer = None
        self.server_public_key = None
        self.encrypted_connection = False
        self.server_address = server_ip
        if server_port:
            self.server_port = server_port
        else:
            self.server_port = cfg['default_server_port']
        self.debug = debug
        self.verbose = verbose
        self.authorized = False
        self.connected = False
        self.aes = None
        self.loop = asyncio.new_event_loop()

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(
            self.server_address, self.server_port
        )
        self.connected = True

    async def reconnect(self):
        self.reset()
        await self.check_connection()

    async def close_connection(self):
        try:
            if self.verbose:
                print(f'Closing connection with {self.server_address}')
            self.writer.write_eof()
            await self.writer.drain()
            self.writer.close()
            await self.writer.wait_closed()
        except OSError as e:
            print(f'OSError occurred: "{e}"')
        finally:
            self.reset()

    def reset(self):
        self.reader = None
        self.writer = None
        self.encrypted_connection = False
        self.authorized = False
        self.connected = False
        self.server_public_key = None

    async def _send_receive_keys(self):
        if self.server_public_key is None:
            server_key_bytes = await self.send_data(
                self.server_address,
                data=rsa.PublicKey.save_pkcs1(self.cr.public_key),
                data_type='public_key'
            )
            if len(server_key_bytes) < 10:
                raise RuntimeError("Received public key is invalid!")
            try:
                self.server_public_key = rsa.PublicKey.load_pkcs1(server_key_bytes)
                self.encrypted_connection = True
                if self.debug:
                    print('Connection encrypted')
            except ValueError as e:
                if self.verbose:
                    print('Received public key is not valid:', e)
                raise
                # return False
        return True

    async def _authorize(self):
        auth_str_request = await self.send_data(
            self.server_address,
            data=oe_common.get_rnd_string().encode(),
            data_type='auth_req'
        )
        auth_str = rsa.decrypt(auth_str_request, self.cr.private_key)
        if self.debug:
            print(f'Auth str: {auth_str}')
        auth_response = await self.send_data(
            self.server_address,
            data=auth_str,
            data_type='auth_resp'
        )
        if self.debug:
            print(f'Auth response: {auth_response}')
        if auth_response == 'auth successful':
            if self.debug:
                print(f'Auth successful')
            return True
        if self.debug:
            print(f'Auth failed')
        return False

    @staticmethod
    def _pad_ov_header(bs, s):
        if len(s) % bs != 0:
            length = bs - (len(s) % bs)
            s += bytes(b'\x00') * length
            # print(f'len is {length}')
        return s

    @staticmethod
    def _pack_data(d):
        if d:
            # enc = d.encode()
            return b''.join([
                len(d).to_bytes(4, byteorder='big'),
                d
            ])
        else:
            return (0).to_bytes(4, byteorder='big')

    def _get_ov_header(self, data_type, filename=None, key=None, iv=None, signed=None, sign=None, size=None):
        ba = [
            self._pad_ov_header(10, data_type.encode()),
            self._pack_data(filename.encode() if filename else None),
            self._pack_data(key),
            self._pack_data(iv),
            b'y' if signed else b'n',
            # self._pack_data(sign) if signed else b'',
            int(size).to_bytes(14, byteorder='big') if data_type == 'file' else b''
        ]
        return b''.join(ba)

    @staticmethod
    def _validate_input(data_type, filename):
        error = 'Unknown error'
        if data_type == 'file':
            if os.path.isfile(filename):
                return True
            else:
                error = f"File {filename} does not exists!"
        raise RuntimeError(error)

    async def read_with_prefix(self, timeout=5, retries=0):
        prefix_timeout = 30
        if timeout > prefix_timeout:
            prefix_timeout = timeout
        try:
            prefix = (await asyncio.wait_for(self.reader.readline(), timeout=prefix_timeout)).rstrip()
        except asyncio.exceptions.TimeoutError:
            if retries:
                print(f"Timeout error, but {retries} retries left")
                return await self.read_with_prefix(timeout=timeout, retries=retries-1)
            else:
                print(f"Timeout error, no retries left")
                raise
        pk_data = b''
        msg_len = 0
        if prefix != b'':
            msg_len = int(prefix[:-3])
            pk_data = await asyncio.wait_for(self.reader.readexactly(msg_len), timeout=timeout)
        return pk_data, msg_len

    async def write_with_prefix(self, data, prefix=False):
        if prefix:
            prefix_pad = b'pad'
        else:
            prefix_pad = b'\x00' * 3
        self.writer.write(b'%d%b\n%b' % (len(data), prefix_pad, data))
        await self.writer.drain()

    async def check_connection(self):
        if not self.connected:
            await self.connect()
        if await self._send_receive_keys():
            if not self.authorized:
                if await self._authorize():
                    self.authorized = True
                else:
                    raise RuntimeError('Auth failed')

    async def verify_file_sign(self, path):
        await self.check_connection()
        self.writer.write(self._get_ov_header(
            'get_hash',
            filename=path
        ))
        await self.writer.drain()
        file_hash_encoded, length = await self.read_with_prefix()
        file_hash = rsa.decrypt(file_hash_encoded, self.cr.private_key)
        file_sign = rsa.sign(file_hash, self.cr.private_key, 'SHA-1')
        if self.debug:
            print(f'File hash: {file_hash}')
            print(f'File sign: {file_sign}')
        if file_hash == b'file_not_exists':
            return False
        else:
            # local_sign_location = os.path.join(pathlib.Path().absolute(), cfg['signs_dir'], self.cr.get_ip_hash(self.server_address))
            return file_sign

    async def get_file(self, path_from, path_to=None):
        if not path_to:
            path_to = path_from
        await self.check_connection()
        self.aes = ov_aes_cipher.AESCipher(key=oe_common.get_rnd_string(60))
        self.writer.write(self._get_ov_header(
            'get_file',
            filename=path_from,
            key=rsa.encrypt(self.aes.key, self.server_public_key),
            iv=rsa.encrypt(self.aes.iv, self.server_public_key),
            signed=True
        ))
        # print(f'zero: {path_to[0]}')
        if path_to[0] != '/':
            path_to = os.path.join(pathlib.Path().absolute(), path_to)
        oe_common.check_create_dir(path_to)
        await self.writer.drain()
        ov_sign = ovcrypt.OvSign(self.server_public_key)
        dc = oe_common.DinConsole()
        sc = oe_common.SpeedChecker('bits / second', 4096)
        rx_bytes = 0
        with open(path_to, 'wb') as f:
            while True:
                part, length = (await self.read_with_prefix())

                rx_bytes += length
                if self.debug or self.verbose:
                    dc.update('  Received %s / %s, %s%%, speed: %s' % (
                        oe_common.convert_size(rx_bytes),
                        0,
                        '?',
                        sc.get_speed()
                    ))

                if length == 256:
                    if part.rstrip(b'\x00') == b'ovsign':
                        received_sign = await self.reader.read(256)
                        if self.debug or self.verbose:
                            dc.stay()
                        if ov_sign.get_verification_result(received_sign):
                            if self.verbose:
                                print(f'File downloaded to: {path_to}')
                            return True
                        else:
                            if self.verbose:
                                print(f'Error downloading file: {path_to}')
                            return False
                    elif part.rstrip(b'\x00') == b'file_not_exists':
                        if self.verbose or self.debug:
                            dc.stay()
                            print(f'File not exists on server: {path_from}')
                        os.remove(path_to)
                        return False
                dec_part = self.aes.unpad(self.aes.decrypt_part(part))
                ov_sign.update_hash(dec_part)
                f.write(dec_part)

    async def send_file(self, path_from, path_to=None):
        if not path_to:
            path_to = path_from
        await self.check_connection()
        self._validate_input('file', path_from)
        self.aes = ov_aes_cipher.AESCipher(key=oe_common.get_rnd_string(60))
        with open(path_from, 'rb') as f:
            file_size = os.path.getsize(path_from)
            '''if file_size > 1024*1024*500:  # 500 Mb
                signed = False
                sign = None
            else:
                signed = True
                sign = rsa.sign(f.read(), self.cr.private_key, 'SHA-1')
            f.seek(0)'''
            signed = True
            #self.reader, self.writer = await asyncio.open_connection(
                #self.server_address,
                #self.server_port
            #)
            self.writer.write(self._get_ov_header(
                'file',
                filename=path_to,
                key=rsa.encrypt(self.aes.key, self.server_public_key),
                iv=rsa.encrypt(self.aes.iv, self.server_public_key),
                signed=signed,
                # sign=sign,
                size=file_size
            ))
            # chunk_num = 0

            dc = oe_common.DinConsole()
            sc = oe_common.SpeedChecker('bits / second', 4096)
            ov_sign = ovcrypt.OvSign(self.cr.private_key)
            prefix_pad = b'\x00' * 3
            tx_bytes = 0
            file_size_str = oe_common.convert_size(file_size)
            for chunk in iter(lambda: f.read(4096), b''):
                # chunk_num += 1
                ov_sign.update_hash(chunk)
                if f.tell() >= file_size:
                    # print(f'\npadding chunk {chunk_num}')
                    chunk = self.aes.pad(chunk)
                    # prefix_pad = b'pad'
                    prefix_pad = True
                else:
                    # prefix_pad = b'\x00' * len(prefix_pad)
                    prefix_pad = False
                # self.writer.write(b'%d%b\n' % (len(chunk), prefix_pad))
                # self.writer.write(aes.encrypt_part(chunk))
                await self.write_with_prefix(self.aes.encrypt_part(chunk), prefix=prefix_pad)
                # await self.writer.drain()
                '''if chunk_num % 1000 == 0:
                    c_time_new = time.perf_counter()
                    c_diff = c_time_new - c_time
                    c_time = c_time_new
                    network_speed = 4096 * 1000 / c_diff * 8'''
                tx_bytes = tx_bytes + len(chunk)
                if self.debug or self.verbose:
                    dc.update('  Sent %s / %s, %s%%, speed: %s' % (
                        oe_common.convert_size(tx_bytes),
                        file_size_str,
                        round(tx_bytes / file_size * 100),
                        sc.get_speed()
                    ))
            if self.debug or self.verbose:
                dc.stay()
            await self.writer.drain()
            if self.debug:
                print("Data sent")
            if signed:
                sign = ov_sign.get_sign()
                prefix = b'\x00' * 3
                self.writer.write(b'%d%b\n' % (len(sign), prefix))
                sign_message = b'ovsign'
                padded_sign_message = sign_message + b'\x00' * (256 - len(sign_message))
                self.writer.write(padded_sign_message)
                self.writer.write(sign)
                await self.writer.drain()
                if self.debug:
                    print("Sign sent")
            # self.writer.write_eof()

            rcv_data = oe_common.fix_block_encoding_errors(self.aes.decrypt((await self.read_with_prefix())[0]))
            if self.debug or self.verbose:
                print(f'Answer: {rcv_data}')
            # self.writer.close()
            # await self.writer.wait_closed()
            return rcv_data

    def send_message_sync(self, message, timeout=2, retries=0):
        return self.loop.run_until_complete(
            self.send_message(message, timeout, retries)
        )

    async def send_message(self, message, timeout=2, retries=0):
        await self.check_connection()
        try:
            rcv = await self.send_data(self.server_address, data=message.encode(), timeout=timeout, retries=retries)
        except ConnectionResetError:
            if not retries:
                raise
            print(f'Connection error, {retries} left')
            await self.reconnect()
            return await self.send_message(message, timeout=timeout, retries=retries-1)
        if rcv == 'Access denied':
            self.server_public_key = None
            self.authorized = False
            return await self.send_message(message, timeout=timeout, retries=retries)
        elif not rcv:
            if self.verbose or self.debug:
                print(f'Reconnecting to {self.server_address}...')
            # await self.close_connection()
            return await self.send_message(message, timeout=timeout, retries=retries)
        return rcv

    async def send_data(self, address, data=b'', data_type='message', timeout=2, retries=0):
        if not self.connected:
            await self.connect()
        #self.reader, self.writer = await asyncio.open_connection(
            #address, server_port
        #)
        # sa = []
        # self._validate_input(data_type, filename)
        rnd_key = oe_common.get_rnd_string(60)
        self.aes = ov_aes_cipher.AESCipher(rnd_key)
        sign = None
        data_hash = None
        if data_type == 'public_key':
            header = self._get_ov_header(data_type)
        else:
            data_hash = rsa.compute_hash(data, 'SHA-256')
            sign = rsa.sign(data_hash, self.cr.private_key, 'SHA-1')
            data = self.aes.encrypt(data)
            header = self._get_ov_header(
                data_type,
                key=rsa.encrypt(self.aes.key, self.server_public_key),
                iv=rsa.encrypt(self.aes.iv, self.server_public_key),
                signed=True
            )
        self.writer.write(header)
        # print(f'header: {header}')
        prefix_pad = b'\x00' * 3  # data is padded, but now prefix is doesn't matter
        self.writer.write(b'%d%b\n' % (len(data), prefix_pad))
        if self.verbose:
            print(f'sending {oe_common.convert_size(len(data))}')
        self.writer.write(data)
        # await self.writer.drain()
        if sign:
            w = b'%d%b\n' % (len(sign), prefix_pad)
            self.writer.write(w)
            if self.debug:
                print('Sended: %s' % w)
            sign_message = b'ovsign'
            padded_sign_message = sign_message + b'\x00' * (256 - len(sign_message))
            self.writer.write(padded_sign_message)
            self.writer.write(sign)
            if self.debug:
                print('Sended: %s' % padded_sign_message)
                print('Sended sign (%sB): %s' % (len(sign), sign))
                print(f'Hash: {data_hash}')
        # self.writer.write_eof()
        await self.writer.drain()
        # print('Data sent!')
        # print(f'Header: "{header}"')
        if self.debug:
            print(f'Data: "{data}"')
            try:
                print(f'Data aes: "{self.aes.decrypt(data)}"')
            except:
                print('not aes')
        # rcv_data = await self.reader.read(4096)
        rcv_data = (await self.read_with_prefix(timeout=timeout, retries=retries))[0]
        # print(f'Encoded: {rcv_data}, len: {len(base64.b64decode(rcv_data))}')
        if data_type not in ['public_key', 'auth_req'] and self.server_public_key:
            # print(f'Decrypted: {aes.decrypt(rcv_data)}')
            if len(rcv_data) > 0:
                rcv_data = self.aes.decrypt(rcv_data)
                if data_type == 'message' and rcv_data == b'Sign ok':
                    sign_data = rcv_data  # Xz why
                    rcv_data = self.aes.decrypt((await self.read_with_prefix(timeout=timeout, retries=retries))[0])
                elif rcv_data == b'Sign error':
                    rcv_data = json.dumps({'status': False, 'description': 'Sign error'}).encode()
                rcv_data = oe_common.fix_block_encoding_errors(rcv_data)
            else:
                await self.close_connection()
                return False
            # if self.debug or self.verbose:
            #    print(f'Answer: {rcv_data}')
        # self.writer.close()
        # await self.writer.wait_closed()
        return rcv_data

    async def manual_send(self, mode):
        while True:
            try:
                if mode in ['uf']:
                    m = input('Input file name: ')
                    if not os.path.isfile(m):
                        m = os.path.join(pathlib.Path().absolute(), m)
                        if not os.path.isfile(m):
                            print(f'File not exist: {m}')
                            continue
                    to = input('Path on server: ')
                    # return await self.send_file(m)
                    print(await self.send_file(m, to))
                elif mode == 'df':
                    m = input('File path on server: ')
                    to = input('Local path: ')
                    print(await self.get_file(m, to))
                elif mode == 'vfs':
                    m = input('File path on server: ')
                    print(await self.verify_file_sign(m))
                else:
                    m = input('Enter message: ')
                    # return await self.send_message(m)
                    if m == 'c':
                        await self.close_connection()
                    else:
                        print(await self.send_message(m))
            except ConnectionRefusedError as e:
                print(f"Connection refused: {e}")
                # return False
