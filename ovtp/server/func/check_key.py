import os
import rsa
from ovtp.server import cfg, short_key_to_full, get_short_rsa_key, SavedKey


def check_key(self, key: SavedKey, address):
    if address[0] in self.server.temp_keys and self.server.temp_keys[address[0]].key == key.key:
        # Temp keys do not need to be checked
        if self.server.verbose:
            print("Temp key not need to be in master keys")
        return True, True
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
    if key.key not in saved_master_keys:
        master_keys = self.cr.get_master_keys()
        for m_key in master_keys:
            if m_key not in saved_master_keys:
                saved_master_keys.append(m_key)
        with open(auth_keys_path, 'wb') as f:
            f.write(b'\n'.join([get_short_rsa_key(rsa.PublicKey.save_pkcs1(k).replace(b'\n', b'')) for k in
                                saved_master_keys]))
    if key.key in saved_master_keys:
        if self.server.debug:
            print(f'Key found in master keys: {key.key}')
        return True, True
    if self.server.verbose:
        print('Key not found in master keys')
    return False, 'no_key'
