import os
from ovtp.server import get_short_rsa_key, cfg
from pathlib import Path


def add_auth_keys():
    auth_keys_path = os.path.join(cfg['auth_keys_dir'], 'authorized_keys')
    if not os.path.isfile(auth_keys_path):
        Path(auth_keys_path).touch()
    if len(ls_dir := os.listdir(cfg['auth_keys_dir'])) > 1:
        with open(auth_keys_path, 'rb+') as f:
            keys = f.read().splitlines()
            for new_key_file in ls_dir:
                if new_key_file != 'authorized_keys':
                    with open(os.path.join(cfg['auth_keys_dir'], new_key_file), 'rb') as f2:
                        new_key = get_short_rsa_key(f2.read().replace(b'\n', b''))
                        key_name = f'{new_key_file} {new_key[:10].decode()}...{new_key[-10:].decode()}'
                        if new_key in keys:
                            print(f"Key {key_name} already added")
                        else:
                            print(f"Added key: {key_name}")
                            f.write(new_key + b'\n')
    else:
        print(f"Keys not found in directory: {cfg['auth_keys_dir']}")
