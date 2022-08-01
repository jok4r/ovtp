import ovcfg
import os


config_dirs = [
    [['/', 'var', 'lib'], []],
    [[os.path.expanduser("~"), '.local'], ['share']]
]


for config_dir in config_dirs:
    if os.access(os.path.join(*config_dir[0]), os.W_OK):
        config_path = os.path.join(*config_dir[0], *config_dir[1], 'ovtp')
        break
else:
    raise RuntimeError("Can't create ovcrypt config directory")


sc = {
    'server_ip': '0.0.0.0',
    'server_port': 888,
    'auth_keys_dir': os.path.join(config_path, 'auth_keys'),
}
cfg = ovcfg.Config(std_config=sc, file='server.json', cfg_dir_name='ovtp').import_config()
