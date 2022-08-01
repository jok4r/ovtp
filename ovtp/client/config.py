import ovcfg


sc = {
    'default_server_port': 888,
    'local_ip': '0.0.0.0'
}
cfg = ovcfg.Config(std_config=sc, file='client.json', cfg_dir_name='ovtp').import_config()
