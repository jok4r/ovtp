import signal
import datetime
import asyncio
import os
from ovtp.client import OvtpClient


def signal_handler(sig, frame):
    print("Pressed Ctrl+C, exiting...")
    os.kill(os.getpid(), signal.SIGTERM)


def run_client():
    print("Running script on %s" % datetime.datetime.now())
    signal.signal(signal.SIGINT, signal_handler)
    print('Press Ctrl+C for exit')
    server_ip = input('Server ip: ')
    oec = OvtpClient(server_ip, verbose=False, debug=False)
    input_text = 'Select mode (m - message, df - download file, uf - upload file, vfs - verify file sign)'
    main_mode = input(input_text + ' or d, v, dv - debug, verbose: ')
    if main_mode in ['d', 'v', 'dv']:
        if main_mode in ['d', 'dv']:
            oec.debug = True
        if main_mode in ['v', 'dv']:
            oec.verbose = True
        main_mode = input(f'{input_text}: ')
        if main_mode not in ['m', 'df', 'uf', 'vfs']:
            raise ValueError(f"Incorrect mode: {main_mode}")
    asyncio.run(oec.manual_send(main_mode))
