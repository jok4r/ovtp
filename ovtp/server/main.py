import datetime
import signal
import asyncio
import sys
from ovtp.server import OvtpServer
from ovtp.server.add_auth_keys import add_auth_keys


def signal_handler(sig, frame):
    print("Pressed Ctrl+C, exiting...")
    exit(0)


def callback(status, response):
    print(f'status: {status}, response: {response}')
    return 'OK', 'GOOD'


def run_server():
    print("Running script %s" % datetime.datetime.now())
    signal.signal(signal.SIGINT, signal_handler)
    print('Press Ctrl+C for exit')
    ovtp_server = OvtpServer(callback, verbose=False, debug=False)
    if len(sys.argv) > 2:
        if sys.argv[2] == '--daemon':
            print('Running in daemon mode')
        elif sys.argv[2] == '--add-keys':
            print('Adding new auth keys...')
            add_auth_keys()
            sys.exit(0)
    else:
        print('Running in normal mode. To run in daemon mode, run with --daemon')
        main_mode = input('Select mode d, v, dv - debug, verbose: ')
        if main_mode in ['d', 'v', 'dv']:
            if main_mode in ['d', 'dv']:
                ovtp_server.debug = True
            if main_mode in ['v', 'dv']:
                ovtp_server.verbose = True
    asyncio.run(ovtp_server.run_server())
