from overengine_client import OverEngineClient
import signal
import datetime
import asyncio
import os


def signal_handler(sig, frame):
    print("Pressed Ctrl+C, exiting...")
    # global script_run
    # script_run = False
    os.kill(os.getpid(), signal.SIGTERM)


print("Running script on %s" % datetime.datetime.now())
signal.signal(signal.SIGINT, signal_handler)
print('Press Ctrl+C for exit')
oec = OverEngineClient(verbose=False, debug=False)
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
