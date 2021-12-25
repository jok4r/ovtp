import datetime
import signal
import asyncio
import sys
from overengine_server import OverEngineServer


def signal_handler(sig, frame):
    print("Pressed Ctrl+C, exiting...")
    exit(0)


print("Running script %s" % datetime.datetime.now())
signal.signal(signal.SIGINT, signal_handler)
print('Press Ctrl+C for exit')
over_engine_server = OverEngineServer(verbose=False, debug=False)
if len(sys.argv) > 1 and sys.argv[1] == '--daemon':
    print('Running in daemon mode')
else:
    print('Running in normal mode. To run in daemon mode, run with --daemon')
    main_mode = input('Select mode d, v, dv - debug, verbose: ')
    if main_mode in ['d', 'v', 'dv']:
        if main_mode in ['d', 'dv']:
            over_engine_server.debug = True
        if main_mode in ['v', 'dv']:
            over_engine_server.verbose = True
asyncio.run(over_engine_server.run_server())
