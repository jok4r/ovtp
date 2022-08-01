import sys
from ovtp.client import run_client
from ovtp.server import run_server


if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help']:
    print("Usage: python3 -m ovtp [client | server]")
    sys.exit(0)

if sys.argv[1] == 'client':
    run_client()
elif sys.argv[1] == 'server':
    run_server()
else:
    print("Unknown mode")
    sys.exit(1)
