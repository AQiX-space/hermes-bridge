"""Linux-only live TCP tests; proves unrelated process is not terminated."""
import os
import pathlib
import socket
import sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'server'/'enrollment'))
from service import close_reverse_session

assert sys.platform.startswith('linux')
listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
try:
    port=None
    for attempt in range(24999,24800,-1):
        try:
            listener.bind(('127.0.0.1',attempt))
            listener.listen(1)
            port=attempt
            break
        except OSError:continue
    assert port is not None,'test reverse-port range unavailable'
    try:
        close_reverse_session(port)
    except RuntimeError as error:
        assert 'cannot safely close' in str(error),str(error)
    else:
        raise AssertionError('an unrelated TCP listener was treated as revoked')
    assert close_reverse_session(port-1),'unused port should be safely closed'
    listener.settimeout(.2)
    probe=socket.socket()
    try:
        probe.settimeout(1)
        probe.connect(('127.0.0.1',port))
    finally:probe.close()
finally:listener.close()
print('PASS live untrusted TCP listener is not terminated by MOS session closer')
