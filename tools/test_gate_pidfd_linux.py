"""Linux-only real pidfd smoke test in an isolated child process, NEVER sshd."""
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
from test_gate_session_guard import setup, PORT
from gate_session_guard import terminate_scoped_session

if not sys.platform.startswith('linux') or not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
    raise SystemExit('Linux with pidfd support required')
with tempfile.TemporaryDirectory() as d:
    proc=pathlib.Path(d)
    child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
    try:
        target=setup(proc,pid=str(child.pid))
        result=terminate_scoped_session(PORT,proc,main_pid=child.pid+1000,expected_uid=1507)
        assert result['safe'],result
        child.wait(timeout=5)
        assert child.returncode==-signal.SIGTERM,child.returncode
    finally:
        if child.poll() is None:
            child.terminate();child.wait(timeout=5)
print('PASS real Linux pidfd SIGTERM targeted only the verified test child')
