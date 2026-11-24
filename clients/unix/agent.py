"""Hermes signed local command executor for Linux/macOS, current UID only.

Wire-compatible with Windows UserSessionAgent and ops/hermes-user-command.py.
Never listens on a public interface, impersonates another user, or escalates.
"""
import base64
import getpass
import hashlib
import hmac
import json
import os
import pwd
import re
import signal
import socketserver
import subprocess
import threading
import time

MAX_REQUEST = 16000
MAX_SCRIPT = 4096
MAX_OUTPUT = 32768


class _ThreadingLoopback(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True
    request_queue_size = 4


class UserSessionAgent:
    def __init__(self, ticket, on_event=None):
        if not isinstance(ticket, str) or len(ticket) < 40:
            raise ValueError('missing approved broker ticket')
        self._key = hashlib.sha256(('Hermes user-agent HMAC v1\n' + ticket).encode()).digest()
        self._used = {}
        self._last_prune = 0
        self._lock = threading.RLock()
        self._busy = False
        self._closed = False
        self._active = None
        self._events = on_event or (lambda _: None)
        self.user = pwd.getpwuid(os.geteuid()).pw_name
        self._server = _ThreadingLoopback(('127.0.0.1', 0), _Handler)
        self._server.agent = self
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _authorize(self, request):
        if not isinstance(request, dict):
            return False
        script, nonce, mac, ts = (request.get(x) for x in ('script', 'nonce', 'mac', 'ts'))
        if (not isinstance(script, str) or not (1 <= len(script) <= MAX_SCRIPT)
                or not isinstance(nonce, str) or not re.fullmatch('[a-fA-F0-9]{32}', nonce)
                or not isinstance(mac, str) or type(ts) is not int or abs(int(time.time())-ts) > 60):
            return False
        try:
            supplied = base64.b64decode(mac, validate=True)
        except Exception:
            return False
        digest = hmac.new(self._key, f'{ts}\n{nonce}\n{script}'.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(supplied, digest):
            return False
        with self._lock:
            now = int(time.time())
            if now-self._last_prune >= 30:
                self._used = {k: v for k, v in self._used.items() if v >= now-180}
                self._last_prune = now
            if self._closed or len(self._used) >= 10000 or nonce in self._used:
                return False
            self._used[nonce] = now
        return True

    def _execute(self, script):
        with self._lock:
            if self._closed or self._busy:
                return {'ok': False, 'error': 'Agent busy or stopped'}
            self._busy = True
            try:
                # Start while holding the same lock used by close().
                process = subprocess.Popen(['/bin/sh', '-c', script], stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, start_new_session=True)
                self._active = process
            except Exception:
                self._busy = False
                return {'ok': False, 'error': 'Unable to start command'}
        self._events('Authorized command started as '+self.user)
        try:
            out, err = bytearray(), bytearray()
            def drain(pipe, sink):
                try:
                    while True:
                        chunk = pipe.read(4096)
                        if not chunk:
                            break
                        if len(sink) < MAX_OUTPUT:
                            sink.extend(chunk[:MAX_OUTPUT-len(sink)])
                except OSError:
                    pass
            output_reader = threading.Thread(target=drain, args=(process.stdout, out), daemon=True)
            error_reader = threading.Thread(target=drain, args=(process.stderr, err), daemon=True)
            output_reader.start()
            error_reader.start()
            timed_out = False
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
            output_reader.join(timeout=3)
            error_reader.join(timeout=3)
            if timed_out:
                return {'ok': False, 'user': self.user, 'exit_code': -1,
                        'error': 'Command timeout (30 seconds)'}
            if self._closed:
                return {'ok': False, 'user': self.user, 'exit_code': -1, 'error': 'Agent stopped'}
            result = {'ok': process.returncode == 0, 'user': self.user,
                      'exit_code': process.returncode,
                      'stdout': out.decode('utf-8', 'replace'),
                      'stderr': err.decode('utf-8', 'replace')}
            self._events('Command completed with exit '+str(process.returncode))
            return result
        finally:
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except OSError:
                    pass
            with self._lock:
                if self._active is process:
                    self._active = None
                self._busy = False

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._active and self._active.poll() is None:
                try:
                    os.killpg(self._active.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self._key = b'\0' * len(self._key)
            self._used.clear()
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=3)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        line = self.rfile.readline(MAX_REQUEST + 1)
        if not line.endswith(b'\n') or len(line) > MAX_REQUEST:
            return self._reply({'ok': False, 'error': 'Invalid or oversized request'})
        try:
            request = json.loads(line.decode('utf-8'))
        except (UnicodeError, ValueError):
            return self._reply({'ok': False, 'error': 'Malformed request'})
        agent = self.server.agent
        if not agent._authorize(request):
            return self._reply({'ok': False, 'error': 'Unauthorized'})
        self.request.settimeout(38)
        return self._reply(agent._execute(request['script']))

    def _reply(self, result):
        try:
            self.wfile.write(json.dumps(result, ensure_ascii=False).encode('utf-8')+b'\n')
            self.wfile.flush()
        except (OSError, ValueError):
            pass
