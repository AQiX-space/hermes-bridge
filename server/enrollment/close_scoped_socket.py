#!/usr/bin/env python3
"""Root, socket-activated scoped SSH revocation, no generic root command API.

systemd Accept=yes gives a single connected AF_UNIX socket as stdin (fd 0).
SO_PEERCRED and cgroup restrict callers to the Hermes broker service. A
validated port 23000..24999 is the only accepted request. Runtime does not
allow arbitrary PIDs, commands, filesystem paths or shell syntax.
"""
import json
import os
import pwd
import socket
import struct
import sys


def validate_peer(uid, pid, broker_uid, cgroup_reader):
    if uid != broker_uid or pid < 2:
        return False
    try:
        return 'hermes-enrollment.service' in cgroup_reader(pid)
    except (OSError, ValueError):
        return False


def parse_request(data):
    if not isinstance(data, bytes) or not 2 <= len(data) <= 6 or not data.endswith(b'\n'):
        raise ValueError('invalid frame length')
    raw = data[:-1]
    if not raw.isascii() or not raw.isdigit() or len(raw) > 5:
        raise ValueError('invalid port representation')
    port = int(raw)
    if not 23000 <= port <= 24999:
        raise ValueError('out-of-range reverse port')
    return port


def execute(data, uid, pid, broker_uid, cgroup_reader, terminator):
    if not validate_peer(uid, pid, broker_uid, cgroup_reader):
        return {'safe': False, 'reason': 'untrusted_broker_peer'}
    try:
        port = parse_request(data)
    except ValueError:
        return {'safe': False, 'reason': 'invalid_port'}
    result = terminator(port, expected_uid=broker_uid)
    return {'safe': bool(result.get('safe')), 'reason': result.get('reason','')}


def main():
    if os.geteuid() != 0:
        raise SystemExit('revocation socket service requires root')
    # -I deliberately omits sys.path from the current directory. This source
    # directory is checked root:root 0755 on LV1, not writable by broker.
    sys.path.insert(0, '/opt/hermes-enrollment')
    from session_guard import terminate_scoped_session

    def peer_cgroup(pid):
        return open('/proc/%d/cgroup' % pid, encoding='utf-8').read()

    conn = socket.socket(fileno=0)
    conn.settimeout(4)
    try:
        if conn.family != socket.AF_UNIX:
            return 7
        rawcred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        pid, uid, _gid = struct.unpack('3i', rawcred)
        payload = conn.recv(8)
        broker_uid = pwd.getpwnam('hermes-bridge').pw_uid
        try:
            result = execute(payload, uid, pid, broker_uid, peer_cgroup, terminate_scoped_session)
        except (OSError, RuntimeError, ValueError, PermissionError):
            result = {'safe': False, 'reason': 'cannot_verify_scoped_session'}
        body = json.dumps(result, separators=(',', ':')).encode('ascii')+b'\n'
        conn.sendall(body)
        return 0 if result['safe'] else 7
    finally:
        conn.close()


if __name__ == '__main__':
    sys.exit(main())
