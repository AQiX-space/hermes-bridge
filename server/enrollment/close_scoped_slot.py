#!/usr/bin/env python3
"""Privilege-separated scoped revocation, invoked only through fixed sudo wrapper.

Never accepts a PID or command from the client; searches exactly one previously
verified SSH listener, anchored to the Hermes service cgroup and UID.
"""
import json
import pwd
import sys
from session_guard import terminate_scoped_session

def main(args):
    if len(args)!=1 or not args[0].isascii() or not args[0].isdecimal():return 64
    port=int(args[0])
    if not 23000<=port<=24999:return 64
    uid=pwd.getpwnam('hermes-bridge').pw_uid
    result=terminate_scoped_session(port,expected_uid=uid)
    print(json.dumps({'safe':result['safe'],'reason':result.get('reason',''), 'port':port}))
    return 0 if result['safe'] else 7
if __name__=='__main__':sys.exit(main(sys.argv[1:]))
