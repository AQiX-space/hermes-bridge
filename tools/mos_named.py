#!/usr/bin/env python3
"""Operator-side name resolver. Does not authorize or approve a session."""
import argparse
import json
import pathlib
import re
import shlex
import subprocess
import sys

ALIAS=re.compile(r'^[A-Za-z][A-Za-z0-9_-]{1,47}$')

def resolve(alias,gateway,service='/opt/hermes-enrollment/service.py',database='/var/lib/hermes-enrollment/requests.sqlite3',run=subprocess.run):
    if not ALIAS.fullmatch(alias):raise ValueError('invalid registered name')
    if not re.fullmatch(r'[A-Za-z0-9.-]{3,253}',gateway):raise ValueError('invalid trusted gateway')
    if not service.startswith('/opt/hermes-enrollment/') or not database.startswith('/var/lib/hermes-enrollment/'):
        raise ValueError('untrusted service or database path')
    command='sudo -n python3 '+shlex.quote(service)+' --db '+shlex.quote(database)+' resolve-device --alias '+shlex.quote(alias)
    result=run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8',gateway,command],
               stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=14)
    if result.returncode:raise RuntimeError('Gate cannot resolve the trusted device name')
    data=json.loads(result.stdout.decode('utf-8'))
    if data.get('alias','').lower()!=alias.lower() or data.get('platform') not in ('windows','openwrt'):
        raise RuntimeError('inconsistent Gate response')
    if data.get('status') not in ('approved','pending','revoking','offline'):
        raise RuntimeError('unknown Gate state')
    slot=data.get('slot')
    if data['status']=='approved':
        if type(slot)!=int or not 23000<=slot<=24999:raise RuntimeError('invalid reverse listener')
        # A database grant is not proof the SSH tunnel is established. Probe the actual listener.
        probe='python3 -c '+shlex.quote('import socket,sys; s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),3); s.settimeout(3); b=s.recv(64); s.close(); sys.exit(0 if b.startswith(b"SSH-") else 1)')+' '+str(slot)
        response=run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8',gateway,probe],
                     stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=14)
        data['tunnel_verified']=response.returncode==0
        data['status']='connected' if data['tunnel_verified'] else 'approved_not_connected'
    else:data['tunnel_verified']=False
    return data

def main():
    parser=argparse.ArgumentParser(description='Find a registered mobile MOS device by name via its verified gateway')
    parser.add_argument('--alias',required=True)
    parser.add_argument('--gateway',required=True)
    args=parser.parse_args()
    try:print(json.dumps(resolve(args.alias,args.gateway),ensure_ascii=False,sort_keys=True))
    except (ValueError,RuntimeError,TimeoutError,subprocess.TimeoutExpired,OSError,json.JSONDecodeError) as ex:
        print(str(ex),file=sys.stderr);return 1
    return 0
if __name__=='__main__':sys.exit(main())
