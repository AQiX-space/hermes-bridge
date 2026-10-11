#!/usr/bin/env python3
"""Offline operator-assisted enrollment. Doesn't modify production SSH or users."""
import argparse
import base64
import ipaddress
import json
import re
from pathlib import Path

PUBLIC = re.compile(r'^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?:\s+.*)?$')
HOST = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.-]{0,251}[a-zA-Z0-9]$')

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--device',required=True)
    p.add_argument('--host',required=True)
    p.add_argument('--port',type=int,required=True)
    p.add_argument('--slot',type=int,required=True)
    p.add_argument('--public-key-file',type=Path,required=True)
    p.add_argument('--gateway-host-key-file',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    args=p.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_-]{2,64}',args.device): p.error('invalid device identifier')
    if not HOST.fullmatch(args.host): p.error('invalid DNS name')
    if not 1<=args.port<=65535 or not 1024<=args.slot<=65535: p.error('invalid port')
    if args.port==args.slot: p.error('ports must differ')
    key=args.public_key_file.read_text().strip()
    hostkey=args.gateway_host_key_file.read_text().strip()
    if not PUBLIC.fullmatch(key) or not PUBLIC.fullmatch(hostkey):p.error('only ed25519 keys supported')
    for v in (key,hostkey):
        try:
            if len(base64.b64decode(v.split()[1],validate=True))!=51: p.error('unexpected ED25519 key blob size')
        except ValueError: p.error('invalid base64')
    args.output_dir.mkdir(parents=True,exist_ok=True)
    file=args.output_dir/(args.device+'.bridge')
    if file.exists(): p.error('refusing overwrite of registration')
    file.write_text(f'host={args.host}\nport={args.port}\nslot={args.slot}\nhostkey={" ".join(hostkey.split()[:2])}\n')
    print('Client bundle:',file)
    print('Server authorized_keys line (review and install only after operator approval):')
    print(f'restrict,port-forwarding,permitlisten="127.0.0.1:{args.slot}" {key}')
    print('ATTENTION: server sshd PermitListen must allow the allocated port; no server configuration modified.')
if __name__=='__main__': main()
