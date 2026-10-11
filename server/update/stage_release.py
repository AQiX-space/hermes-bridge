#!/usr/bin/env python3
"""Stage a private GitHub beta for AQiX HTTPS mirror, no production writes."""
import argparse
import base64
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tempfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

REPO = 'AQiX-space/hermes-bridge'
URL_ROOT = 'https://sub.aqix.ru:3443/downloads/hermes-bridge'
SIGNER = '/etc/aqix-hermes-bridge-update/signing-key.pem'
PUBKEY = '/etc/aqix-hermes-bridge-update/signing-key.pub.pem'

def run(*args, **kw):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw).stdout

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--tag', required=True)
    p.add_argument('--sha256', required=True, help='Independently verified asset hash')
    p.add_argument('--output', type=pathlib.Path, required=True, help='New, empty staging directory')
    args=p.parse_args()
    match=re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)-beta\.(\d+)', args.tag)
    if not match or int(match[4]) < 1: p.error('beta release tag required')
    if not re.fullmatch('[a-f0-9]{64}',args.sha256):p.error('invalid expected SHA-256')
    if args.output.exists():p.error('refusing to overwrite staging output')
    metadata=json.loads(run('gh','api',f'repos/{REPO}/releases/tags/{args.tag}'))
    if metadata['draft'] or not metadata['prerelease']:p.error('release must be published beta')
    assets=[a for a in metadata['assets'] if a['name']=='HermesBridge.exe']
    if len(assets)!=1:p.error('expected exactly one EXE asset')
    with tempfile.TemporaryDirectory(prefix='hermes-bridge-stage-') as td:
        tmp=pathlib.Path(td)
        run('gh','release','download',args.tag,'-R',REPO,'-p','HermesBridge.exe','-D',str(tmp))
        binary=tmp/'HermesBridge.exe'
        if binary.stat().st_size < 2048 or binary.stat().st_size > 100*1024*1024 or binary.read_bytes()[:2]!=b'MZ':p.error('invalid Windows EXE')
        digest=hashlib.sha256(binary.read_bytes()).hexdigest()
        if digest!=args.sha256:p.error('hash mismatch; do not publish')
        numeric='.'.join([*match.groups()[:3],str(int(match[4])-1)])
        url=f'{URL_ROOT}/releases/{args.tag[1:]}/HermesBridge.exe'
        canonical=f'{numeric}\n{url}\n{digest}'.encode('utf-8')
        signature=run('ssh','-o','BatchMode=yes','de2','sudo','-n','openssl','dgst','-sha256','-sign',SIGNER,input=canonical)
        pub=serialization.load_pem_public_key(run('ssh','-o','BatchMode=yes','de2','sudo','-n','cat',PUBKEY))
        pub.verify(signature,canonical,padding.PKCS1v15(),hashes.SHA256())
        manifest=dict(version=numeric,url=url,sha256=digest,signature=base64.b64encode(signature).decode())
        args.output.mkdir(parents=True)
        target=args.output/'releases'/args.tag[1:]
        target.mkdir(parents=True)
        shutil.copy2(binary,target/'HermesBridge.exe')
        (args.output/'beta.json').write_text(json.dumps(manifest,separators=(',',':'))+'\n')
        (args.output/'EVIDENCE.txt').write_text(f'{args.tag}\n{digest}\n{assets[0]["size"]} bytes\nSOURCE: {REPO}\nNOT DEPLOYED\n')
        print(f'PASS staged signed manifest and binary to {args.output}; numeric version={numeric}')
        print('WARNING: staging is not deployment; manual sign-off, mirror backup, validation and rollback required')
if __name__=='__main__':main()
