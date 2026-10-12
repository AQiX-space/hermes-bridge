#!/usr/bin/env python3
"""Atomic publication of a signed Hermes Connector update staging tree.
Requires explicit production-change approval. Default is READ-ONLY validation.
"""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tempfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE = pathlib.Path('/srv/aqix-downloads/hermes-bridge')
KEY = pathlib.Path('/etc/aqix-hermes-bridge-update/signing-key.pub.pem')

def verify(stage, pubkey):
    m = json.loads((stage/'beta.json').read_text())
    if set(m) != {'version','url','sha256','signature'}: raise ValueError('unexpected manifest keys')
    from urllib.parse import urlparse
    u=urlparse(m['url'])
    if (u.scheme,u.hostname,u.port)!=("https","sub.aqix.ru",3443):raise ValueError('wrong URL origin')
    if not u.path.startswith('/downloads/hermes-bridge/releases/') or not u.path.endswith('/HermesBridge.exe'):raise ValueError('wrong URL path')
    relative=u.path[len('/downloads/hermes-bridge/'):]
    binary=stage/relative
    if not binary.is_file() or binary.read_bytes()[:2]!=b'MZ':raise ValueError('invalid/missing EXE')
    digest=hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest!=m['sha256']:raise ValueError('binary digest mismatch')
    import base64
    data=f'{m["version"]}\n{m["url"]}\n{m["sha256"]}'.encode()
    key=serialization.load_pem_public_key(pubkey.read_bytes())
    key.verify(base64.b64decode(m['signature'],validate=True),data,padding.PKCS1v15(),hashes.SHA256())
    return m,relative

def main():
    p=argparse.ArgumentParser();p.add_argument('--staging',type=pathlib.Path,required=True);p.add_argument('--public-key',type=pathlib.Path,default=KEY);p.add_argument('--apply',action='store_true',help='production WRITE: require explicit owner approval first');a=p.parse_args()
    m,rel=verify(a.staging,a.public_key)
    print('PASS signed bundle:',m['version'],rel,m['sha256'])
    if not a.apply:
        print('DRY RUN ONLY: nothing published; use --apply only after specific production approval')
        return
    if os.geteuid()!=0: p.error('root required to publish')
    BASE.mkdir(mode=0o755,parents=True,exist_ok=True)
    dest=BASE/rel
    if dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest()!=m['sha256']:
        raise ValueError('refusing overwrite of existing release binary')
    dest.parent.mkdir(parents=True,exist_ok=True)
    tmp=dest.with_suffix('.incoming')
    shutil.copy2(a.staging/rel,tmp)
    os.chmod(tmp,0o644)
    os.replace(tmp,dest)
    manifest=BASE/'beta.json'
    backup=None
    if manifest.exists():
        import datetime
        backup=BASE/('beta.json.backup-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
        shutil.copy2(manifest,backup)
    incoming=BASE/'beta.json.incoming'
    shutil.copy2(a.staging/'beta.json',incoming)
    os.chmod(incoming,0o644)
    os.replace(incoming,manifest)
    print('PUBLISHED',manifest,'backup',backup)

if __name__=='__main__':main()
