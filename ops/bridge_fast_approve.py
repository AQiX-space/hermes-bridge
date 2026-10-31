#!/usr/bin/env python3
"""One-shot DE2 enrollment approval; never claims SSH authentication success."""
import argparse
import json
import re
import subprocess
import time

DB = '/var/lib/hermes-enrollment/requests.sqlite3'
APP = '/opt/hermes-enrollment/service.py'
BASE = ['sudo', '-n', 'python3', APP, '--db', DB]

def run(args, timeout=5):
    return subprocess.check_output(args, text=True, timeout=timeout).strip()

def normalize(code):
    code = code.replace('-', '').strip()
    if not re.fullmatch(r'[A-Za-z0-9]{4}', code):
        raise ValueError('expected four alphanumeric characters, optional display hyphen')
    return code

def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('code')
    a = cli.parse_args()
    t = time.monotonic()
    code = normalize(a.code)
    p = json.loads(run(BASE+['preflight', '--code', code]))
    if p.get('status') != 'ready' or p.get('blockers'):
        print(json.dumps({'stage':'preflight','outcome':p},ensure_ascii=False)); return 2
    records = json.loads(run(BASE+['pending']))
    matching = [r for r in records if r.get('code','').casefold()==code.casefold()]
    if len(matching)!=1:
        print(json.dumps({'stage':'pending','match_count':len(matching)})); return 3
    row = matching[0]
    scan = run(['ssh-keyscan','-p','22471','-t','ed25519','127.0.0.1'])
    keys = [line.split(' ',1)[1] for line in scan.splitlines() if line and not line.startswith('#')]
    if len(keys)!=1: raise RuntimeError('ambiguous gate SSH host key')
    cmd = BASE+['approve','--ticket',row['ticket'],'--code',row['code'],'--host','de2.nod.aqixnet.com','--hostkey',keys[0],'--slot','auto']
    preview = json.loads(run(cmd))
    if not preview.get('dry_run'): raise RuntimeError('dry-run verification failed')
    result = json.loads(run(cmd+['--apply']))
    print(json.dumps({'stage':'approved','device':row.get('device'),'code':row['code'],'slot':result['config']['slot'],'approval_seconds':round(time.monotonic()-t,3),'ssh_authentication':'not_tested'},ensure_ascii=False))
    return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except (subprocess.SubprocessError,ValueError,RuntimeError,KeyError) as exc:
        print(json.dumps({'stage':'error','reason':str(exc)},ensure_ascii=False)); raise SystemExit(1)
