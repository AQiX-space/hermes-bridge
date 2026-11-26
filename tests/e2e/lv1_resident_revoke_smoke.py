#!/usr/bin/env python3
import base64, json, os, shlex, shutil, subprocess, tempfile, time, threading, urllib.request, urllib.error, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
if '--confirm-live-lv1' not in sys.argv:
 print('Refusing to modify a real broker without --confirm-live-lv1',file=sys.stderr)
 sys.exit(64)

ROOT='https://gr2.touch01.top:18512'; GATE='gr2.touch01.top'; DB='/var/lib/hermes-enrollment/requests.sqlite3'
def remote(script):
 return subprocess.run(['ssh','-o','BatchMode=yes','lv1',script],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12,check=True).stdout
class Proof(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200); self.end_headers();self.wfile.write(b'HERMES_TUNNEL_PROOF_20261118')
 def log_message(self,*a):pass
server=ThreadingHTTPServer(('127.0.0.1',0),Proof);threading.Thread(target=server.serve_forever,daemon=True).start()
with tempfile.TemporaryDirectory(prefix='hermes-lv1-smoke-') as temp:
 path=Path(temp); key=path/'testkey'; ticket=None; tunnel=None
 try:
  subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
  official=remote('sudo -n cat /etc/ssh/hermes-bridge-host_ed25519_key.pub').strip().split()
  scanned=subprocess.check_output(['ssh-keyscan','-T','5','-p','22471',GATE],stderr=subprocess.DEVNULL,text=True).strip().splitlines()
  valid=[l for l in scanned if len(l.split())>=3 and l.split()[1:3]==official[:2]]
  if not valid:raise RuntimeError('SSH GATE HOST KEY MISMATCH')
  known=path/'known_hosts';known.write_text(valid[0]+'\n')
  data=json.dumps({'device':'LV1-SMOKE-'+os.urandom(3).hex(),'public_key':key.with_suffix('.pub').read_text().strip(),'requested_mode':'resident','requested_lease_seconds':0}).encode()
  payload=base64.b64encode(data).decode()
  obj=json.loads(remote('printf %s '+shlex.quote(payload)+' | base64 -d | curl -fsS --max-time 5 -H '+shlex.quote('Content-Type: application/json')+' --data-binary @- http://127.0.0.1:18511/v1/enroll'))
  ticket=obj['ticket'];code=obj['code']
  print('ENROLL: LOCAL BROKER 202, CODE PRESENT')
  cli=f'sudo -n -u hermes-bridge python3 /opt/hermes-enrollment/service.py --db {DB} approve --ticket {shlex.quote(ticket)} --code {shlex.quote(code)} --host {GATE} --hostkey {shlex.quote(" ".join(official[:2]))} --slot auto --ttl-seconds 0 --apply'
  approval=json.loads(remote(cli)); slot=int(approval['config']['slot']); print('APPROVED SLOT:',slot)
  with urllib.request.urlopen(ROOT+'/v1/enroll/'+ticket,timeout=10) as response: poll=json.load(response)
  assert poll['status']=='approved' and poll['config']['slot']==slot
  assert poll.get('status')=='approved'
  print('RESIDENT APPROVAL: PENDING->APPROVED (explicit ttl=0)')
  tunnel=subprocess.Popen(['ssh','-N','-T','-p','22471','-i',str(key),'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','ExitOnForwardFailure=yes','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={known}','-R',f'127.0.0.1:{slot}:127.0.0.1:{server.server_port}','hermes-bridge@'+GATE],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  passed=False
  for i in range(25):
   if tunnel.poll() is not None:break
   try:
    payload=remote(f'curl -fsS --max-time 2 http://127.0.0.1:{slot}/')
    if payload=='HERMES_TUNNEL_PROOF_20261118':passed=True;break
   except subprocess.CalledProcessError:time.sleep(.35)
  if not passed:
   detail=(tunnel.stderr.read().decode(errors='replace') if tunnel.poll() is not None else 'no remote forward reached')
   raise RuntimeError('SSH FORWARD FAILED: '+detail[:300])
  print('REVERSE SSH -> PANEL HTTP: PASS')
  print('RESIDENT TEST: live reverse SSH listener active, revoking it while connected')
  revoke=urllib.request.Request(ROOT+'/v1/enroll/revoke',data=json.dumps({'ticket':ticket}).encode(),headers={'Content-Type':'application/json'})
  try:
   with urllib.request.urlopen(revoke,timeout=12) as response:result=json.load(response);print('LIVE REVOKE:',response.status,result.get('status'))
  except urllib.error.HTTPError as ex:
   print('LIVE REVOKE BLOCKED:',ex.code,ex.read(300).decode());raise
  for _ in range(12):
   if tunnel.poll() is not None:break
   time.sleep(.3)
  if tunnel.poll() is None:raise RuntimeError('REVOKED but SSH session still exists')
  if remote(f'ss -lnt | grep -F ":{slot} " || true').strip():raise RuntimeError('REVOKED but remote listener remains')
  print('LIVE SCOPED REVOKE CLOSED SESSION AND LISTENER: PASS');ticket=None
 finally:
  if tunnel is not None and tunnel.poll() is None:
   tunnel.terminate();time.sleep(.4)
   if tunnel.poll() is None:tunnel.kill()
  if ticket:
   req=urllib.request.Request(ROOT+'/v1/enroll/revoke',data=json.dumps({'ticket':ticket}).encode(),headers={'Content-Type':'application/json'})
   try:urllib.request.urlopen(req,timeout=8).close();print('CLEANUP REVOKE: OK')
   except Exception as e:print('CLEANUP REVOKE FAILED:',type(e).__name__)
  server.shutdown();server.server_close()
