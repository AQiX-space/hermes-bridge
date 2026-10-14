import base64, json, pathlib, tempfile, threading, urllib.request
from http.server import ThreadingHTTPServer
from service import Enrollment,handler
key='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes(range(32))).decode()
with tempfile.TemporaryDirectory() as tmp:
 db=Enrollment(pathlib.Path(tmp)/'state.sqlite')
 web=ThreadingHTTPServer(('127.0.0.1',0),handler(db))
 thread=threading.Thread(target=web.serve_forever,daemon=True);thread.start()
 try:
  api=f'http://127.0.0.1:{web.server_port}/v1/enroll'
  request=urllib.request.Request(api,json.dumps({'device':'TestPC','public_key':key}).encode(),headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(request,timeout=3) as r:
   assert r.status==202;ticket=json.load(r)['ticket']
  with urllib.request.urlopen(api+'/'+ticket,timeout=3) as r: assert json.load(r)=={'status':'pending'}
  auth=pathlib.Path(tmp)/'authorized_keys';auth.write_text('existing-safe-ssh-key\n')
  db.approve(ticket,23011,'router-mgmt.aqixnet.com',key,apply=True,keys_file=auth)
  with urllib.request.urlopen(api+'/'+ticket,timeout=3) as r:
   response=json.load(r);assert response['status']=='approved'
   assert response['config']['slot']==23011
   assert response['config']['hostkey']==key
  for _ in range(2):
   with urllib.request.urlopen(request,timeout=3) as r:assert r.status==202
  try:
   urllib.request.urlopen(request,timeout=3)
   raise AssertionError('unbounded registration accepted')
  except urllib.error.HTTPError as e:assert e.code==429
  print('PASS HTTP enrollment request, pending poll, approved config, per-device rate limit')
 finally:web.shutdown();web.server_close();thread.join(timeout=3)
