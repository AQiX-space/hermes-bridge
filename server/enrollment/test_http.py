import base64, json, pathlib, tempfile, threading, urllib.request
from http.server import ThreadingHTTPServer
from service import Enrollment,handler
key='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes(range(32))).decode()
with tempfile.TemporaryDirectory() as tmp:
 db=Enrollment(pathlib.Path(tmp)/'state.sqlite')
 auth=pathlib.Path(tmp)/'authorized_keys';auth.write_text('existing-safe-ssh-key\n')
 web=ThreadingHTTPServer(('127.0.0.1',0),handler(db,auth))
 thread=threading.Thread(target=web.serve_forever,daemon=True);thread.start()
 try:
  api=f'http://127.0.0.1:{web.server_port}/v1/enroll'
  request=urllib.request.Request(api,json.dumps({'device':'TestPC','public_key':key}).encode(),headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(request,timeout=3) as r:
   assert r.status==202;first=json.load(r);ticket=first['ticket'];assert len(first['code'])==4
  with urllib.request.urlopen(api+'/'+ticket,timeout=3) as r: assert json.load(r)=={'status':'pending'}
  db.approve(ticket,23011,'router-mgmt.aqixnet.com',key,apply=True,keys_file=auth,code=db.code_for(ticket))
  with urllib.request.urlopen(api+'/'+ticket,timeout=3) as r:
   response=json.load(r);assert response['status']=='approved'
   assert response['config']['slot']==23011
   assert response['config']['hostkey']==key
  # Owner-controlled per-ticket disconnect revokes only its own approved key.
  revoke=urllib.request.Request(api+'/revoke',json.dumps({'ticket':ticket}).encode(),headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(revoke,timeout=3) as r:assert r.status==200 and json.load(r)['status']=='revoked'
  with urllib.request.urlopen(revoke,timeout=3) as r:assert r.status==200 and json.load(r)['status']=='revoked'
  with urllib.request.urlopen(api+'/'+ticket,timeout=3) as r:assert json.load(r)['status']=='revoked'
  assert auth.read_text()=='existing-safe-ssh-key\n'
  # Same device/key reuses its current ticket, no duplicate pending requests.
  with urllib.request.urlopen(request,timeout=3) as r:assert r.status==202 and json.load(r)['ticket']!=ticket
  next_ticket=db.submit('AnotherPC',key)
  assert db.submit('AnotherPC',key)==next_ticket
  # Approved original key is not a pending ticket; only two new submissions remain allowed.
  raw=base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes((i+2)%256 for i in range(32))).decode()
  req=urllib.request.Request(api,json.dumps({'device':'TestPC','public_key':'ssh-ed25519 '+raw}).encode(),headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(req,timeout=3) as r:assert r.status==202
  try:
   other=base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes((i+4)%256 for i in range(32))).decode()
   req=urllib.request.Request(api,json.dumps({'device':'TestPC','public_key':'ssh-ed25519 '+other}).encode(),headers={'Content-Type':'application/json'})
   urllib.request.urlopen(req,timeout=3)
   raise AssertionError('unbounded registration accepted')
  except urllib.error.HTTPError as e:assert e.code==429
  # Pending-ticket cancellation is an explicit server-side terminal state.
  cancel_key='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes((i+9)%256 for i in range(32))).decode()
  cancel_request=urllib.request.Request(api,json.dumps({'device':'CancelPC','public_key':cancel_key}).encode(),headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(cancel_request,timeout=3) as r:cancelled=json.load(r)['ticket']
  cancel=urllib.request.Request(api+'/revoke',json.dumps({'ticket':cancelled}).encode(),headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(cancel,timeout=3) as r:assert r.status==200 and json.load(r)['status']=='revoked'
  with urllib.request.urlopen(api+'/'+cancelled,timeout=3) as r:assert json.load(r)['status']=='revoked'
  try:
   db.approve(cancelled,None,'test-gateway.example',key,code=db.code_for(cancelled))
   raise AssertionError('cancelled request was approvable')
  except ValueError:pass
  print('PASS HTTP enrollment, per-device rate limit, approved revoke and pending cancel')
 finally:web.shutdown();web.server_close();thread.join(timeout=3)
