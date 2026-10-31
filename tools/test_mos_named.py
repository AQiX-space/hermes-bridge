import json
from mos_named import resolve
class Result:
 def __init__(self,data=b'',code=0):self.stdout=data;self.returncode=code;self.stderr=b''
def fake(cmd,**kwargs):
 if 'resolve-device' in cmd[-1]:return Result(json.dumps(dict(alias='laptop',platform='windows',device='WIN',status='approved',slot=23000)).encode())
 assert 'socket.create_connection' in cmd[-1]
 return Result()
r=resolve('laptop','gate.example',run=fake)
assert r['status']=='connected' and r['tunnel_verified']
def down(cmd,**kwargs):
 if 'resolve-device' in cmd[-1]:return fake(cmd,**kwargs)
 return Result(code=1)
assert resolve('laptop','gate.example',run=down)['status']=='approved_not_connected'
for bad in ('abc;whoami','-X','abc xyz'):
 try:resolve(bad,'gate.example',run=fake);raise AssertionError('accepted unsafe alias')
 except ValueError:pass
print('PASS named MOS device resolution, tunnel probe, offline detection and input validation')
