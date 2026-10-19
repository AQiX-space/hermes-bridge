import base64, pathlib, tempfile, sys
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from service import Enrollment
from registry import DeviceRegistry

def key(n):
 return 'ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes((i+n)%256 for i in range(32))).decode()
with tempfile.TemporaryDirectory() as temp:
 path=pathlib.Path(temp)/'gate.sqlite3'
 enrollment=Enrollment(path)
 reg=DeviceRegistry(path)
 ticket=enrollment.submit('Mobile-Windows',key(1))
 try:reg.add('laptop','windows','Mobile-Windows',key(1));raise AssertionError('registered without verifying')
 except AssertionError:raise
 except Exception:pass
 auth=pathlib.Path(temp)/'authorized_keys';auth.write_text('trusted-baseline\n')
 enrollment.approve(ticket,23001,'test-gate.example',key(2),apply=True,keys_file=auth,code=enrollment.code_for(ticket))
 assert reg.add('laptop','windows','Mobile-Windows',key(1))['alias']=='laptop'
 assert reg.lookup_live('LAPTOP')['status']=='approved'
 assert reg.lookup_live('laptop')['slot']==23001
 try:reg.add('other','windows','Mobile-Windows',key(1));raise AssertionError('accepted duplicate key')
 except __import__('sqlite3').IntegrityError:pass
 try:reg.add('laptop','openwrt','New-device',key(3));raise AssertionError('accepted reused alias')
 except (ValueError,__import__('sqlite3').IntegrityError):pass
 try:reg.add('bad name','openwrt','New-device',key(3));raise AssertionError('accepted invalid alias')
 except ValueError:pass
 reg.set_enabled('laptop',False)
 try:reg.lookup_live('laptop');raise AssertionError('disabled alias resolved')
 except ValueError:pass
 reg.set_enabled('laptop',True)
 enrollment.revoke(ticket,apply=True,keys_file=auth)
 assert reg.lookup_live('laptop')['status']=='offline'
 # The same verified hardware identity can appear on a completely different network.
 new_ticket=enrollment.submit('Mobile-Windows',key(1))
 assert reg.lookup_live('laptop')['status']=='pending'
 # A second portable form factor has the same registry semantics.
 gate_ticket=enrollment.submit('Cudy-TR1200',key(4))
 enrollment.approve(gate_ticket,23002,'test-gate.example',key(2),apply=True,keys_file=auth,code=enrollment.code_for(gate_ticket))
 reg.add('field-gate','openwrt','Cudy-TR1200',key(4))
 assert reg.lookup_live('field-gate')['status']=='approved'
 assert {x['platform'] for x in reg.list()}=={'windows','openwrt'}
 assert all('ticket' not in x and 'key' not in x for x in reg.list())
 print('PASS: named device registry, key identity, platform, aliases, revoked/disconnected status, mobility')
