import base64, pathlib, tempfile, sys
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from service import Enrollment
key='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes(range(32))).decode()
with tempfile.TemporaryDirectory() as d:
 s=Enrollment(pathlib.Path(d)/'db.sqlite')
 t=s.submit('Miniko',key)
 assert s.poll(t)=={'status':'pending'}
 assert s.poll('random')=={'status':'not_found'}
 response=s.approve(t,23001,'router-mgmt.aqixnet.com',key)
 assert response['dry_run'] and 'permitlisten="127.0.0.1:23001"' in response['auth_line']
 assert s.poll(t)=={'status':'pending'}
 s.approve(t,23001,'router-mgmt.aqixnet.com',key,apply=True)
 assert s.poll(t)['config']['slot']==23001
 try:s.submit('Bad',key+'\ncommand="evil"');raise Exception('bad key accepted')
 except ValueError:pass
 try:s.approve(t,23001,'router-mgmt.aqixnet.com',key);raise Exception('replay accepted')
 except ValueError:pass
 print('PASS 7: request, pending, not-found, dry-run, approval, injection guard, replay guard')
