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
 auth=pathlib.Path(d)/'authorized_keys';auth.write_text('existing-safe-ssh-key\n')
 s.approve(t,23001,'router-mgmt.aqixnet.com',key,apply=True,keys_file=auth)
 assert 'permitlisten=\"127.0.0.1:23001\"' in auth.read_text()
 assert list(pathlib.Path(d).glob('authorized_keys.backup-*'))
 assert s.poll(t)['config']['slot']==23001
 second=s.submit('Miniko-clone',key)
 try:s.approve(second,23002,'router-mgmt.aqixnet.com',key,apply=True,keys_file=auth);raise Exception('duplicate device key accepted')
 except ValueError:pass
 assert auth.read_text().count('permitlisten=')==1
 try:s.submit('Bad',key+'\ncommand="evil"');raise Exception('bad key accepted')
 except ValueError:pass
 try:s.approve(t,23001,'router-mgmt.aqixnet.com',key);raise Exception('replay accepted')
 except ValueError:pass
 print('PASS 7: request, pending, not-found, dry-run, approval, injection guard, replay guard')
