import base64, pathlib, tempfile, sys
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from service import Enrollment
key='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes(range(32))).decode()
with tempfile.TemporaryDirectory() as d:
 s=Enrollment(pathlib.Path(d)/'db.sqlite')
 t=s.submit('Miniko',key)
 assert s.poll(t)=={'status':'pending'}
 assert len(s.code_for(t))==5
 assert s.poll('random')=={'status':'not_found'}
 try:s.approve(t,23001,'router-mgmt.aqixnet.com',key);raise AssertionError('approved without code')
 except ValueError:pass
 try:s.approve(t,23001,'router-mgmt.aqixnet.com',key,code='AAAAA');raise AssertionError('accepted wrong code')
 except ValueError:pass
 response=s.approve(t,23001,'router-mgmt.aqixnet.com',key,code=s.code_for(t))
 assert response['dry_run'] and 'permitlisten="127.0.0.1:23001"' in response['auth_line']
 assert s.poll(t)=={'status':'pending'}
 auth=pathlib.Path(d)/'authorized_keys';auth.write_text('existing-safe-ssh-key\n')
 s.approve(t,23001,'router-mgmt.aqixnet.com',key,apply=True,keys_file=auth,code=s.code_for(t))
 assert 'permitlisten=\"127.0.0.1:23001\"' in auth.read_text()
 assert list(pathlib.Path(d).glob('authorized_keys.backup-*'))
 assert s.poll(t)['config']['slot']==23001
 # Temporary device is revocable without deleting or touching other authorized keys.
 assert s.revoke(t)['dry_run']
 assert s.poll(t)['status']=='approved'
 revoke_result=s.revoke(t,apply=True,keys_file=auth)
 assert revoke_result['backup']
 assert s.poll(t)=={'status':'revoked'}
 assert 'existing-safe-ssh-key' in auth.read_text()
 assert 'permitlisten="127.0.0.1:23001"' not in auth.read_text()
 try:s.revoke(t,apply=True,keys_file=auth);raise Exception('revocation replay accepted')
 except ValueError:pass
 # Auto-allocation skips an already approved slot; dry run never consumes one.
 auto_key='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes((i+11)%256 for i in range(32))).decode()
 auto_ticket=s.submit('Temporary-Laptop',auto_key)
 assert s.approve(auto_ticket,None,'router-mgmt.aqixnet.com',key,code=s.code_for(auto_ticket))['config']['slot']==23000
 assert s.poll(auto_ticket)=={'status':'pending'}
 s.approve(auto_ticket,None,'router-mgmt.aqixnet.com',key,apply=True,keys_file=auth,code=s.code_for(auto_ticket))
 assert s.poll(auto_ticket)['config']['slot']==23000
 next_auto='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes((i+12)%256 for i in range(32))).decode()
 another=s.submit('Another-Laptop',next_auto)
 assert s.approve(another,None,'router-mgmt.aqixnet.com',key,code=s.code_for(another))['config']['slot']==23001
 second=s.submit('Miniko-clone',auto_key)
 try:s.approve(second,23002,'router-mgmt.aqixnet.com',key,apply=True,keys_file=auth,code=s.code_for(second));raise Exception('duplicate device key accepted')
 except ValueError:pass
 assert auth.read_text().count('permitlisten=')==1
 third_key='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes(reversed(range(32)))).decode()
 third=s.submit('Rollback-test',third_key)
 before=auth.read_bytes()
 with s.db() as conn: conn.execute("CREATE TRIGGER refuse_approval BEFORE UPDATE ON requests BEGIN SELECT RAISE(ABORT, 'simulate db failure'); END")
 try:s.approve(third,23003,'router-mgmt.aqixnet.com',key,apply=True,keys_file=auth,code=s.code_for(third));raise Exception('DB failure not detected')
 except Exception as ex:assert 'simulate db failure' in str(ex)
 assert auth.read_bytes()==before, 'database failure left unauthorized device key behind'
 assert s.poll(third)=={'status':'pending'}

 try:s.submit('Bad',key+'\ncommand="evil"');raise Exception('bad key accepted')
 except ValueError:pass
 try:s.approve(t,23001,'router-mgmt.aqixnet.com',key,code=s.code_for(t));raise Exception('replay accepted')
 except ValueError:pass
 print('PASS 7: request, pending, not-found, dry-run, approval, injection guard, replay guard')
