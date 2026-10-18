import base64, pathlib, tempfile, sys
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from service import Enrollment
key='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes(range(32))).decode()
with tempfile.TemporaryDirectory() as d:
 s=Enrollment(pathlib.Path(d)/'db.sqlite')
 t=s.submit('Miniko',key)
 assert s.poll(t)=={'status':'pending'}
 assert len(s.code_for(t))==4
 # Waiting for operator can span the initial 15-minute creation time,
 # while the same client continues polling. A stale inactive ticket expires.
 with s.db() as conn: conn.execute('UPDATE requests SET created=created-1800 WHERE ticket=?',(t,))
 assert s.poll(t)=={'status':'pending'}
 assert s.approve(t,23001,'router-mgmt.aqixnet.com',key,code=s.code_for(t))['dry_run']
 stale=s.submit('Offline-PC','ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes((i+24)%256 for i in range(32))).decode())
 with s.db() as conn:conn.execute('UPDATE requests SET last_seen=last_seen-901 WHERE ticket=?',(stale,))
 assert s.poll(stale)=={'status':'expired'}
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
 # Migration from older broker DB must not lose tickets or accept an approval without code.
 import sqlite3, time
 legacy=pathlib.Path(d)/'oldbroker.sqlite'
 with sqlite3.connect(legacy) as db:
  db.execute('CREATE TABLE requests(ticket TEXT PRIMARY KEY,device TEXT,key TEXT,created INTEGER,status TEXT,slot INTEGER,config TEXT)')
  db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?)',('L'*43,'LegacyPC',key,int(time.time()),'pending',None,None))
 old=Enrollment(legacy)
 assert old.code_for('L'*43) is None
 assert old.submit('LegacyPC',key)=='L'*43
 assert len(old.code_for('L'*43))==4
 assert old.recent_events()==[], 'Migrated legacy pending request does not create a new request event'
 try:old.approve('L'*43,23010,'router-mgmt.aqixnet.com',key,code='ZZZZZ');raise AssertionError('wrong migrated code accepted')
 except ValueError:pass
 assert old.approve('L'*43,23010,'router-mgmt.aqixnet.com',key,code=old.code_for('L'*43))['dry_run']
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
 with s.db() as conn:conn.execute('DROP TRIGGER refuse_approval')
 assert s.poll(third)=={'status':'pending'}
 # Approved lease is expired by background Gate reaper, even without a client request.
 with s.db() as conn:conn.execute("UPDATE requests SET expires_at=? WHERE ticket=?",(int(time.time())-1,auto_ticket))
 simulated_live={23000}
 def bounded_close(slot):return slot not in simulated_live
 first=s.reap_expired(auth,bounded_close)
 assert first['retry_needed']>=1 and s.poll(auto_ticket)['status']=='revoking',first
 assert '127.0.0.1:23000' not in auth.read_text(), 'expired device key remains authorized'
 assert 'existing-safe-ssh-key' in auth.read_text(), 'operator key was removed'
 simulated_live.remove(23000)
 second=s.reap_expired(auth,bounded_close)
 assert second['revoked']>=1 and s.poll(auto_ticket)['status']=='revoked',second
 assert 'existing-safe-ssh-key' in auth.read_text()
 # Doctor must not disclose public keys or tickets when reporting stray grants.
 assert s.doctor(auth)['ok'],s.doctor(auth)
 extra='restrict,port-forwarding,permitlisten="127.0.0.1:24888" '+third_key
 with auth.open('a') as output:output.write(extra+'\n')
 report=s.doctor(auth)
 assert not report['ok'] and any(f['problem']=='unmatched_scoped_authorizations' for f in report['findings']),report
 assert third_key not in str(report) and third not in str(report)
 auth.write_text(auth.read_text().replace(extra+'\n',''))
 assert s.doctor(auth)['ok'],s.doctor(auth)



 try:s.submit('Bad',key+'\ncommand="evil"');raise Exception('bad key accepted')
 except ValueError:pass
 try:s.approve(t,23001,'router-mgmt.aqixnet.com',key,code=s.code_for(t));raise Exception('replay accepted')
 except ValueError:pass
 print('PASS 7: request, pending, not-found, dry-run, approval, injection guard, replay guard')
