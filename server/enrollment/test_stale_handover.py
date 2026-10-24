#!/usr/bin/env python3
"""Regression: same-key stale grants; an active listener must never be displaced."""
import base64
import pathlib
import tempfile
import time
from service import Enrollment


def key(seed):
    return 'ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes((seed+i)%256 for i in range(32))).decode()

with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory)
    db=Enrollment(root/'state.sqlite3')
    auth=root/'authorized_keys'; auth.write_text('operator-must-remain\n')
    server_key=key(99)
    device_key=key(1)
    old=db.submit('MINIKO',device_key)
    db.approve(old,23001,'gate.example',server_key,keys_file=auth,code=db.code_for(old),apply=True,
               approval_ttl_seconds=0)  # legacy unlimited state
    new=db.submit('MINIKO',device_key)
    code=db.code_for(new)
    assert new!=old
    report=db.preflight(code,listeners=set())
    assert report['status']=='blocked',report
    assert len(report['blockers'])==1 and report['blockers'][0]['code']==db.code_for(old)
    assert not report['blockers'][0]['listener_active']
    assert 'ticket' not in str(report) and old not in str(report)
    assert db.preflight(code,listeners={23001})['blockers'][0]['listener_active']
    assert db.preflight(code.lower(),listeners=set())['code']==code
    before=auth.read_text()
    try:
        db.replace_stale(old,new,code,'gate.example',server_key,auth,listeners={23001},apply=True)
        raise AssertionError('Displaced active connection')
    except ValueError as error:
        assert 'listening' in str(error)
    assert auth.read_text()==before
    assert db.poll(old)['status']=='approved' and db.poll(new)['status']=='pending'
    try:
        db.approve(new,None,'gate.example',server_key,code=code)
        raise AssertionError('Duplicate key bypassed ordinary approval')
    except ValueError as error:
        assert 'same key already reserved' in str(error)
    # Bad or already-reserved port is rejected before old authorization changes.
    for bad_port in (23001,65535):
        try:
            db.replace_stale(old,new,code,'gate.example',server_key,auth,slot=bad_port,
                             listeners=set(),apply=True)
            raise AssertionError('Unsafe port accepted')
        except ValueError:
            pass
        assert auth.read_text()==before and db.poll(old)['status']=='approved'
    # A different device name or key is never eligible, even if the caller has a ticket.
    alien=db.submit('OTHERPC',device_key)
    try:
        db.replace_stale(old,alien,db.code_for(alien),'gate.example',server_key,auth,
                         listeners=set(),apply=True)
        raise AssertionError('Other device stole the old authorization')
    except ValueError as error:
        assert 'same device and key' in str(error)
    assert auth.read_text()==before and db.poll(old)['status']=='approved'
    preview=db.replace_stale(old,new,code,'gate.example',server_key,auth,listeners=set())
    assert preview['dry_run'] and preview['old_slot']==23001
    assert auth.read_text()==before
    # Real localhost /proc has no test listeners. No other grants are modified.
    result=db.replace_stale(old,new,code,'gate.example',server_key,auth,apply=True,listeners=set())
    assert result['status']=='approved'
    assert db.poll(old)['status']=='revoked'
    assert db.poll(new)['status']=='approved'
    assert db.poll(new)['config']['slot']!=23001
    assert '127.0.0.1:23001' not in auth.read_text()
    assert 'operator-must-remain' in auth.read_text()
    assert auth.read_text().count('permitlisten=')==1
    with db.db() as conn:
        expires=conn.execute('SELECT expires_at FROM requests WHERE ticket=?',(new,)).fetchone()[0]
    assert 1<=expires-int(time.time())<=7200
    assert db.doctor(auth)['ok']
    assert db.preflight(code,listeners=set())['status']=='not_found'

with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory); db=Enrollment(root/'state.sqlite3')
    auth=root/'authorized_keys';auth.write_text('operator\n')
    first=db.submit('OtherMachine',key(31))
    db.approve(first,23010,'gate.example',key(80),apply=True,keys_file=auth,code=db.code_for(first))
    with db.db() as conn:
        ttl=conn.execute('SELECT expires_at FROM requests WHERE ticket=?',(first,)).fetchone()[0]
    assert 1<=ttl-int(time.time())<=7200, 'New approvals require a bounded default lease'
    # Expired leased grants are garbage-collected without affecting operator keys.
    with db.db() as conn:
        conn.execute('UPDATE requests SET expires_at=? WHERE ticket=?',(int(time.time())-1,first))
    summary=db.reap_expired(auth,lambda slot: True)
    assert summary['revoked']==1 and db.poll(first)['status']=='revoked'
    assert auth.read_text()=='operator\n'
print('PASS preflight + guarded stale-key replacement + bounded default TTL + expiry')

# Second-phase database failure leaves no stale SSH authorization and never
# opens the pending ticket. The operator must be told the handover is partial.
with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory);db=Enrollment(root/'state.sqlite3')
    auth=root/'authorized_keys';auth.write_text('operator\n')
    server_key=key(90);device_key=key(13)
    old=db.submit('MINIKO',device_key)
    db.approve(old,23040,'gate.example',server_key,apply=True,keys_file=auth,code=db.code_for(old),approval_ttl_seconds=0)
    new=db.submit('MINIKO',device_key);code=db.code_for(new)
    with db.db() as conn:
        conn.execute("CREATE TRIGGER stop_new_approval BEFORE UPDATE ON requests WHEN NEW.status='approved' BEGIN SELECT RAISE(ABORT,'injected approve failure'); END")
    try:
        db.replace_stale(old,new,code,'gate.example',server_key,auth,listeners=set(),apply=True)
        raise AssertionError('Handover reported success after database failure')
    except Exception as error:
        assert 'injected approve failure' in str(error)
    assert db.poll(old)['status']=='revoked'
    assert db.poll(new)['status']=='pending'
    assert auth.read_text()=='operator\n'
    assert db.doctor(auth)['ok']
    with db.db() as conn:conn.execute('DROP TRIGGER stop_new_approval')
    retry=db.approve(new,23041,'gate.example',server_key,apply=True,keys_file=auth,code=code)
    assert not retry['dry_run'] and db.poll(new)['status']=='approved'
print('PASS partial-commit fail-closed and operator retry')
