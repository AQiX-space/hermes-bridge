"""Resident registration requests are surfaced to operator, not auto-approved."""
import base64, pathlib, tempfile
from service import Enrollment
KEY='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes(range(32))).decode()
with tempfile.TemporaryDirectory() as tmp:
    root=pathlib.Path(tmp)
    broker=Enrollment(root/'db.sqlite')
    resident=broker.submit('RESIDENT-PC',KEY,requested_mode='resident')
    code=broker.code_for(resident)
    assert broker.preflight(code,listeners=set())['requested_mode']=='resident'
    assert broker.poll(resident)=={'status':'pending'}
    try:broker.submit('RESIDENT-PC',KEY,requested_mode='support')
    except ValueError:pass
    else:raise AssertionError('Pending ticket mode changed silently')
    try:broker.submit('BAD-PC',KEY,requested_mode='system')
    except ValueError:pass
    else:raise AssertionError('Unrecognized privilege mode was accepted')
    auth=root/'authorized_keys';auth.write_text('')
    server_key=KEY
    dry=broker.approve(resident,None,'gr2.touch01.top',server_key,code=code,approval_ttl_seconds=0)
    assert dry['dry_run'] and broker.poll(resident)=={'status':'pending'}
    broker.approve(resident,None,'gr2.touch01.top',server_key,code=code,approval_ttl_seconds=0,apply=True,keys_file=auth)
    assert broker.poll(resident)['status']=='approved'
    with broker.db() as db:
        row=db.execute('SELECT requested_mode,expires_at FROM requests WHERE ticket=?',(resident,)).fetchone()
        assert row['requested_mode']=='resident' and row['expires_at'] is None
    print('PASS: requested resident mode, explicit unlimited approval, no automatic privilege change')
