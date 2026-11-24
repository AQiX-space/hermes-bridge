"""Rehearse migrating the exact legacy GR2 requests columns without touching production."""
import json
import pathlib
import sqlite3
import tempfile
import time
from service import Enrollment

LEGACY_COLUMNS=('ticket','device','key','created','status','slot','config','code','last_seen','expires_at','computer_name','local_ipv4')
with tempfile.TemporaryDirectory(prefix='hermes-gr2-schema-test-') as tmp:
    db_path=pathlib.Path(tmp)/'copy-shaped-like-gr2.sqlite'
    now=int(time.time())
    with sqlite3.connect(db_path) as db:
        db.execute('''CREATE TABLE requests(
           ticket TEXT PRIMARY KEY,device TEXT,key TEXT,created INTEGER,
           status TEXT,slot INTEGER,config TEXT,code TEXT,last_seen INTEGER,
           expires_at INTEGER,computer_name TEXT,local_ipv4 TEXT)''')
        db.execute('''CREATE TABLE audit_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL,event TEXT NOT NULL,
          device TEXT NOT NULL,slot INTEGER,ticket_hash TEXT NOT NULL)''')
        db.execute("CREATE UNIQUE INDEX approved_slots ON requests(slot) WHERE status='approved'")
        db.execute("CREATE UNIQUE INDEX approved_keys ON requests(key) WHERE status='approved'")
        old_ticket='a'*43
        db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
          (old_ticket,'LEGACY-PC','ssh-ed25519 LEGACY-KEY',now-120,'approved',23007,
           json.dumps({'host':'gr2.touch01.top','port':22471,'slot':23007}),
           'Ab31',now-120,now+3600,'LEGACY-PC','192.168.10.22'))
        pending_ticket='b'*43
        db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
          (pending_ticket,'PENDING-PC','ssh-ed25519 PENDING-KEY',now-10,'pending',None,
           None,'Bc42',now-10,None,'PENDING-PC','192.168.10.23'))
        initial_cols=[row[1] for row in db.execute('pragma table_info(requests)')]
        assert tuple(initial_cols)==LEGACY_COLUMNS
    Enrollment(db_path)
    # Repeated restarts must be idempotent and preserve all original access.
    Enrollment(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory=sqlite3.Row
        cols={row[1] for row in db.execute('pragma table_info(requests)')}
        assert cols==set(LEGACY_COLUMNS)|{'requested_mode','requested_lease_seconds'},cols
        approved=db.execute('SELECT * FROM requests WHERE ticket=?',(old_ticket,)).fetchone()
        assert (approved['status'],approved['slot'],approved['expires_at'])==('approved',23007,now+3600)
        assert approved['requested_mode']=='support' and approved['requested_lease_seconds'] is None
        pending=db.execute('SELECT * FROM requests WHERE ticket=?',(pending_ticket,)).fetchone()
        assert pending['status']=='pending' and pending['requested_mode']=='support'
        assert db.execute('SELECT COUNT(*) FROM requests').fetchone()[0]==2
        assert 'actor' in {row[1] for row in db.execute('pragma table_info(audit_events)')}
        try:
            db.execute('INSERT INTO requests(ticket,device,key,status,slot) VALUES(?,?,?,?,?)',
                       ('c'*43,'COLLISION','ssh-ed25519 DIFFERENT','approved',23007))
        except sqlite3.IntegrityError:pass
        else:raise AssertionError('schema migration removed slot uniqueness')
        db.rollback()
    print('PASS: legacy GR2 schema migration twice, approved and pending grants preserved, unique slots enforced')
