"""Connector PC/IP metadata and safe auto-renew on expired pending ticket."""
import base64
import json
import pathlib
import sqlite3
import tempfile
import threading
import time
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from service import Enrollment, handler

KEY = 'ssh-ed25519 ' + base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + bytes(range(32))).decode()

with tempfile.TemporaryDirectory() as tmp:
    path=pathlib.Path(tmp)/'db.sqlite'
    # An old SQLite installation receives new nullable metadata columns on start.
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE requests(ticket TEXT PRIMARY KEY,device TEXT,key TEXT,created INTEGER,status TEXT,slot INTEGER,config TEXT)')
    db=Enrollment(path)
    with db.db() as conn:
        cols={col[1] for col in conn.execute('PRAGMA table_info(requests)')}
    assert {'computer_name','local_ipv4'}<=cols
    auth=pathlib.Path(tmp)/'authorized_keys';auth.write_text('unrelated-key\n')
    web=ThreadingHTTPServer(('127.0.0.1',0),handler(db,auth))
    t=threading.Thread(target=web.serve_forever,daemon=True);t.start()
    try:
        url='http://127.0.0.1:%d/v1/enroll' % web.server_port
        def post(payload,success=True):
            request=urllib.request.Request(url,json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
            try:
                with urllib.request.urlopen(request,timeout=3) as res:
                    assert res.status==202
                    return json.load(res)
            except urllib.error.HTTPError as error:
                if success:raise
                assert error.code==400
                return None
        payload={'device':'FriendlyAlias','public_key':KEY,'computer_name':'MINIKO','local_ipv4':'192.168.100.23'}
        original=post(payload)
        code=original['code']; old_ticket=original['ticket']
        assert len(code)==4
        assert db.preflight(code,listeners=set())=={'status':'ready','code':code,'device':'FriendlyAlias','computer_name':'MINIKO','local_ipv4':'192.168.100.23','blockers':[]}
        with db.db() as conn:
            row=conn.execute('SELECT computer_name,local_ipv4 FROM requests WHERE ticket=?',(old_ticket,)).fetchone()
            assert (row['computer_name'],row['local_ipv4'])==('MINIKO','192.168.100.23')
        # A repeat from the same key keeps code and diagnostic data, not a new registration.
        same=post(dict(payload,local_ipv4='192.168.100.99'))
        assert same['ticket']==old_ticket and same['code']==code
        assert db.preflight(code,listeners=set())['local_ipv4']=='192.168.100.23'
        # Simulate 15m inactivity; ticket must be confirmed expired before refresh.
        with db.db() as conn:
            conn.execute('UPDATE requests SET last_seen=?,created=? WHERE ticket=?',(int(time.time())-1000,int(time.time())-1000,old_ticket))
        with urllib.request.urlopen(url+'/'+old_ticket,timeout=3) as res:
            assert json.load(res)=={'status':'expired'}
        renewed=post(dict(payload,local_ipv4='10.0.0.42'))
        assert renewed['ticket']!=old_ticket and renewed['code']!=code
        assert db.preflight(renewed['code'],listeners=set())['local_ipv4']=='10.0.0.42'
        # A fresh request is not reissued while pending; rate limit remains meaningful.
        assert post(payload)['ticket']==renewed['ticket']
        # Nullable metadata preserves compatibility with older Connector builds.
        other_key='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+bytes((n+22)%256 for n in range(32))).decode()
        legacy=post({'device':'OLDPC','public_key':other_key})
        info=db.preflight(legacy['code'],listeners=set())
        assert info['computer_name'] is None and info['local_ipv4'] is None
        for bad in ('127.0.0.1','224.0.0.1','169.254.2.1','not-ip','::1','10.0.0.1\nheader'):
            assert post({'device':'BAD'+str(len(bad)),'public_key':other_key,'local_ipv4':bad},False) is None
        assert post({'device':'TEST','public_key':other_key,'computer_name':'bad\nname'},False) is None
        assert auth.read_text()=='unrelated-key\n'
        print('PASS DB migration, hostname/IP diagnostics, legacy clients, validation, expired-ticket reissue and deduplication')
    finally:
        web.shutdown();t.join(timeout=2)
