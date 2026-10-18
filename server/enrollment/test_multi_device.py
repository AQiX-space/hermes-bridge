"""Independent Windows devices behind one external IP: broker lifecycle regression."""
import base64
import json
import pathlib
import tempfile
import threading
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from service import Enrollment, handler

def pubkey(seed):
    return 'ssh-ed25519 '+base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+bytes((i+seed)%256 for i in range(32))).decode()

with tempfile.TemporaryDirectory() as temporary:
    root=pathlib.Path(temporary)
    db=Enrollment(root/'requests.sqlite3')
    keys=root/'authorized_keys';keys.write_text('original-operator-key\n')
    # Both sessions receive independent grants and scoped reverse ports.
    listening={23000,23001}
    def stop(port):
        if port in listening:return False
        return True
    web=ThreadingHTTPServer(('127.0.0.1',0),handler(db,keys,stop))
    thread=threading.Thread(target=web.serve_forever,daemon=True);thread.start()
    base='http://127.0.0.1:%d/v1/enroll'%web.server_port
    def send(url,payload):
        req=urllib.request.Request(url,json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=4) as response:return response.status,json.load(response)
    try:
        tickets={}
        for name,seed in [('ALEXHUB',0),('MINIKO',30)]:
            status,response=send(base,{'device':name,'public_key':pubkey(seed)})
            assert status==202
            tickets[name]=response['ticket']
            assert len(response['code'])==4
        assert len(set(tickets.values()))==2
        for index,(name,seed) in enumerate([('ALEXHUB',0),('MINIKO',30)]):
            ticket=tickets[name]
            slot=23000+index
            db.approve(ticket,slot,'example-gateway.test',pubkey(70),apply=True,keys_file=keys,code=db.code_for(ticket))
            with urllib.request.urlopen(base+'/'+ticket,timeout=4) as response:
                result=json.load(response)
            assert result['status']=='approved' and result['config']['slot']==slot
        assert keys.read_text().count('permitlisten=')==2
        # Revoking one device never changes the other device or its TCP listener.
        ticket=tickets['ALEXHUB']
        try:send(base+'/revoke',{'ticket':ticket})
        except urllib.error.HTTPError as error:assert error.code==503
        else:raise AssertionError('live first session reported closed')
        assert db.poll(tickets['MINIKO'])['status']=='approved'
        listening.remove(23000)
        status,result=send(base+'/revoke',{'ticket':ticket})
        assert status==200 and result['status']=='revoked'
        assert keys.read_text().count('permitlisten=')==1
        assert '127.0.0.1:23001' in keys.read_text()
        assert db.poll(tickets['MINIKO'])['status']=='approved'
        listening.remove(23001)
        status,result=send(base+'/revoke',{'ticket':tickets['MINIKO']})
        assert status==200 and result['status']=='revoked'
        assert keys.read_text()=='original-operator-key\n'
        print('PASS separate approvals, unique slots, independent revocations from shared-IP clients')
    finally:
        web.shutdown();web.server_close();thread.join(timeout=4)
