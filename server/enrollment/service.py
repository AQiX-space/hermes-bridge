#!/usr/bin/env python3
"""Operator-approved enrollment broker. Serve on 127.0.0.1 behind trusted HTTPS."""
import argparse, base64, json, os, re, secrets, sqlite3, time
from contextlib import contextmanager
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

KEY_RE=re.compile(r'^ssh-ed25519 ([a-zA-Z0-9+/]+={0,2})(?:[ \t]+[^\r\n]*)?$')
def public_key(value):
    m=KEY_RE.fullmatch(value.strip())
    if not m:raise ValueError('invalid public key')
    raw=base64.b64decode(m[1],validate=True)
    if len(raw)!=51 or not raw.startswith(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'):raise ValueError('malformed ed25519 key')
    return 'ssh-ed25519 '+m[1]

class Enrollment:
    def __init__(self,path):
        self.path=str(path)
        with self.db() as d:d.execute('CREATE TABLE IF NOT EXISTS requests(ticket TEXT PRIMARY KEY,device TEXT,key TEXT,created INTEGER,status TEXT,slot INTEGER,config TEXT)')
    @contextmanager
    def db(self):
        c=sqlite3.connect(self.path,timeout=15);c.row_factory=sqlite3.Row
        try:
            yield c
            c.commit()
        except:
            c.rollback()
            raise
        finally:
            c.close()
    def submit(self,device,key):
        if not isinstance(device,str) or not re.fullmatch(r'[a-zA-Z0-9._-]{1,64}',device):raise ValueError('bad device')
        key=public_key(key);ticket=secrets.token_urlsafe(32)
        with self.db() as d:d.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?)',(ticket,device,key,int(time.time()),'pending',None,None))
        return ticket
    def poll(self,ticket):
        if not re.fullmatch(r'[a-zA-Z0-9_-]{40,60}',ticket):return {'status':'not_found'}
        with self.db() as d:r=d.execute('SELECT * FROM requests WHERE ticket=?',(ticket,)).fetchone()
        if not r:return {'status':'not_found'}
        if r['status']=='pending' and time.time()-r['created']>900:return {'status':'expired'}
        result={'status':r['status']}
        if r['status']=='approved':result['config']=json.loads(r['config'])
        return result
    def approve(self,ticket,slot,host,hostkey,apply=False):
        if not 23000<=slot<=24999:raise ValueError('invalid slot')
        if not re.fullmatch(r'[A-Za-z0-9.-]{3,255}',host):raise ValueError('invalid host')
        with self.db() as d:
            r=d.execute('SELECT * FROM requests WHERE ticket=? AND status=?',(ticket,'pending')).fetchone()
            if not r or time.time()-r['created']>900:raise ValueError('not pending')
            if d.execute('SELECT 1 FROM requests WHERE status=? AND slot=?',('approved',slot)).fetchone():raise ValueError('slot already assigned')
            config={'host':host,'port':22471,'slot':slot,'hostkey':public_key(hostkey)}
            auth='restrict,port-forwarding,permitlisten="127.0.0.1:%s" %s' % (slot,r['key'])
            if apply:d.execute('UPDATE requests SET status=?,slot=?,config=? WHERE ticket=?',('approved',slot,json.dumps(config),ticket))
            return {'auth_line':auth,'config':config,'dry_run':not apply}

def handler(db):
    class Handler(BaseHTTPRequestHandler):
        def send(self,code,data):
            b=json.dumps(data).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
        def do_POST(self):
            if self.path!='/v1/enroll':return self.send(404,{'error':'not found'})
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=4096:return self.send(413,{'error':'size'})
                obj=json.loads(self.rfile.read(size));ticket=db.submit(obj['device'],obj['public_key'])
                self.send(202,{'ticket':ticket,'status':'pending'})
            except (ValueError,KeyError,TypeError):self.send(400,{'error':'invalid device key'})
        def do_GET(self):
            if not self.path.startswith('/v1/enroll/'):return self.send(404,{'error':'not found'})
            result=db.poll(self.path[len('/v1/enroll/'):]);self.send(200 if result['status']!='not_found' else 404,result)
        def log_message(self,*args):pass
    return Handler

def main():
    p=argparse.ArgumentParser();p.add_argument('--db',type=Path,required=True);sub=p.add_subparsers(dest='action',required=True)
    sub.add_parser('serve');sub.add_parser('pending')
    ap=sub.add_parser('approve');ap.add_argument('--ticket',required=True);ap.add_argument('--slot',type=int,required=True);ap.add_argument('--host',required=True);ap.add_argument('--hostkey',required=True)
    a=p.parse_args();db=Enrollment(a.db)
    if a.action=='serve':ThreadingHTTPServer(('127.0.0.1',18511),handler(db)).serve_forever()
    elif a.action=='pending':
        with db.db() as conn:print(json.dumps([dict(r) for r in conn.execute("SELECT ticket,device,key,created FROM requests WHERE status='pending' AND created>?",(int(time.time())-900,))]))
    else:print(json.dumps(db.approve(a.ticket,a.slot,a.host,a.hostkey,False),indent=2))
if __name__=='__main__':main()
