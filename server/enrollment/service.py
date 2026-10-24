#!/usr/bin/env python3
"""Operator-approved enrollment broker. Serve on 127.0.0.1 behind trusted HTTPS."""
import argparse, base64, hashlib, json, os, re, secrets, sqlite3, sys, time
import datetime, shutil, tempfile
from contextlib import contextmanager
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

def audit_event(action, ticket, device, slot=None):
    """Minimal structured audit; never log bearer tickets, device public keys or secrets."""
    record={'event':'hermes_gate','action':action,'device':device,
            'ticket_id':hashlib.sha256(ticket.encode('ascii')).hexdigest()[:16],
            'slot':slot,'time_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    print(json.dumps(record,ensure_ascii=False),file=sys.stderr,flush=True)

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
        with self.db() as d:
            d.execute('CREATE TABLE IF NOT EXISTS requests(ticket TEXT PRIMARY KEY,device TEXT,key TEXT,created INTEGER,status TEXT,slot INTEGER,config TEXT)')
            # Replacing the original partial indices is safe: revoking reservations
            # MUST stay exclusive until the reverse listener is verified closed.
            d.execute('DROP INDEX IF EXISTS approved_slots')
            d.execute('DROP INDEX IF EXISTS approved_keys')
            d.execute("CREATE UNIQUE INDEX approved_slots ON requests(slot) WHERE status IN ('approved','revoking')")
            d.execute("CREATE UNIQUE INDEX approved_keys ON requests(key) WHERE status IN ('approved','revoking')")
            if not any(c[1]=='code' for c in d.execute('PRAGMA table_info(requests)')):d.execute('ALTER TABLE requests ADD COLUMN code TEXT')
            if not any(c[1]=='last_seen' for c in d.execute('PRAGMA table_info(requests)')):d.execute('ALTER TABLE requests ADD COLUMN last_seen INTEGER')
            if not any(c[1]=='expires_at' for c in d.execute('PRAGMA table_info(requests)')):
                d.execute('ALTER TABLE requests ADD COLUMN expires_at INTEGER')
            d.execute('UPDATE requests SET last_seen=created WHERE last_seen IS NULL')
            d.execute('CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, event TEXT NOT NULL, device TEXT NOT NULL, slot INTEGER, ticket_hash TEXT NOT NULL)')
            if not any(c[1]=='actor' for c in d.execute('PRAGMA table_info(audit_events)')):
                d.execute('ALTER TABLE audit_events ADD COLUMN actor TEXT')
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
    @staticmethod
    def audit(d,event,request,actor='system'):
        # Only a non-reversible ticket digest; never store bearer tokens or full keys in the event log.
        import hashlib
        if not re.fullmatch(r'[a-zA-Z0-9_@.:-]{1,80}',actor):actor='unknown'
        d.execute('INSERT INTO audit_events(ts,event,device,slot,ticket_hash,actor) VALUES(?,?,?,?,?,?)',
                  (int(time.time()),event,request['device'],request['slot'],hashlib.sha256(request['ticket'].encode()).hexdigest(),actor))
    def recent_events(self,limit=50):
        with self.db() as d:
            return [dict(row) for row in d.execute('SELECT ts,event,device,slot,ticket_hash,actor FROM audit_events ORDER BY id DESC LIMIT ?',(min(max(1,int(limit)),200),))]
    def submit(self,device,key):
        if not isinstance(device,str) or not re.fullmatch(r'[a-zA-Z0-9._-]{1,64}',device):raise ValueError('bad device')
        key=public_key(key)
        with self.db() as d:
            now=int(time.time())
            # Reopening a Connector must not create a second request or consume the rate limit.
            existing=d.execute('SELECT ticket FROM requests WHERE device=? AND key=? AND status=? AND last_seen>? ORDER BY created DESC LIMIT 1',(device,key,'pending',now-900)).fetchone()
            if existing:
                if self.code_for_unsafe(d,existing['ticket']) is None:
                    d.execute('UPDATE requests SET code=? WHERE ticket=?',(self.new_code(d,now),existing['ticket']))
                return existing['ticket']
            ticket=secrets.token_urlsafe(32)
            # Bound anonymous submissions until the HTTPS reverse proxy enforces per-IP limits.
            recent=d.execute('SELECT COUNT(*) FROM requests WHERE device=? AND created>?',(device,now-900)).fetchone()[0]
            if recent>=3:raise OverflowError('registration rate limit')
            code=self.new_code(d,now)
            d.execute('INSERT INTO requests(ticket,device,key,created,status,slot,config,code,last_seen) VALUES(?,?,?,?,?,?,?,?,?)',(ticket,device,key,now,'pending',None,None,code,now))
            self.audit(d,'requested',{'ticket':ticket,'device':device,'slot':None})
        return ticket
    @staticmethod
    def code_for_unsafe(d,ticket):
        row=d.execute('SELECT code FROM requests WHERE ticket=?',(ticket,)).fetchone()
        return row['code'] if row else None
    @staticmethod
    def new_code(d,now):
        uppercase='ABCDEFGHJKLMNPQRSTUVWXYZ'
        lowercase='abcdefghjkmnpqrstuvwxyz'
        while True:
            code=secrets.choice(uppercase)+secrets.choice(lowercase)+''.join(secrets.choice('0123456789') for _ in range(2))
            if not d.execute("SELECT 1 FROM requests WHERE code=? AND status='pending' AND last_seen>?",(code,now-900)).fetchone():return code
    def code_for(self,ticket):
        with self.db() as d:
            r=d.execute('SELECT code FROM requests WHERE ticket=?',(ticket,)).fetchone()
            return r['code'] if r else None
    def poll(self,ticket):
        if not re.fullmatch(r'[a-zA-Z0-9_-]{40,60}',ticket):return {'status':'not_found'}
        with self.db() as d:
            r=d.execute('SELECT * FROM requests WHERE ticket=?',(ticket,)).fetchone()
            if not r:return {'status':'not_found'}
            if r['status']=='pending':
                now=int(time.time())
                # Pending ticket remains valid while its original owner polls it;
                # expire only after 15 minutes of inactivity. Never rotate its code.
                if now-r['last_seen']>900:return {'status':'expired'}
                d.execute('UPDATE requests SET last_seen=? WHERE ticket=?',(now,ticket))
            result={'status':r['status']}
        if r['status']=='approved':
            if r['expires_at'] is not None and int(time.time())>=r['expires_at']:
                result={'status':'expiring'}
            else:result['config']=json.loads(r['config'])
        return result
    def preflight(self,code,listeners=None):
        """Read-only operator preflight by owner-facing code, without bearer tickets or public keys.

        A stopped listener does NOT authorize deleting the old SSH grant. The
        operator must separately revoke it; this method never mutates state.
        """
        if not isinstance(code,str) or not re.fullmatch(r'[A-Za-z0-9]{4,5}',code):
            raise ValueError('invalid bridge code')
        now=int(time.time())
        with self.db() as d:
            all_matches=d.execute('SELECT ticket,device,key,code,last_seen,status,slot FROM requests WHERE lower(code)=lower(?)',(code,)).fetchall()
            fresh=[r for r in all_matches if r['status']=='pending' and r['last_seen'] is not None and now-r['last_seen']<=900]
            if len(fresh)!=1:
                return {'status':'ambiguous' if len(fresh)>1 else ('expired' if any(r['status']== 'pending' for r in all_matches) else 'not_found'),
                        'matching_pending':len(fresh),'code':code}
            current=fresh[0]
            old=d.execute("SELECT code,device,status,slot,expires_at FROM requests WHERE key=? AND ticket!=? AND status IN ('approved','revoking') ORDER BY created DESC",(current['key'],current['ticket'])).fetchall()
        if listeners is None:
            from session_guard import tcp_listeners
            listeners=set(tcp_listeners())
        blockers=[{'type':'same_key_grant','code':r['code'],'device':r['device'],
                   'status':r['status'],'slot':r['slot'],
                   'listener_active':r['slot'] in listeners,
                   'expires_at':r['expires_at'],
                   'same_device':r['device']==current['device']} for r in old]
        return {'status':'blocked' if blockers else 'ready','code':current['code'],
                'device':current['device'],'blockers':blockers}

    def approve(self,ticket,slot,host,hostkey,apply=False,keys_file=None,code=None,approval_ttl_seconds=7200):
        if slot is not None and not 23000<=slot<=24999:raise ValueError('invalid slot')
        if not isinstance(approval_ttl_seconds,int) or not 0<=approval_ttl_seconds<=30*86400:raise ValueError('invalid approval lifetime')
        if not re.fullmatch(r'[A-Za-z0-9.-]{3,255}',host):raise ValueError('invalid host')
        with self.db() as d:
            r=d.execute('SELECT * FROM requests WHERE ticket=? AND status=?',(ticket,'pending')).fetchone()
            if not r or time.time()-r['last_seen']>900:raise ValueError('not pending')
            if not r['code'] or code!=r['code']:raise ValueError('matching confirmation code required')
            if slot is None:
                used={x[0] for x in d.execute("SELECT slot FROM requests WHERE status IN ('approved','revoking') AND slot IS NOT NULL")}
                slot=next((candidate for candidate in range(23000,25000) if candidate not in used),None)
                if slot is None:raise ValueError('no available reverse ports')
            if d.execute("SELECT 1 FROM requests WHERE status IN ('approved','revoking') AND slot=?",(slot,)).fetchone():raise ValueError('slot already assigned')
            blocker=d.execute("SELECT device,code,status,slot FROM requests WHERE status IN ('approved','revoking') AND key=?",(r['key'],)).fetchone()
            if blocker:raise ValueError('same key already reserved by %s session %s on %s (slot %s); inspect preflight and revoke separately' %
                                        (blocker['status'],blocker['code'],blocker['device'],blocker['slot']))
            config={'host':host,'port':22471,'slot':slot,'hostkey':public_key(hostkey)}
            auth='restrict,port-forwarding,permitlisten="127.0.0.1:%s" %s' % (slot,r['key'])
            backup=None
            if apply:
                if keys_file is None:raise ValueError('authorized_keys path required for approval')
                target=Path(keys_file)
                if target.is_symlink() or not target.is_file():raise ValueError('authorized_keys must exist as regular file')
                old=target.read_text()
                if '\r' in old or auth in old:raise ValueError('invalid or duplicate authorized_keys')
                stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
                backup=Path(str(target)+'.backup-'+stamp)
                if backup.exists():raise ValueError('backup path occupied')
                shutil.copy2(target,backup)
                info=target.stat()
                fd,tmp=tempfile.mkstemp(prefix='.hermes-auth-',dir=str(target.parent))
                try:
                    if hasattr(os,"fchmod"):os.fchmod(fd,0o600)
                    if hasattr(os,'fchown'):os.fchown(fd,info.st_uid,info.st_gid)
                    with os.fdopen(fd,'w') as out:out.write(old.rstrip('\n')+'\n'+auth+'\n')
                    os.replace(tmp,target)
                finally:
                    if os.path.exists(tmp):os.unlink(tmp)
                try:
                    expires_at=int(time.time())+approval_ttl_seconds if approval_ttl_seconds else None
                    d.execute('UPDATE requests SET status=?,slot=?,config=?,expires_at=? WHERE ticket=?',('approved',slot,json.dumps(config),expires_at,ticket))
                    self.audit(d,'approved',{'ticket':ticket,'device':r['device'],'slot':slot},actor='operator:'+str(os.environ.get('SUDO_USER') or os.environ.get('USER') or 'unknown'))
                    d.commit()
                except Exception:
                    shutil.copy2(backup,target)
                    raise
            if apply:audit_event('approved',ticket,r['device'],slot)
            return {'auth_line':auth,'config':config,'dry_run':not apply,'backup':str(backup) if backup else None}

    def replace_stale(self,old_ticket,new_ticket,code,host,hostkey,keys_file,
                      slot=None,apply=False,ttl_seconds=7200,listeners=None):
        """Explicit operator-approved same-device/same-key handover, never automatic.

        Fail closed if old session listens. Revoke fully before approval so unique
        key/port constraints remain intact. A failure between stages leaves old
        access revoked and new ticket pending; no access is widened silently.
        """
        now=int(time.time())
        with self.db() as d:
            old=d.execute('SELECT * FROM requests WHERE ticket=? AND status="approved"',(old_ticket,)).fetchone()
            new=d.execute('SELECT * FROM requests WHERE ticket=? AND status="pending"',(new_ticket,)).fetchone()
        if old is None or new is None or old_ticket==new_ticket:
            raise ValueError('expected distinct approved old and pending new tickets')
        if old['device']!=new['device'] or old['key']!=new['key']:
            raise ValueError('handover requires exact same device and key')
        if new['code']!=code or new['last_seen'] is None or now-new['last_seen']>900:
            raise ValueError('new confirmation code mismatch or stale pending ticket')
        if old['slot'] is None or not 23000<=old['slot']<=24999:
            raise ValueError('old reverse slot invalid')
        if listeners is None:
            from session_guard import tcp_listeners
            listeners=set(tcp_listeners())
        if old['slot'] in listeners:
            raise ValueError('old tunnel is still listening; do not replace active session')
        # Dry-run validates the fresh ticket, slot, host key, and no other DB conflicts.
        # Reserve the old slot for old until fully revoked; choose an independent slot.
        preview=self.preflight(code,listeners=listeners)
        blockers=preview.get('blockers',[])
        if len(blockers)!=1 or blockers[0]['code']!=old['code'] or blockers[0]['slot']!=old['slot']:
            raise ValueError('handover requires exactly one matching old grant')
        dry_slot=slot
        if dry_slot is None:
            with self.db() as d:
                used={r[0] for r in d.execute("SELECT slot FROM requests WHERE status IN ('approved','revoking') AND slot IS NOT NULL")}
            dry_slot=next((n for n in range(23000,25000) if n not in used),None)
        if dry_slot is None or not 23000<=dry_slot<=24999 or dry_slot==old['slot']:
            raise ValueError('handover requires valid distinct temporary port')
        with self.db() as d:
            if d.execute("SELECT 1 FROM requests WHERE status IN ('approved','revoking') AND slot=?",(dry_slot,)).fetchone():
                raise ValueError('replacement port already reserved')
        target=Path(keys_file)
        if target.is_symlink() or not target.is_file():raise ValueError('invalid authorized_keys target')
        lines=target.read_text().splitlines()
        old_auth='restrict,port-forwarding,permitlisten="127.0.0.1:%s" %s' % (old['slot'],old['key'])
        if lines.count(old_auth)!=1:
            raise ValueError('old SSH grant must exist exactly once')
        if any(line!=old_auth and line.endswith(' '+old['key']) for line in lines):
            raise ValueError('same key has an unexpected additional SSH authorization')
        if not re.fullmatch(r'[A-Za-z0-9.-]{3,255}',host):raise ValueError('invalid host')
        public_key(hostkey)
        if not isinstance(ttl_seconds,int) or not 1<=ttl_seconds<=7200:
            raise ValueError('handover TTL must be between 1 and 7200 seconds')
        if not apply:
            return {'dry_run':True,'device':old['device'],'old_code':old['code'],
                    'new_code':new['code'],'old_slot':old['slot'],'new_slot':dry_slot}
        # Check listener again immediately before the first write. Avoid a broad kill.
        from session_guard import tcp_listeners
        if old['slot'] in tcp_listeners():
            raise ValueError('old tunnel became active; handover cancelled')
        self.revoke(old_ticket,apply=True,keys_file=keys_file,terminal_status='revoking')
        # Fail closed on any race: do not disconnect an active session implicitly.
        if not self.finish_revocation(old_ticket,lambda old_slot: old_slot not in tcp_listeners()):
            raise RuntimeError('old tunnel appeared after authorization removal; old ticket revoking, new ticket still pending')
        result=self.approve(new_ticket,dry_slot,host,hostkey,apply=True,keys_file=keys_file,
                            code=code,approval_ttl_seconds=ttl_seconds)
        return {'dry_run':False,'status':'approved','device':old['device'],
                'old_code':old['code'],'new_code':new['code'],
                'old_slot':old['slot'],'new_slot':result['config']['slot'],
                'backup':result['backup']}

    def doctor(self,keys_file):
        """Read-only reconciliation of active DB grants and SSH keys, no secret values."""
        target=Path(keys_file)
        if target.is_symlink() or not target.is_file():raise ValueError('authorized_keys must be a regular file')
        lines=target.read_text().splitlines()
        findings=[]
        with self.db() as d:
            active=d.execute("SELECT device,key,slot,status FROM requests WHERE status IN ('approved','revoking') ORDER BY device").fetchall()
            expected=set()
            for r in active:
                auth='restrict,port-forwarding,permitlisten="127.0.0.1:%s" %s' % (r['slot'],r['key'])
                if r['status']=='approved':
                    expected.add(auth)
                    count=lines.count(auth)
                    if count!=1:findings.append({'device':r['device'],'slot':r['slot'],'problem':'approved_key_missing_or_duplicate'})
                elif auth in lines:
                    findings.append({'device':r['device'],'slot':r['slot'],'problem':'revoking_key_still_authorized'})
        unmatched=sum(1 for line in lines if 'permitlisten=' in line and line not in expected)
        if unmatched:findings.append({'problem':'unmatched_scoped_authorizations','count':unmatched})
        return {'ok':not findings,'approved':sum(r['status']=='approved' for r in active),
                'revoking':sum(r['status']=='revoking' for r in active),'findings':findings}

    def revoke(self,ticket,apply=False,keys_file=None,terminal_status="revoked"):
        """Remove one approved device key; ticket is a server-side operator identifier."""
        with self.db() as d:
            r=d.execute("SELECT * FROM requests WHERE ticket=? AND status='approved'",(ticket,)).fetchone()
            if r is None:raise ValueError('not an approved device')
            config=json.loads(r['config'])
            auth='restrict,port-forwarding,permitlisten="127.0.0.1:%s" %s' % (config['slot'],r['key'])
            if not apply:return {'dry_run':True,'device':r['device'],'slot':config['slot']}
            if keys_file is None:raise ValueError('authorized_keys path required')
            target=Path(keys_file)
            if target.is_symlink() or not target.is_file():raise ValueError('authorized_keys must be a regular file')
            old=target.read_text()
            rows=old.splitlines(keepends=True)
            if sum(1 for line in rows if line.rstrip('\n')==auth)!=1:raise ValueError('device SSH authorization not found exactly once')
            stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
            backup=Path(str(target)+'.backup-'+stamp)
            shutil.copy2(target,backup)
            info=target.stat()
            fd,tmp=tempfile.mkstemp(prefix='.hermes-revoke-',dir=str(target.parent))
            try:
                if hasattr(os,'fchmod'):os.fchmod(fd,0o600)
                if hasattr(os,'fchown'):os.fchown(fd,info.st_uid,info.st_gid)
                with os.fdopen(fd,'w') as out:
                    out.writelines(line for line in rows if line.rstrip('\n')!=auth)
                os.replace(tmp,target)
            finally:
                if os.path.exists(tmp):os.unlink(tmp)
            try:
                if terminal_status not in ('revoked','revoking'):raise ValueError('invalid revoke state')
                d.execute('UPDATE requests SET status=? WHERE ticket=? AND status="approved"',(terminal_status,ticket))
                self.audit(d,'revoked' if terminal_status=='revoked' else 'revoking',r,actor='device-ticket' if terminal_status=='revoking' else 'operator')
                d.commit()
            except Exception:
                shutil.copy2(backup,target)
                raise
            audit_event('revoked' if terminal_status=='revoked' else 'revoking',ticket,r['device'],config['slot'])
            return {'dry_run':False,'device':r['device'],'slot':config['slot'],'backup':str(backup)}

    def finish_revocation(self,ticket,close_slot):
        with self.db() as d:
            row=d.execute('SELECT * FROM requests WHERE ticket=? AND status="revoking"',(ticket,)).fetchone()
        if row is None:raise ValueError('not a revoking request')
        if not close_slot(row['slot']):return False
        with self.db() as d:
            d.execute('UPDATE requests SET status="revoked" WHERE ticket=? AND status="revoking"',(ticket,))
            self.audit(d,'revoked',row,actor='gate')
        audit_event('revoked',ticket,row['device'],row['slot'])
        return True


    def reap_expired(self,keys_file,close_slot):
        """Retry unfinished revocations and expire approved leases; never free live ports."""
        with self.db() as d:
            rows=d.execute('SELECT ticket,status FROM requests WHERE status="revoking" OR (status="approved" AND expires_at IS NOT NULL AND expires_at<=?)', (int(time.time()),)).fetchall()
        summary={'checked':len(rows),'revoked':0,'retry_needed':0}
        for row in rows:
            try:
                if row['status']=='approved':
                    self.revoke(row['ticket'],True,keys_file,terminal_status='revoking')
                if self.finish_revocation(row['ticket'],close_slot):summary['revoked']+=1
                else:summary['retry_needed']+=1
            except (OSError,RuntimeError,ValueError,sqlite3.Error) as ex:
                summary['retry_needed']+=1
                print(json.dumps({'event':'gate_reaper','error_type':type(ex).__name__}),file=sys.stderr,flush=True)
        return summary

def close_reverse_session(slot,timeout_seconds=5):
    """Close only one verified MOS sshd child, not the Gate master or another user."""
    from session_guard import tcp_listeners,terminate_scoped_session
    if not isinstance(slot,int) or not 23000<=slot<=24999:raise ValueError('invalid slot')
    if slot not in tcp_listeners():return True
    result=terminate_scoped_session(slot,expected_uid=os.getuid())
    if not result['safe']:raise RuntimeError('cannot safely close reverse tunnel: '+result['reason'])
    until=time.monotonic()+timeout_seconds
    while time.monotonic()<until:
        if slot not in tcp_listeners():return True
        time.sleep(.1)
    return slot not in tcp_listeners()

def handler(db,keys_file=Path('/var/lib/hermes-bridge/.ssh/authorized_keys'),close_slot=close_reverse_session):
    class Handler(BaseHTTPRequestHandler):
        def send(self,code,data):
            b=json.dumps(data).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
        def do_POST(self):
            if self.path=='/v1/enroll/revoke':
                try:
                    size=int(self.headers.get('Content-Length','0'))
                    if not 0<size<=256:return self.send(413,{'error':'size'})
                    obj=json.loads(self.rfile.read(size))
                    ticket=obj.get('ticket')
                    if not isinstance(ticket,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{40,60}',ticket):return self.send(400,{'error':'invalid'})
                    # A 256-bit ticket is a bearer capability: can revoke only its own access.
                    # An absent/already-revoked ticket is idempotently harmless.
                    with db.db() as conn:
                        row=conn.execute('SELECT status FROM requests WHERE ticket=?',(ticket,)).fetchone()
                    if row is None:return self.send(404,{'error':'not found'})
                    if row['status']=='approved':
                        db.revoke(ticket,apply=True,keys_file=keys_file,terminal_status='revoking')
                    if row['status'] in ('approved','revoking'):
                        if not db.finish_revocation(ticket,close_slot):
                            return self.send(503,{'status':'revoking','error':'reverse tunnel still active'})
                    elif row['status']=='pending':
                        with db.db() as conn:conn.execute("UPDATE requests SET status='revoked' WHERE ticket=? AND status='pending'",(ticket,))
                    return self.send(200,{'status':'revoked'})
                except (ValueError,KeyError,TypeError):return self.send(400,{'error':'invalid'})
                except Exception:return self.send(503,{'error':'revocation temporarily unavailable'})
            if self.path!='/v1/enroll':return self.send(404,{'error':'not found'})
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=4096:return self.send(413,{'error':'size'})
                obj=json.loads(self.rfile.read(size));ticket=db.submit(obj['device'],obj['public_key'])
                self.send(202,{'ticket':ticket,'status':'pending','code':db.code_for(ticket)})
            except OverflowError:self.send(429,{'error':'too many requests'})
            except (ValueError,KeyError,TypeError):self.send(400,{'error':'invalid device key'})
        def do_GET(self):
            if not self.path.startswith('/v1/enroll/'):return self.send(404,{'error':'not found'})
            result=db.poll(self.path[len('/v1/enroll/'):]);self.send(200 if result['status']!='not_found' else 404,result)
        def log_message(self,*args):pass
    return Handler

def main():
    p=argparse.ArgumentParser();p.add_argument('--db',type=Path,required=True);sub=p.add_subparsers(dest='action',required=True)
    sub.add_parser('serve');sub.add_parser('pending')
    pf=sub.add_parser('preflight',help='Read-only MOS lookup and duplicate-key grant diagnostics');pf.add_argument('--code',required=True)
    reglist=sub.add_parser('devices')
    regadd=sub.add_parser('register-device');regadd.add_argument('--alias',required=True);regadd.add_argument('--platform',choices=['windows','openwrt'],required=True);regadd.add_argument('--ticket',required=True)
    regresolve=sub.add_parser('resolve-device');regresolve.add_argument('--alias',required=True)
    regdisable=sub.add_parser('disable-device');regdisable.add_argument('--alias',required=True)
    regenable=sub.add_parser('enable-device');regenable.add_argument('--alias',required=True)
    doctor=sub.add_parser('doctor');doctor.add_argument('--keys-file',type=Path,default=Path('/var/lib/hermes-bridge/.ssh/authorized_keys'));sub.add_parser('events')
    ap=sub.add_parser('approve');ap.add_argument('--ticket',required=True);ap.add_argument('--code',required=True,help='Four-character code shown in Connector (legacy five-character tickets accepted)');ap.add_argument('--slot',type=lambda v:None if v=='auto' else int(v),default=None,help='Reverse port 23000-24999, or auto (default)');ap.add_argument('--host',required=True);ap.add_argument('--hostkey',required=True);ap.add_argument('--apply',action='store_true');ap.add_argument('--ttl-seconds',type=int,default=7200,help='Approved lease duration, default 7200 seconds (0=unlimited, explicit exception only)');ap.add_argument('--keys-file',type=Path,default=Path('/var/lib/hermes-bridge/.ssh/authorized_keys'))
    rp=sub.add_parser('revoke');rp.add_argument('--ticket',required=True);rp.add_argument('--apply',action='store_true');rp.add_argument('--keys-file',type=Path,default=Path('/var/lib/hermes-bridge/.ssh/authorized_keys'))
    hp=sub.add_parser('replace-stale',help='Explicitly authorized same-key handover; refuses live reverse session');hp.add_argument('--old-ticket',required=True);hp.add_argument('--ticket',required=True);hp.add_argument('--code',required=True);hp.add_argument('--host',required=True);hp.add_argument('--hostkey',required=True);hp.add_argument('--slot',type=lambda v:None if v=='auto' else int(v),default=None);hp.add_argument('--ttl-seconds',type=int,default=7200);hp.add_argument('--keys-file',type=Path,default=Path('/var/lib/hermes-bridge/.ssh/authorized_keys'));hp.add_argument('--apply',action='store_true')
    a=p.parse_args();db=Enrollment(a.db)
    if a.action in ('devices','register-device','resolve-device','disable-device','enable-device'):
        from registry import DeviceRegistry
        reg=DeviceRegistry(a.db)
        if a.action=='devices':result=reg.list()
        elif a.action=='register-device':
            with db.db() as conn:
                row=conn.execute("SELECT device,key,status FROM requests WHERE ticket=?",(a.ticket,)).fetchone()
            if row is None or row['status'] not in ('approved','revoked','revoking'):raise ValueError('register only a previously verified device; never trust a pending request alone')
            result=reg.add(a.alias,a.platform,row['device'],row['key'])
        elif a.action=='resolve-device':result=reg.lookup_live(a.alias)
        else:
            reg.set_enabled(a.alias,a.action=='enable-device');result={'alias':a.alias,'enabled':a.action=='enable-device'}
        print(json.dumps(result,ensure_ascii=False,indent=2))
    elif a.action=='serve':
        import threading
        def reaper():
            while True:
                try:db.reap_expired(Path('/var/lib/hermes-bridge/.ssh/authorized_keys'),close_reverse_session)
                except Exception as ex:
                    print(json.dumps({'event':'gate_reaper','error_type':type(ex).__name__}),file=sys.stderr,flush=True)
                time.sleep(15)
        threading.Thread(target=reaper,daemon=True,name='mos-session-reaper').start()
        ThreadingHTTPServer(('127.0.0.1',18511),handler(db)).serve_forever()
    elif a.action=='events':print(json.dumps(db.recent_events(),indent=2))
    elif a.action=='doctor':print(json.dumps(db.doctor(a.keys_file),ensure_ascii=False))
    elif a.action=='preflight':print(json.dumps(db.preflight(a.code),ensure_ascii=False))
    elif a.action=='pending':
        with db.db() as conn:print(json.dumps([dict(r) for r in conn.execute("SELECT ticket,device,key,created,code FROM requests WHERE status='pending' AND last_seen>?",(int(time.time())-900,))]))
    elif a.action=='approve':print(json.dumps(db.approve(a.ticket,a.slot,a.host,a.hostkey,a.apply,a.keys_file,code=a.code,approval_ttl_seconds=a.ttl_seconds),indent=2))
    elif a.action=='replace-stale':print(json.dumps(db.replace_stale(a.old_ticket,a.ticket,a.code,a.host,a.hostkey,a.keys_file,slot=a.slot,apply=a.apply,ttl_seconds=a.ttl_seconds),indent=2))
    elif a.action=='revoke':
        if not a.apply:
            print(json.dumps(db.revoke(a.ticket,False,a.keys_file),indent=2))
        else:
            with db.db() as conn:
                request=conn.execute('SELECT status FROM requests WHERE ticket=?',(a.ticket,)).fetchone()
            if request is None or request['status'] not in ('approved','revoking'):
                raise ValueError('ticket is not an approved or revoking request')
            if request['status']=='approved':
                db.revoke(a.ticket,True,a.keys_file,terminal_status='revoking')
            if not db.finish_revocation(a.ticket,close_reverse_session):
                print(json.dumps({'status':'revoking','error':'session remains open'}))
                sys.exit(3)
            print(json.dumps({'status':'revoked','verified_closed':True}))
if __name__=='__main__':main()
