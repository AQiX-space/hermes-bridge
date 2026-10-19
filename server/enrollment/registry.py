"""Named trusted-device inventory for MOS. Registry is NOT an authorization bypass."""
import hashlib
import re
import sqlite3
import time

ALIAS_RE=re.compile(r'^[A-Za-z][A-Za-z0-9_-]{1,47}$')
PLATFORMS=('windows','openwrt')

class DeviceRegistry:
    def __init__(self, path):
        self.path=str(path)
        with self.db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS registered_devices (
                alias TEXT PRIMARY KEY COLLATE NOCASE,
                platform TEXT NOT NULL CHECK(platform IN ('windows','openwrt')),
                device_key_hash TEXT NOT NULL UNIQUE,
                device_label TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1))
            )''')
    def db(self):
        return sqlite3.connect(self.path,timeout=15)
    @staticmethod
    def fingerprint(key):
        if not isinstance(key,str) or not key.startswith('ssh-ed25519 '):raise ValueError('invalid device key')
        return hashlib.sha256(key.encode('ascii')).hexdigest()
    def add(self,alias,platform,device,key):
        if not isinstance(alias,str) or not ALIAS_RE.fullmatch(alias):raise ValueError('invalid alias')
        if platform not in PLATFORMS:raise ValueError('unsupported platform')
        if not isinstance(device,str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}',device):raise ValueError('invalid device name')
        fingerprint=self.fingerprint(key)
        with self.db() as db:
            trusted=db.execute("SELECT 1 FROM requests WHERE key=? AND status IN ('approved','revoked','revoking') LIMIT 1",(key,)).fetchone()
            if trusted is None:raise ValueError('device must complete a verified enrollment first')
            db.execute('INSERT INTO registered_devices(alias,platform,device_key_hash,device_label,created_at) VALUES(?,?,?,?,?)',
                       (alias,platform,fingerprint,device,int(time.time())))
        return {'alias':alias,'platform':platform,'device':device,'fingerprint':fingerprint}
    def list(self):
        with self.db() as db:
            db.row_factory=sqlite3.Row
            return [dict(row) for row in db.execute('SELECT alias,platform,device_label AS device,device_key_hash AS fingerprint,enabled FROM registered_devices ORDER BY alias COLLATE NOCASE')]
    def set_enabled(self,alias,enabled):
        with self.db() as db:
            result=db.execute('UPDATE registered_devices SET enabled=? WHERE alias=?',(1 if enabled else 0,alias))
            if result.rowcount!=1:raise ValueError('unknown device alias')
    def lookup_live(self,alias):
        """Resolve by pinned key against live DB state, never return a bearer ticket."""
        with self.db() as db:
            db.row_factory=sqlite3.Row
            item=db.execute('SELECT * FROM registered_devices WHERE alias=?',(alias,)).fetchone()
            if item is None:raise ValueError('unknown alias')
            if not item['enabled']:raise ValueError('device disabled')
            rows=db.execute("SELECT device,key,status,slot,last_seen,expires_at FROM requests WHERE status IN ('approved','pending','revoking') ORDER BY created DESC").fetchall()
            matches=[r for r in rows if self.fingerprint(r['key'])==item['device_key_hash']]
            active=[r for r in matches if r['status']=='approved' and (r['expires_at'] is None or r['expires_at']>int(time.time()))]
            # Never silently select among multiple authorizations for a registered device.
            if len(active)>1:raise ValueError('ambiguous active sessions')
            if active:
                r=active[0]
                return {'alias':item['alias'],'platform':item['platform'],'device':r['device'],'status':'approved','slot':r['slot']}
            if any(r['status']=='revoking' for r in matches):status='revoking'
            elif any(r['status']=='pending' and r['last_seen'] and r['last_seen']>time.time()-900 for r in matches):status='pending'
            else:status='offline'
            return {'alias':item['alias'],'platform':item['platform'],'device':item['device_label'],'status':status,'slot':None}
