#!/usr/bin/env python3
"""Operator's read-only session lookup + signed RPC; run only on approved Gate.
Requires SELECT permission to broker SQLite DB. Never outputs bearer ticket.
"""
import argparse,base64,hashlib,hmac,json,socket,sqlite3,time,uuid

def execute(database,slot,script):
    if not 23000<=slot<=24999:raise ValueError('invalid MOS port')
    if not 1<=len(script)<=4096:raise ValueError('invalid command size')
    with sqlite3.connect('file:'+database+'?mode=ro',uri=True) as db:
        db.row_factory=sqlite3.Row
        rows=db.execute("SELECT ticket,device,status,expires_at FROM requests WHERE slot=? AND status='approved'",(slot,)).fetchall()
    if len(rows)!=1:raise ValueError('MOS slot not uniquely approved')
    row=rows[0]
    if row['expires_at'] is not None and row['expires_at']<=time.time():raise ValueError('MOS approval has expired')
    ticket=row['ticket']
    nonce=uuid.uuid4().hex;ts=int(time.time())
    key=hashlib.sha256(('Hermes user-agent HMAC v1\n'+ticket).encode()).digest()
    mac=base64.b64encode(hmac.new(key,f'{ts}\n{nonce}\n{script}'.encode(),hashlib.sha256).digest()).decode()
    message=json.dumps({'ts':ts,'nonce':nonce,'script':script,'mac':mac},ensure_ascii=True,separators=(',',':')).encode()+b'\n'
    with socket.create_connection(('127.0.0.1',slot),timeout=5) as connection:
        connection.settimeout(38)
        connection.sendall(message)
        with connection.makefile('rb') as stream:
            response=stream.readline(130000)
    if not response.endswith(b'\n'):raise RuntimeError('incomplete agent response')
    result=json.loads(response)
    # Ticket and HMAC are never printed, stored in audit or forwarded to GUI.
    return {k:result.get(k) for k in ('ok','user','exit_code','stdout','stderr','error')}

if __name__=='__main__':
    p=argparse.ArgumentParser(description='Hermes current-user agent command')
    p.add_argument('--db',default='/var/lib/hermes-enrollment/requests.sqlite3')
    p.add_argument('--slot',required=True,type=int)
    p.add_argument('--script',required=True)
    a=p.parse_args()
    print(json.dumps(execute(a.db,a.slot,a.script),ensure_ascii=False))
