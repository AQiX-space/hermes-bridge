"""Operator-to-agent auth over loopback, test-only mock with real broker SQLite rows."""
import base64,hashlib,hmac,importlib.util,json,os,socketserver,sqlite3,tempfile,threading,time,unittest
from pathlib import Path
from contextlib import closing
spec=importlib.util.spec_from_file_location('operator',Path(__file__).resolve().parents[1]/'ops'/'hermes-user-command.py')
operator=importlib.util.module_from_spec(spec);spec.loader.exec_module(operator)
class Protocol(socketserver.BaseRequestHandler):
    def handle(self):
        data=b''
        while not data.endswith(b'\n'):
            item=self.request.recv(2048)
            if not item:return
            data+=item
            if len(data)>16000:return
        request=json.loads(data)
        self.server.seen=request
        payload=f'{request["ts"]}\n{request["nonce"]}\n{request["script"]}'.encode()
        expected=hmac.new(hashlib.sha256(('Hermes user-agent HMAC v1\n'+self.server.ticket).encode()).digest(),payload,hashlib.sha256).digest()
        if not hmac.compare_digest(expected,base64.b64decode(request['mac'])):return
        response={'ok':True,'user':'TEST-WINDOWS\\Alex','exit_code':0,'stdout':'TEST-WINDOWS\\Alex\n','stderr':'','error':None}
        self.request.sendall(json.dumps(response).encode()+b'\n')
class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.database=str(Path(self.temp.name)/'broker.sqlite3')
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('CREATE TABLE requests(ticket TEXT,device TEXT,status TEXT,slot INTEGER,expires_at INTEGER)')
            db.commit()
        self.listener=None
    def tearDown(self):
        if self.listener:
            self.listener.shutdown();self.listener.server_close()
        self.temp.cleanup()
    def add(self,ticket,slot,status='approved',expires=3600):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('INSERT INTO requests VALUES (?,?,?,?,?)',(ticket,'ALEXHUB',status,slot,int(time.time()+expires)))
            db.commit()
    def test_approved_request_signed_and_sent(self):
        self.listener=socketserver.TCPServer(('127.0.0.1',0),Protocol)
        slot=self.listener.server_address[1]
        if not (23000<=slot<=24999):
            # Use a test-only relay to avoid relying on OS ephemeral allocation range.
            self.listener.server_close()
            for port in range(23200,23300):
                try:self.listener=socketserver.TCPServer(('127.0.0.1',port),Protocol);break
                except OSError:continue
            slot=self.listener.server_address[1]
        self.listener.ticket='safely-test-ticket-not-a-real-grant-0123456789'
        self.add(self.listener.ticket,slot)
        worker=threading.Thread(target=self.listener.serve_forever,daemon=True);worker.start()
        result=operator.execute(self.database,slot,'whoami')
        self.assertEqual(result['user'],'TEST-WINDOWS\\Alex')
        self.assertEqual(self.listener.seen['script'],'whoami')
        self.assertNotIn('ticket',self.listener.seen)
    def test_denies_expired_or_nonunique(self):
        self.add('other-test-ticket-111111111111111111111111',23044,expires=-1)
        with self.assertRaises(ValueError):operator.execute(self.database,23044,'whoami')
        self.add('test-ticket-222222222222222222222222',23045)
        self.add('test-ticket-333333333333333333333333',23045)
        with self.assertRaises(ValueError):operator.execute(self.database,23045,'whoami')
    def test_denies_invalid_port(self):
        with self.assertRaises(ValueError):operator.execute(self.database,22,'whoami')
if __name__=='__main__':unittest.main()
