#!/usr/bin/env python3
import os
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest
import uuid
from mos_operator import diagnostic,validate

class OperatorTests(unittest.TestCase):
 def test_invalid_inputs_are_rejected(self):
  for host,port,user in [('bad host',23001,'Alex'),('gate.example',22,'Alex'),('gate.example',23001,'admin;evil')]:
   with self.assertRaises(ValueError):validate(host,port,user)
 def test_transport_is_via_gateway_and_audits_no_secrets(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);key=root/'identity';key.write_text('secret-for-test')
   output=b'COMPUTER=HOST\r\nSECRET_SENSITIVE_OUTPUT_NOT_FOR_LOG\r\n'
   calls=[]
   def fake_run(cmd,**kwargs):
    calls.append(cmd);return subprocess.CompletedProcess(cmd,0,output,b'')
   path=root/'audit.jsonl'
   result=diagnostic('gate.example',23001,'Alex',key,path,runner=fake_run)
   self.assertEqual(result,output)
   self.assertEqual(calls[0][calls[0].index('-J')+1],'gate.example')
   self.assertIn('Alex@127.0.0.1',calls[0])
   rows=[json.loads(s) for s in path.read_text().splitlines()]
   self.assertEqual(len(rows),1)
   self.assertEqual(rows[0]['result'],'success')
   self.assertTrue(rows[0]['operator_os_user'])
   self.assertEqual(str(uuid.UUID(rows[0]['action_id'])),rows[0]['action_id'])
   self.assertEqual(rows[0]['stdout_sha256'],hashlib.sha256(output).hexdigest())
   self.assertNotIn('SECRET_SENSITIVE',path.read_text())
   self.assertNotIn('secret-for-test',path.read_text())
   if os.name!='nt':self.assertEqual(path.stat().st_mode & 0o777,0o600)
 def test_failure_is_logged_without_raw_output(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);key=root/'identity';key.write_text('test')
   def failing(cmd,**kwargs):return subprocess.CompletedProcess(cmd,255,b'',b'Denied ssh private metadata')
   path=root/'audit.jsonl'
   with self.assertRaises(RuntimeError):diagnostic('gate.example',23001,'Alex',key,path,runner=failing)
   self.assertEqual(json.loads(path.read_text())['result'],'remote_error')
   self.assertNotIn('Denied',path.read_text())
 def test_timeout_logged(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);key=root/'identity';key.write_text('test')
   def timeout(cmd,**kwargs):raise subprocess.TimeoutExpired(cmd,40)
   path=root/'audit.jsonl'
   with self.assertRaises(RuntimeError):diagnostic('gate.example',23001,'Alex',key,path,runner=timeout)
   self.assertEqual(json.loads(path.read_text())['result'],'timeout')

if __name__=='__main__':unittest.main()
