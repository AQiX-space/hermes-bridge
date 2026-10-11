import base64, pathlib, subprocess, sys, tempfile
with tempfile.TemporaryDirectory() as temp:
 d=pathlib.Path(temp); blob=bytes([0,0,0,11])+b'ssh-ed25519'+bytes([0,0,0,32])+bytes(range(32))
 k='ssh-ed25519 '+base64.b64encode(blob).decode()
 (d/'device.pub').write_text(k+' device');(d/'host.pub').write_text(k+' host')
 cmd=[sys.executable,str(pathlib.Path(__file__).with_name('enroll.py')),'--device','test1','--host','bridge.example.com','--port','22471','--slot','22473','--public-key-file',str(d/'device.pub'),'--gateway-host-key-file',str(d/'host.pub'),'--output-dir',str(d/'out')]
 q=subprocess.run(cmd,capture_output=True,text=True,check=True)
 assert 'permitlisten="127.0.0.1:22473"' in q.stdout
 assert 'host=bridge.example.com' in (d/'out'/'test1.bridge').read_text()
 bad=subprocess.run(cmd,capture_output=True,text=True)
 assert bad.returncode!=0
print('PASS enrollment file, permitlisten restriction, overwrite guard')
