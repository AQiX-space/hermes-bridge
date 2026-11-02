import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from types import SimpleNamespace

PATH = pathlib.Path(__file__).resolve().parents[1] / 'tools/mos_operator.py'
spec = importlib.util.spec_from_file_location('mos_operator', PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class OperatorAuthTests(unittest.TestCase):
    def test_missing_private_key_is_hard_failure(self):
        with tempfile.TemporaryDirectory() as root:
            base=pathlib.Path(root)
            with self.assertRaises(FileNotFoundError):
                mod.diagnostic('de2.nod.aqixnet.com',23003,'Revizor',base/'no-key',base/'audit')
    def test_ssh_denied_cannot_be_reported_connected(self):
        with tempfile.TemporaryDirectory() as root:
            base=pathlib.Path(root)
            key=base/'id_ed25519';key.write_text('placeholder; not used by stub')
            seen=[]
            def reject(command,**kwargs):
                seen.append(command)
                return SimpleNamespace(stdout=b'',stderr=b'Permission denied (publickey).',returncode=255)
            with self.assertRaisesRegex(RuntimeError,'diagnostic failed'):
                mod.diagnostic('de2.nod.aqixnet.com',23003,'Revizor',key,base/'audit',runner=reject)
            self.assertIn('IdentitiesOnly=yes',seen[0])
            self.assertIn('BatchMode=yes',seen[0])
            self.assertIn('remote_error',(base/'audit').read_text())
            self.assertNotIn('Permission denied',(base/'audit').read_text())
    def test_success_requires_ssh_exit_zero(self):
        with tempfile.TemporaryDirectory() as root:
            base=pathlib.Path(root)
            key=base/'key';key.write_text('placeholder')
            def succeed(command,**kwargs):
                return SimpleNamespace(stdout=b'COMPUTER=MINIKO\nUSER=Revizor\n',stderr=b'',returncode=0)
            out=mod.diagnostic('de2.nod.aqixnet.com',23003,'Revizor',key,base/'audit',runner=succeed)
            self.assertIn(b'MINIKO',out)
            self.assertIn('success',(base/'audit').read_text())
if __name__=='__main__':unittest.main()
