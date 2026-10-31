import importlib.util
import pathlib
import unittest
p=pathlib.Path(__file__).resolve().parents[1]/'ops/bridge_fast_approve.py'
spec=importlib.util.spec_from_file_location('bridge_fast_approve',p)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class CodeTests(unittest.TestCase):
 def test_display_hyphen(self): self.assertEqual(m.normalize('AJ-51'),'AJ51')
 def test_case(self): self.assertEqual(m.normalize('Zr55'),'Zr55')
 def test_reject_shell_and_long_code(self):
  for bad in ('$(id)','ABCDEF','ABC 1',''):
   with self.assertRaises(ValueError): m.normalize(bad)
if __name__=='__main__': unittest.main()
