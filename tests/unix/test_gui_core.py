"""GUI helpers and persistent privacy tests; no display needed."""
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]/'clients'/'unix'))
try:
    import gui
except ImportError:
    gui = None  # Basic headless runner may omit Tk; CI builds must install it.


@unittest.skipUnless(gui is not None, 'Tkinter not installed on this Python')
class GUIHelpersTests(unittest.TestCase):
    def test_no_secret_code_in_disk_journal(self):
        with tempfile.TemporaryDirectory() as folder:
            journal = gui.Journal(pathlib.Path(folder)/'activity.log')
            journal.append('Код МОСТ: De49; password=private api_key=secret')
            journal.append('gr2.touch01.top подключён')
            text = journal.tail()
            self.assertNotIn('De49', text)
            self.assertNotIn('private', text)
            self.assertNotIn('api_key=secret', text)
            self.assertIn('gr2.touch01.top', text)
            self.assertEqual(journal.path.stat().st_mode & 0o077, 0)

    def test_bounded_journal_after_many_reconnects(self):
        with tempfile.TemporaryDirectory() as folder:
            journal = gui.Journal(pathlib.Path(folder)/'activity.log')
            for i in range(6000):
                journal.append('Reconnect '+str(i)+' '+('x'*120))
            self.assertLessEqual(journal.path.stat().st_size, 512*1024)
            self.assertIn('Reconnect 5999', journal.tail(1500))

    def test_gui_child_calls_same_native_connector(self):
        args = gui.cli_args('connect','--mode','support','--gateway','gr2')
        self.assertEqual(args[-5:], ['connect','--mode','support','--gateway','gr2'])
        self.assertNotIn('sudo', args)


if __name__ == '__main__':
    unittest.main()
