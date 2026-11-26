"""Unit tests for the socket-activated root helper privilege boundary."""
import importlib.util
from pathlib import Path
from unittest.mock import Mock

path=Path(__file__).with_name('close_scoped_socket.py')
spec=importlib.util.spec_from_file_location('root_helper',path)
h=importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


class HelperTests:
    def test(self):
        uid,pid=1321,4389
        valid=lambda _pid:'0::/system.slice/hermes-enrollment.service\n'
        refused=lambda _pid:'0::/system.slice/other.service\n'
        terminator=Mock(return_value={'safe':True,'pid':99999})
        assert h.execute(b'23000\n',uid,pid,uid,valid,terminator)['safe']
        terminator.assert_called_once_with(23000,expected_uid=uid)
        for text in (b'', b'22\n', b'24999 BAD\n', b'23000;rm\n', b'-23000\n',
                     b'23000\nextra', b'25000\n', b'23000\x00', b'\n', b'23000'):
            terminator.reset_mock()
            result=h.execute(text,uid,pid,uid,valid,terminator)
            assert result['safe'] is False,(text,result)
            terminator.assert_not_called()
        for peer in ((uid+1,pid,valid),(uid,pid,refused),(uid,0,valid)):
            terminator.reset_mock()
            assert not h.execute(b'23000\n',peer[0],peer[1],uid,peer[2],terminator)['safe']
            terminator.assert_not_called()
        terminator.return_value={'safe':False,'reason':'foreign_listener'}
        assert not h.execute(b'23000\n',uid,pid,uid,valid,terminator)['safe']
        print('PASS: socket peer UID, broker cgroup, port and foreign listener fail closed')


if __name__=='__main__':
    HelperTests().test()
