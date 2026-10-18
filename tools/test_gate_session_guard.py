import os
import pathlib
import tempfile
from gate_session_guard import inspected_target, listener_owners, tcp_listeners

PORT=23021

def setup(root,addr='0100007F',pid='1802',cmd='sshd: hermes-bridge@notty',uid=1507,service='hermes-bridge-sshd.service'):
    net=root/'net';net.mkdir(exist_ok=True)
    (net/'tcp').write_text('sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'+
        '0: '+addr+':'+format(PORT,'04X')+' 00000000:0000 0A 0 0 0 0 0 77891\n')
    node=root/pid;node.mkdir(exist_ok=True);(node/'fd').mkdir(exist_ok=True)
    (node/'fd'/'5').symlink_to('socket:[77891]')
    (node/'status').write_text('Name:\tsshd\nUid:\t'+str(uid)+' '+str(uid)+' '+str(uid)+' '+str(uid)+'\n')
    (node/'cmdline').write_bytes(cmd.encode()+b'\0')
    (node/'cgroup').write_text('0::/system.slice/'+service+'\n')
    (node/'exe').symlink_to('/usr/sbin/sshd')
    (node/'stat').write_text(pid+' (sshd) S '+' '.join('1' for _ in range(18))+' 999 0 0\n')
    return node

with tempfile.TemporaryDirectory() as d:
    r=pathlib.Path(d);setup(r)
    assert tcp_listeners(r)[PORT]=={'77891'}
    assert listener_owners(PORT,r)==[1802]
    good=inspected_target(PORT,r,main_pid=1200,expected_uid=1507)
    assert good['safe'] and good['pid']==1802 and good['starttime']=='999',good
    assert not inspected_target(PORT,r,main_pid=1802,expected_uid=1507)['safe']
    assert inspected_target(PORT,r,main_pid=1200,expected_uid=1000)['reason']=='uid_mismatch'
    (r/'1802'/'cgroup').write_text('0::/system.slice/sshd.service\n')
    assert inspected_target(PORT,r,main_pid=1200,expected_uid=1507)['reason']=='wrong_cgroup'
    (r/'1802'/'cgroup').write_text('0::/system.slice/hermes-bridge-sshd.service\n')
    (r/'1802'/'cmdline').write_bytes(b'sshd: root@pts/0\0')
    assert inspected_target(PORT,r,main_pid=1200,expected_uid=1507)['reason']=='not_authenticated_device_sshd'
with tempfile.TemporaryDirectory() as d:
    r=pathlib.Path(d);setup(r,addr='00000000')
    assert inspected_target(PORT,r,main_pid=1200,expected_uid=1507)['reason']=='ambiguous_or_missing_listener'
with tempfile.TemporaryDirectory() as d:
    r=pathlib.Path(d);setup(r)
    node=setup(r,pid='1803') if False else None
    other=r/'1803';other.mkdir();(other/'fd').mkdir();(other/'fd'/'3').symlink_to('socket:[77891]')
    assert inspected_target(PORT,r,main_pid=1200,expected_uid=1507)['reason']=='ambiguous_or_missing_listener'
print('PASS gate session identification: one scoped sshd only, fail closed on master/wrong-user/foreign listener/ambiguity')
