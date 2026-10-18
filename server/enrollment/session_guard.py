#!/usr/bin/env python3
"""Fail-closed target identification for closing one MOS reverse SSH listener.

Read-only by default. No shell execution, no remote invocation, no broad sshd kills.
Production kill integration intentionally requires separate privilege review.
"""
import argparse
import os
import pathlib
import re
import signal

MIN_PORT, MAX_PORT = 23000, 24999


def tcp_listeners(proc=pathlib.Path('/proc')):
    """Linux /proc/net/tcp local port -> socket inode for loopback LISTEN sockets."""
    matches={}
    for proto in ('tcp','tcp6'):
        source=proc/'net'/proto
        if not source.exists():continue
        for line in source.read_text().splitlines()[1:]:
            fields=line.split()
            if len(fields)<10 or fields[3]!='0A':continue
            address, port_hex=fields[1].split(':')
            port=int(port_hex,16)
            if port not in range(MIN_PORT,MAX_PORT+1):continue
            # Do not act on all-interface or external listener addresses.
            if proto=='tcp' and address!='0100007F':continue
            if proto=='tcp6' and address.upper()!='00000000000000000000000001000000':continue
            matches.setdefault(port,set()).add(fields[9])
    return matches


def listener_owners(port,proc=pathlib.Path('/proc')):
    if not MIN_PORT<=port<=MAX_PORT:raise ValueError('not a MOS reverse port')
    inodes=tcp_listeners(proc).get(port,set())
    if not inodes:return []
    owners=[]
    for node in proc.iterdir():
        if not node.name.isdecimal():continue
        fd=node/'fd'
        try:
            for entry in fd.iterdir():
                try: target=os.readlink(entry)
                except (OSError,PermissionError):continue
                if target.startswith('socket:[') and target[8:-1] in inodes:
                    owners.append(int(node.name));break
        except (OSError,PermissionError):continue
    return sorted(set(owners))


def inspected_target(port,proc=pathlib.Path('/proc'),main_pid=None,expected_uid=None):
    """Identify exactly one owned sshd child, rejecting ambiguity and master processes.

    This is only a candidate report. Revalidation of PID starttime and process identity
    is mandatory immediately before signaling; this module does NOT issue a signal.
    """
    pids=listener_owners(port,proc)
    if len(pids)!=1:return {'safe':False,'reason':'ambiguous_or_missing_listener','pids':pids}
    pid=pids[0]
    if pid==main_pid:return {'safe':False,'reason':'master_sshd_pid','pids':pids}
    node=proc/str(pid)
    try:
        status=(node/'status').read_text()
        real_uid=int(re.search(r'^Uid:\s*(\d+)',status,re.M).group(1))
        cmdline=(node/'cmdline').read_bytes().replace(b'\0',b' ').decode('utf-8','replace')
        cgroup=(node/'cgroup').read_text()
        exe=os.readlink(node/'exe')
        stat=(node/'stat').read_text()
        # proc stat field 22: process starttime, parenthesized comm can have spaces.
        starttime=stat[stat.rfind(')')+2:].split()[19]
    except (OSError,ValueError,AttributeError,IndexError):
        return {'safe':False,'reason':'cannot_verify_process','pids':pids}
    if expected_uid is None or real_uid!=expected_uid:
        return {'safe':False,'reason':'uid_mismatch','pids':pids}
    if not pathlib.Path(exe).name.startswith('sshd'):
        return {'safe':False,'reason':'not_sshd','pids':pids}
    if 'hermes-bridge-sshd.service' not in cgroup:
        return {'safe':False,'reason':'wrong_cgroup','pids':pids}
    if not re.search(r'sshd: hermes-bridge\b',cmdline):
        return {'safe':False,'reason':'not_authenticated_device_sshd','pids':pids}
    # One SSH process may own multiple reverse ports: terminating it would disrupt
    # another device. Refuse such a candidate, even if the requested port is valid.
    all_listeners=tcp_listeners(proc)
    for other_port in all_listeners:
        if other_port!=port and pid in listener_owners(other_port,proc):
            return {'safe':False,'reason':'shared_sshd_process','pids':pids}
    return {'safe':True,'pid':pid,'starttime':starttime,'port':port}


def terminate_scoped_session(port,proc=pathlib.Path('/proc'),main_pid=None,expected_uid=None,
                             open_pidfd=None,send_pidfd=None):
    """Terminate exactly one verified sshd session using Linux race-safe pidfd.

    Never fall back to kill(pid): the process ID could be reused after inspection.
    Production integration is subject to separate approval and full E2E tests.
    """
    if open_pidfd is None:open_pidfd=os.pidfd_open
    if send_pidfd is None:send_pidfd=signal.pidfd_send_signal
    previous=inspected_target(port,proc,main_pid,expected_uid)
    if not previous['safe']:return previous
    fd=open_pidfd(previous['pid'])
    try:
        current=inspected_target(port,proc,main_pid,expected_uid)
        if not current['safe'] or current['pid']!=previous['pid'] or current['starttime']!=previous['starttime']:
            return {'safe':False,'reason':'process_changed_during_validation'}
        send_pidfd(fd,signal.SIGTERM,None,0)
        return {'safe':True,'pid':previous['pid'],'signal':'SIGTERM'}
    finally:
        os.close(fd)


def main():
    parser=argparse.ArgumentParser(description='Read-only MOS per-session listener guard')
    parser.add_argument('--port',type=int,required=True)
    parser.add_argument('--expected-uid',type=int,required=True)
    parser.add_argument('--master-pid',type=int,required=True)
    args=parser.parse_args()
    print(inspected_target(args.port,main_pid=args.master_pid,expected_uid=args.expected_uid))


if __name__=='__main__':main()
