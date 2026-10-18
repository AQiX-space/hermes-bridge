#!/usr/bin/env python3
"""Audited and bounded MOS operator diagnostics over a pre-approved reverse tunnel.
No server credentials, passwords, or bearer tickets are stored by this tool.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

# Intentionally read-only. Broader administrative changes require a separately audited command.
DIAGNOSE = (
    "$ErrorActionPreference='Stop';"
    "Write-Output ('COMPUTER='+$env:COMPUTERNAME);"
    "Write-Output ('USER='+$env:USERNAME);"
    "$os=Get-CimInstance Win32_OperatingSystem;"
    "Write-Output ('OS='+$os.Caption);"
    "Write-Output ('OS_VERSION='+$os.Version);"
    "Write-Output ('RAM_GB='+[math]::Round($os.TotalVisibleMemorySize/1MB,1));"
    "Write-Output ('UPTIME_HOURS='+[math]::Round(((Get-Date)-$os.LastBootUpTime).TotalHours,1));"
    "$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1;"
    "Write-Output ('CPU='+$cpu.Name);"
    "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|ForEach-Object{"
    "Write-Output ('DISK='+$_.DeviceID+' FREE_GB='+[math]::Round($_.FreeSpace/1GB,1))};"
    "Write-Output ('SSHD='+((Get-Service sshd).Status))"
)

def validate(host, slot, user):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{2,252}',host):
        raise ValueError('invalid trusted gateway name')
    if not 23000 <= slot <= 24999:
        raise ValueError('reverse port must be in the MOS range')
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,64}',user):
        raise ValueError('invalid Windows SSH login')

def record(path, event):
    path=path.expanduser()
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    # 0600 even when the caller has an unusually permissive umask.
    fd=os.open(str(path),os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
    try:
        if hasattr(os,"fchmod"):os.fchmod(fd,0o600) # POSIX; on Windows parent ACL controls access
        with os.fdopen(fd,'a',encoding='utf-8') as out:
            out.write(json.dumps(event,ensure_ascii=False,sort_keys=True)+'\n')
    except Exception:
        try:os.close(fd)
        except OSError:pass
        raise

def diagnostic(host,slot,user,key,audit,timeout=40,runner=subprocess.run):
    validate(host,slot,user)
    if not key.is_file():raise FileNotFoundError('operator key not found')
    ps=base64.b64encode(DIAGNOSE.encode('utf-16le')).decode('ascii')
    cmd=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
         '-o','ConnectTimeout=10','-o','IdentitiesOnly=yes',
         '-i',str(key),'-J',host,'-p',str(slot),user+'@127.0.0.1',
         'powershell.exe -NoProfile -NonInteractive -EncodedCommand '+ps]
    started=datetime.datetime.now(datetime.timezone.utc).isoformat()
    outcome='transport_error';exit_code=None;stdout=b''
    try:
        result=runner(cmd,timeout=timeout,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        stdout=result.stdout;exit_code=result.returncode
        outcome='success' if exit_code==0 else 'remote_error'
    except subprocess.TimeoutExpired:
        outcome='timeout'
    finally:
        # Deliberately exclude raw command output, ticket, SSH key material and IP addresses.
        record(audit,{'time_utc':started,'action':'diagnose','gateway':host,
                      'slot':slot,'windows_user':user,'result':outcome,'exit_code':exit_code,
                      'stdout_sha256':hashlib.sha256(stdout).hexdigest() if stdout else None})
    if outcome!='success':raise RuntimeError('MOS diagnostic failed: '+outcome)
    return stdout

def main():
    p=argparse.ArgumentParser(description='Read-only MOS operator diagnostics via an approved reverse tunnel')
    p.add_argument('--gateway',required=True,help='Operator-approved gateway SSH name, never a public reverse port')
    p.add_argument('--port',type=int,required=True)
    p.add_argument('--user',required=True,help='Windows login with a separately authorized operator public key')
    p.add_argument('--identity',required=True,type=pathlib.Path,help='Existing operator SSH private key path')
    p.add_argument('--audit',type=pathlib.Path,default=pathlib.Path.home()/'.local/state/hermes-mos/operator.jsonl')
    a=p.parse_args()
    try:sys.stdout.buffer.write(diagnostic(a.gateway,a.port,a.user,a.identity,a.audit))
    except (ValueError,RuntimeError,OSError) as ex:print(str(ex),file=sys.stderr);return 1
    return 0
if __name__=='__main__':sys.exit(main())
