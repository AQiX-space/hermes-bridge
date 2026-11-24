#!/usr/bin/env python3
"""Hermes Connector Unix: per-user approved support/resident CLI (development)."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

from agent import UserSessionAgent
from broker import Broker, BROKERS, probe_broker
from state import State

RETRY_MIN = 2
RETRY_MAX = 120


def notify(message):
    # Do not print bearer ticket, signed HMAC, secrets, or passwords.
    print(time.strftime('%Y-%m-%d %H:%M:%S'), message, flush=True)


def doctor():
    system = platform.system()
    print('Operating system:', system)
    print('Current account:', os.getuid(), 'Effective account:', os.geteuid())
    print('OpenSSH Client:', shutil.which('ssh') or 'not installed')
    print('OpenSSH Keygen:', shutil.which('ssh-keygen') or 'not installed')
    print('OpenSSH Server (optional):', shutil.which('sshd') or 'not installed/not on PATH')
    try:
        s = State()
        s._keychain()
        print('Secure OS keyring: available')
    except Exception as exc:
        print('Secure OS keyring: unavailable ('+str(exc)+')')
    if system == 'Linux':
        print('SSH installation: package manager (apt/dnf/pacman/zypper), explicit user consent required.')
    elif system == 'Darwin':
        print('OpenSSH client/server are normally included in macOS. Remote Login remains disabled by default.')
    else:
        print('Unsupported OS for this build')


def _linux_package(component):
    candidates = [
        ('apt-get', ['apt-get', 'install', '-y', 'openssh-'+component]),
        ('dnf', ['dnf', 'install', '-y', 'openssh-'+('clients' if component == 'client' else 'server')]),
        ('pacman', ['pacman', '-S', '--noconfirm', 'openssh']),
        ('zypper', ['zypper', '--non-interactive', 'install', 'openssh'])]
    for binary, command in candidates:
        if shutil.which(binary):
            return command
    raise RuntimeError('no known OS package manager; install OpenSSH manually')


def setup_ssh(component, install=False):
    system = platform.system()
    if system == 'Darwin':
        print('macOS supplies OpenSSH Client/Server. Verify /usr/bin/ssh and /usr/sbin/sshd.')
        print('Remote Login stays disabled: System Settings > General > Sharing is optional.')
        return
    if system != 'Linux':
        raise RuntimeError('Linux/macOS required')
    command = _linux_package(component)
    print('Native OS package:', ' '.join(command))
    if not install:
        print('Run setup-ssh '+component+' --install to request permission in this app.')
        return
    if not sys.stdin.isatty():
        raise RuntimeError('OS package installation requires an interactive consent prompt')
    if component == 'server':
        print('WARNING: installing OpenSSH Server may temporarily open inbound TCP/22.')
        print('Existing SSH server configurations will not be modified by the Connector.')
    answer = input('Type INSTALL to install the selected OS package: ')
    if answer != 'INSTALL':
        raise RuntimeError('installation canceled by user')
    # Installation requires system administrator permission, never used for
    # the remote command agent itself (which retains the current user token).
    root_command = command if os.geteuid() == 0 else ['sudo']+command
    subprocess.run(root_command, check=True, timeout=600)
    if component == 'client':
        if not shutil.which('ssh') or not shutil.which('ssh-keygen'):
            raise RuntimeError('OpenSSH Client installation did not provide ssh/ssh-keygen')
        print('OpenSSH Client verified')
    else:
        # Do not change a pre-existing sshd. Newly installed servers are
        # optional, never used by the current-user Connector command path.
        print('Check SSH server status and firewall before enabling it.')
        print('Hermes Connector does NOT require a listening SSH Server for ordinary support.')


@contextlib.contextmanager
def single_instance(root):
    lockfile = root/'connector.lock'
    handle = os.open(str(lockfile), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Hermes Connector is already running for this OS account')
        yield
    finally:
        os.close(handle)


def choose_broker(mode):
    if mode in ('gr1', 'gr2'):
        return BROKERS[0 if mode == 'gr1' else 1]
    for base in BROKERS:
        if probe_broker(base):
            return base
    raise ConnectionError('both Hermes brokers unavailable (GR1, GR2)')


def authorized_config(state, broker, mode, duration, stop):
    ticket = state.load_ticket()
    if ticket:
        status = broker.poll(ticket)
        if status['status'] == 'approved':
            return ticket, status['config']
        if status['status'] in ('revoking', 'expiring'):
            raise RuntimeError('previous Gate authorization is not confirmed revoked; no new registration')
        if status['status'] in ('revoked', 'expired', 'denied', 'not_found'):
            state.clear_ticket()
            ticket = None
    if not ticket:
        public = state.ensure_key()
        submitted = broker.submit(socket.gethostname().replace(' ', '-')[:64], public, mode, duration)
        ticket = submitted['ticket']
        state.store_ticket(ticket)
        state.save({'broker': broker.base, 'mode': mode})
        notify('МОСТ: '+submitted['code']+' — сообщите код оператору для подтверждения.')
    else:
        notify('Восстанавливаю ранее созданную заявку на исходном Gate; нужен прежний код МОСТ.')
    while not stop[0]:
        try:
            status = broker.poll(ticket)
        except (OSError, ValueError) as exc:
            notify('Broker temporarily unavailable: '+str(type(exc).__name__))
            time.sleep(5)
            continue
        if status['status'] == 'approved':
            return ticket, status['config']
        if status['status'] in ('revoked', 'denied', 'expired', 'not_found'):
            raise RuntimeError('Gate registration ended: '+status['status'])
        if status['status'] in ('revoking', 'expiring'):
            raise RuntimeError('Gate authorization is closing; no new connection')
        time.sleep(5)
    raise KeyboardInterrupt


def ssh_args(state, config, port):
    return ['ssh', '-N', '-T', '-p', str(config['port']),
            '-R', f"127.0.0.1:{config['slot']}:127.0.0.1:{port}",
            '-i', str(state.keyfile), '-o', 'IdentitiesOnly=yes',
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile='+str(state.root/'known_hosts'),
            '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=10',
            '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=30',
            '-o', 'ServerAliveCountMax=3', 'hermes-bridge@'+config['host']]


def should_revoke_on_exit(mode):
    return mode == 'support'


def run_connector(args):
    if platform.system() not in ('Linux', 'Darwin'):
        raise RuntimeError('this build supports Linux/macOS only')
    if not shutil.which('ssh') or not shutil.which('ssh-keygen'):
        raise RuntimeError('OpenSSH Client missing. Run setup-ssh client for help')
    state = State()
    stop = [False]

    def on_stop(_signum, _frame):
        stop[0] = True

    signal.signal(signal.SIGINT, on_stop)
    signal.signal(signal.SIGTERM, on_stop)
    mode = args.mode
    duration = 0 if mode == 'resident' or not args.disconnect_after else args.disconnect_after*60
    if duration > 86400:
        raise ValueError('requested support duration exceeds 24 hours')
    with single_instance(state.root):
        saved = state.load()
        ticket = state.load_ticket()
        if ticket:
            base = saved.get('broker')
            if base not in BROKERS:
                raise RuntimeError('existing ticket has no pinned broker; cannot silently migrate')
            if saved.get('mode') != mode:
                raise RuntimeError('existing approval has a different mode; explicitly revoke it before switching')
        else:
            base = choose_broker(args.gateway)
        broker = Broker(base)
        ticket, config = authorized_config(state, broker, mode, duration, stop)
        state.known_hosts(config)
        notify('Approved device: '+config['host']+'; current Unix UID: '+str(os.geteuid()))
        started = time.monotonic()
        previous_check = 0
        backoff = RETRY_MIN
        local_requested_revoke = False
        try:
            with UserSessionAgent(ticket, notify) as agent:
                while not stop[0]:
                    if duration and time.monotonic()-started >= duration:
                        notify('Configured auto-disconnect duration reached')
                        local_requested_revoke = True
                        break
                    connected_since = time.monotonic()
                    process = subprocess.Popen(ssh_args(state, config, agent.port),
                                               stdin=subprocess.DEVNULL,
                                               stdout=subprocess.DEVNULL,
                                               stderr=subprocess.DEVNULL)
                    notify('Attempting approved reverse tunnel through '+config['host'])
                    disconnected = False
                    while not stop[0]:
                        if duration and time.monotonic()-started >= duration:
                            local_requested_revoke = True
                            break
                        if process.poll() is not None:
                            notify('SSH transport exited ('+str(process.returncode)+'); retrying')
                            disconnected = True
                            break
                        if time.monotonic()-previous_check >= 30:
                            previous_check = time.monotonic()
                            try:
                                current = broker.poll(ticket)['status']
                                if current != 'approved':
                                    notify('Gate authorization no longer active ('+current+'); closing')
                                    stop[0] = True
                                    break
                            except (OSError, ValueError):
                                notify('Gate check failed; SSH keepalive monitors transport')
                        time.sleep(1)
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=3)
                    if stop[0] or local_requested_revoke:
                        break
                    if disconnected:
                        if time.monotonic()-connected_since > 120:
                            backoff = RETRY_MIN
                        notify('Waiting '+str(backoff)+' s before reconnect')
                        for _ in range(backoff):
                            if stop[0]:
                                break
                            time.sleep(1)
                        backoff = min(RETRY_MAX, backoff*2)
        finally:
            # Stop local execution immediately; a failed network revoke must
            # not be misrepresented as a remotely revoked authorization.
            if not should_revoke_on_exit(mode):
                # Power loss, logout and service stop must NOT destroy a deliberately
                # approved, permanent grant. Explicit `revoke` is a separate action.
                notify('Resident agent stopped locally; approved Gate ticket preserved for restart')
            else:
                try:
                    revoked = broker.revoke(ticket)
                except (OSError, ValueError):
                    revoked = False
                if revoked:
                    state.clear_ticket()
                    notify('Gate confirmed revoked; local ticket removed')
                else:
                    notify('Local agent stopped. Remote revocation UNCONFIRMED; ticket retained')


def _command_for_autostart():
    executable = pathlib.Path(sys.executable).resolve()
    if getattr(sys, 'frozen', False):
        # A downloaded one-file binary must not disappear when Downloads is
        # cleaned. Persist an atomically verified executable in the user home.
        state = State()
        installed_dir = state.root/'bin'
        installed_dir.mkdir(mode=0o700, exist_ok=True)
        installed = installed_dir/'HermesConnector'
        if executable != installed:
            temp = installed_dir/('HermesConnector-'+str(os.getpid())+'.new')
            try:
                shutil.copyfile(str(executable), str(temp))
                os.chmod(temp, 0o700)
                def checksum(path):
                    with open(path, 'rb') as stream:
                        h = hashlib.sha256()
                        for block in iter(lambda: stream.read(1024*1024), b''):
                            h.update(block)
                        return h.digest()
                if checksum(temp) != checksum(executable):
                    raise IOError('installed executable verification failed')
                os.replace(temp, installed)
            finally:
                if temp.exists():
                    temp.unlink()
        return [str(installed), 'connect', '--mode', 'resident']
    return [str(executable), str(pathlib.Path(__file__).resolve()), 'connect', '--mode', 'resident']


def _systemd_quote(value):
    if not value or '\n' in value or '\r' in value:
        raise ValueError('unsafe systemd service argument')
    return '"'+value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')+'"'


def _autostart_path():
    if platform.system() == 'Linux':
        return pathlib.Path.home()/'.config'/'systemd'/'user'/'hermes-connector.service'
    if platform.system() == 'Darwin':
        return pathlib.Path.home()/'Library'/'LaunchAgents'/'com.hermes.connector.plist'
    raise RuntimeError('autostart supported only on Linux and macOS')


def autostart(action, install_service=False):
    path = _autostart_path()
    if action == 'status':
        print('Enabled for current user:' if path.exists() else 'Disabled for current user:', str(path))
        return
    if action == 'disable':
        # Users can stop/unload their own service/agent; never touch root services.
        if platform.system() == 'Linux':
            subprocess.run(['systemctl', '--user', 'disable', '--now', 'hermes-connector.service'], check=False)
            subprocess.run(['systemctl', '--user', 'daemon-reload'], check=False)
        elif path.exists():
            subprocess.run(['launchctl', 'bootout', 'gui/'+str(os.getuid()), str(path)], check=False)
        if path.exists():
            path.unlink()
        print('Autostart disabled. Existing remote authorization is NOT automatically revoked.')
        return
    if action != 'enable' or not install_service:
        raise ValueError('explicit enable confirmation required')
    if path.exists():
        raise RuntimeError('existing autostart unit is not overwritten')
    state = State()
    if not state.load_ticket():
        raise RuntimeError('resident autostart requires a previously approved, keychain-stored ticket')
    path.parent.mkdir(parents=True, exist_ok=True)
    args = _command_for_autostart()
    if platform.system() == 'Linux':
        body = ('[Unit]\nDescription=Hermes Connector (current user)\nAfter=network-online.target\n'
                '[Service]\nType=simple\nExecStart='+ ' '.join(_systemd_quote(x) for x in args)+'\n'
                'Restart=always\nRestartSec=15\nNoNewPrivileges=yes\n'
                '[Install]\nWantedBy=default.target\n')
        path.write_text(body, encoding='utf-8')
        os.chmod(path, 0o600)
        subprocess.run(['systemctl', '--user', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', '--user', 'enable', 'hermes-connector.service'], check=True)
    else:
        import plistlib
        data = {'Label': 'com.hermes.connector', 'ProgramArguments': args,
                'RunAtLoad': True, 'KeepAlive': True}
        path.write_bytes(plistlib.dumps(data))
        os.chmod(path, 0o600)
        # launchd will load the agent at next login. Avoid a second instance now.
    print('Resident autostart enabled for the NEXT login. No OS privileges changed.')
    print('This is a USER service; before-login operation is not guaranteed.')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Hermes Connector Linux/macOS — user-context bridge')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('doctor')
    commands.add_parser('revoke', help='explicitly revoke the prior broker authorization')
    ssh = commands.add_parser('setup-ssh')
    ssh.add_argument('component', choices=('client', 'server'))
    ssh.add_argument('--install', action='store_true')
    connect = commands.add_parser('connect')
    connect.add_argument('--mode', choices=('support', 'resident'), default='support')
    connect.add_argument('--gateway', choices=('auto', 'gr1', 'gr2'), default='auto')
    connect.add_argument('--disconnect-after', type=int, choices=range(5, 1441), metavar='MINUTES')
    setup = commands.add_parser('autostart')
    setup.add_argument('action', choices=('status', 'enable', 'disable'))
    setup.add_argument('--confirm', action='store_true', help='explicitly approve user autostart')
    args = parser.parse_args(argv)
    if args.command == 'doctor':
        return doctor()
    if args.command == 'setup-ssh':
        return setup_ssh(args.component, args.install)
    if args.command == 'revoke':
        state = State()
        ticket = state.load_ticket()
        if not ticket:
            print('No saved authorization to revoke')
            return
        saved = state.load()
        if saved.get('broker') not in BROKERS:
            raise RuntimeError('cannot safely identify old broker for revocation')
        if Broker(saved['broker']).revoke(ticket):
            state.clear_ticket()
            print('Broker confirmed revoked, ticket removed from OS keyring')
        else:
            raise RuntimeError('broker did not confirm revocation; ticket preserved')
        return
    if args.command == 'autostart':
        return autostart(args.action, args.confirm)
    return run_connector(args)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError, PermissionError) as exc:
        print('Hermes Connector: '+str(exc), file=sys.stderr)
        sys.exit(2)
