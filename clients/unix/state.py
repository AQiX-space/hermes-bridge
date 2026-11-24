"""Per-user SSH identity and OS-keychain protected broker ticket."""
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile

SERVICE = 'HermesConnector-Unix'


def appdir():
    if platform.system() == 'Darwin':
        return pathlib.Path.home()/'Library'/'Application Support'/'HermesConnector'
    return pathlib.Path(os.environ.get('XDG_DATA_HOME', pathlib.Path.home()/'.local'/'share'))/'hermes-connector'


class State:
    def __init__(self, root=None, secrets=None):
        requested = pathlib.Path(root or appdir()).expanduser()
        if requested.is_symlink():
            raise ValueError('application directory may not be a symlink')
        self.root = requested.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.secrets = secrets  # injectable only by tests, else native OS keyring
        self.ticket_name = 'device-'+str(os.getuid())

    @property
    def keyfile(self):
        return self.root/'device_ed25519'

    def ensure_key(self):
        if self.keyfile.exists():
            if not self.keyfile.with_suffix('.pub').exists():
                raise ValueError('SSH private key exists but public key is missing')
            if self.keyfile.stat().st_mode & 0o077:
                raise PermissionError('device SSH key has unsafe permissions')
            return self.keyfile.with_suffix('.pub').read_text().strip()
        if shutil.which('ssh-keygen') is None:
            raise RuntimeError('OpenSSH Client ssh-keygen is required')
        previous = os.umask(0o077)
        try:
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.keyfile)],
                           check=True, timeout=20, stdin=subprocess.DEVNULL)
        finally:
            os.umask(previous)
        os.chmod(self.keyfile, 0o600)
        os.chmod(self.keyfile.with_suffix('.pub'), 0o600)
        return self.keyfile.with_suffix('.pub').read_text().strip()

    def _keychain(self):
        if self.secrets is not None:
            return self.secrets
        try:
            import keyring
            if platform.system() == 'Darwin':
                from keyring.backends.macOS import Keyring
            elif platform.system() == 'Linux':
                from keyring.backends.SecretService import Keyring
            else:
                raise RuntimeError('Unix credential backend supported only on Linux/macOS')
            self.secrets = Keyring()
            if self.secrets.priority < 1:
                raise RuntimeError('Secure OS keychain is not available in this session')
            return self.secrets
        except (ImportError, AttributeError) as exc:
            raise RuntimeError('Secure system keyring is required; plaintext fallback is forbidden') from exc

    def store_ticket(self, ticket):
        if not re.fullmatch(r'[a-zA-Z0-9_-]{40,60}', ticket):
            raise ValueError('invalid broker ticket')
        self._keychain().set_password(SERVICE, self.ticket_name, ticket)

    def load_ticket(self):
        ticket = self._keychain().get_password(SERVICE, self.ticket_name)
        if ticket is not None and not re.fullmatch(r'[a-zA-Z0-9_-]{40,60}', ticket):
            raise ValueError('invalid ticket found in OS keyring')
        return ticket

    def clear_ticket(self):
        if self.load_ticket():
            self._keychain().delete_password(SERVICE, self.ticket_name)

    def save(self, value):
        if type(value) is not dict or any(k in value for k in ('ticket', 'token', 'secret', 'private_key')):
            raise ValueError('do not persist bearer secrets in a settings file')
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False).encode('utf-8')
        if len(raw) > 8192:
            raise ValueError('settings too large')
        path = self.root/'state.json'
        fd, tmp = tempfile.mkstemp(prefix='.state-', suffix='.tmp', dir=str(self.root))
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            os.chmod(path, 0o600)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def load(self):
        path = self.root/'state.json'
        if not path.exists():
            return {}
        if path.stat().st_mode & 0o077:
            raise PermissionError('insecure state file permissions')
        data = json.loads(path.read_bytes())
        if not isinstance(data, dict):
            raise ValueError('invalid saved state')
        return data

    def known_hosts(self, config):
        from broker import validate_approval
        config = validate_approval(config)
        line = f"[{config['host']}]:{config['port']} {config['hostkey']}\n"
        path = self.root/'known_hosts'
        path.write_text(line, encoding='ascii')
        os.chmod(path, 0o600)
        return path
