"""HTTPS enrollment and pinned reverse-SSH parameters shared by Linux/macOS."""
import base64
import json
import re
import socket
import ssl
import struct
import urllib.error
import urllib.request
from urllib.parse import urljoin

BROKERS = ('https://gr1.touch01.top:18512/', 'https://gr2.touch01.top:18512/')
HOSTS = ('gr1.touch01.top', 'gr2.touch01.top')
KEY_PREFIX = struct.pack('!I', 11)+b'ssh-ed25519'+struct.pack('!I', 32)
TICKET_RE = re.compile(r'^[a-zA-Z0-9_-]{40,60}$')
CODE_RE = re.compile(r'^(?:[A-Z][a-z][0-9]{2}|[A-HJ-NP-Z2-9]{5})$')


class Broker:
    def __init__(self, base, transport=None):
        if base not in BROKERS:
            raise ValueError('unknown trusted Hermes broker')
        self.base = base
        self.transport = transport or self._request

    @staticmethod
    def _request(url, payload=None):
        data = json.dumps(payload).encode('utf-8') if payload is not None else None
        if data is not None and len(data) > 4096:
            raise ValueError('enrollment payload too large')
        headers = {'Content-Type': 'application/json'} if data is not None else {}
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=15) as response:
            if response.status not in (200, 202):
                raise ValueError('unexpected enrollment HTTP status')
            return json.loads(response.read(8192))

    def submit(self, device, public_key, mode, lease_seconds):
        if not re.fullmatch(r'[a-zA-Z0-9._-]{1,64}', device):
            raise ValueError('invalid device name')
        if mode not in ('resident', 'support') or not (0 <= lease_seconds <= 86400):
            raise ValueError('invalid requested mode or lease')
        if mode == 'resident' and lease_seconds != 0:
            raise ValueError('resident mode requires explicit unlimited lease request')
        if not public_key.startswith('ssh-ed25519 '):
            raise ValueError('invalid device SSH public key')
        result = self.transport(urljoin(self.base, 'v1/enroll'),
                                {'device': device, 'public_key': public_key,
                                 'requested_mode': mode, 'requested_lease_seconds': lease_seconds})
        if result.get('status') != 'pending' or not TICKET_RE.fullmatch(result.get('ticket', '')) \
                or not CODE_RE.fullmatch(result.get('code', '')):
            raise ValueError('untrusted broker enrollment response')
        return result

    def poll(self, ticket):
        if not TICKET_RE.fullmatch(ticket):
            raise ValueError('invalid ticket')
        result = self.transport(urljoin(self.base, 'v1/enroll/'+ticket))
        status = result.get('status')
        if status not in ('approved', 'pending', 'revoking', 'revoked', 'denied', 'expired', 'expiring', 'not_found'):
            raise ValueError('invalid broker status')
        if status == 'approved':
            result['config'] = validate_approval(result.get('config'))
        return result

    def revoke(self, ticket):
        if not TICKET_RE.fullmatch(ticket):
            raise ValueError('invalid ticket')
        result = self.transport(urljoin(self.base, 'v1/enroll/revoke'), {'ticket': ticket})
        return result.get('status') == 'revoked'


def validate_approval(value):
    if not isinstance(value, dict):
        raise ValueError('no trusted Gate config')
    host, port, slot, hostkey = (value.get(k) for k in ('host', 'port', 'slot', 'hostkey'))
    if host not in HOSTS or type(port) is not int or port != 22471 \
            or type(slot) is not int or not 23000 <= slot <= 24999:
        raise ValueError('unrecognized Hermes Gate configuration')
    if not isinstance(hostkey, str) or not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}', hostkey):
        raise ValueError('invalid SSH host-key format')
    blob = base64.b64decode(hostkey[len('ssh-ed25519 '):], validate=True)
    if len(blob) != 51 or not blob.startswith(KEY_PREFIX):
        raise ValueError('untrusted SSH ed25519 host-key bytes')
    return {'host': host, 'port': port, 'slot': slot, 'hostkey': hostkey}


def probe_broker(base, request=None, dial=None):
    if base not in BROKERS:
        return False
    request = request or Broker._request
    try:
        # An unknown ticket gives 404 only if the actual enrollment broker is up.
        url = urljoin(base, 'v1/enroll/hermes-unregistered-probe')
        try:
            request(url)
            return False
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                return False
        host = base.split('/')[2].split(':')[0]
        if dial is None:
            sock = socket.create_connection((host, 22471), timeout=3)
        else:
            sock = dial(host, 22471)
        with sock:
            sock.settimeout(3)
            return sock.recv(64).startswith(b'SSH-2.0-')
    except (OSError, ValueError, ssl.SSLError):
        return False
