"""Unix connector protocol, isolation and storage tests without live Gate."""
import base64
import hashlib
import hmac
import json
import os
import pathlib
import pwd
import socket
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]/'clients'/'unix'))
import agent
import broker
import main
import state

TICKET = 't'*43
HOSTKEY = 'ssh-ed25519 '+base64.b64encode(broker.KEY_PREFIX+bytes(range(32))).decode()
CONFIG = {'host': 'gr2.touch01.top', 'port': 22471, 'slot': 23018, 'hostkey': HOSTKEY}


class MemoryKeyring:
    def __init__(self):
        self.passwords = {}
    def set_password(self, service, user, secret):
        self.passwords[(service, user)] = secret
    def get_password(self, service, user):
        return self.passwords.get((service, user))
    def delete_password(self, service, user):
        del self.passwords[(service, user)]


def signed(ticket, command='id -un', nonce=None, ts=None):
    nonce = nonce or os.urandom(16).hex()
    ts = int(time.time()) if ts is None else ts
    key = hashlib.sha256(('Hermes user-agent HMAC v1\n'+ticket).encode()).digest()
    mac = base64.b64encode(hmac.new(key, f'{ts}\n{nonce}\n{command}'.encode(), hashlib.sha256).digest()).decode()
    return {'ts': ts, 'nonce': nonce, 'script': command, 'mac': mac}


def send(port, obj):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
        client.settimeout(9)
        client.sendall(json.dumps(obj).encode()+b'\n')
        buffer = b''
        while not buffer.endswith(b'\n'):
            buffer += client.recv(2048)
        return json.loads(buffer)


class LocalAgentTests(unittest.TestCase):
    def test_current_user_hmac_and_replay(self):
        with agent.UserSessionAgent(TICKET) as server:
            self.assertEqual(server.user, pwd.getpwuid(os.geteuid()).pw_name)
            first = signed(TICKET)
            ok = send(server.port, first)
            self.assertTrue(ok['ok'], ok)
            self.assertEqual(ok['stdout'].strip(), server.user)
            self.assertEqual(ok['user'], server.user)
            self.assertEqual(send(server.port, first)['error'], 'Unauthorized')
            self.assertEqual(send(server.port, signed('u'*43))['error'], 'Unauthorized')
            self.assertEqual(send(server.port, signed(TICKET, ts=int(time.time())-300))['error'], 'Unauthorized')
            self.assertEqual(send(server.port, signed(TICKET, command='x'*4100))['error'], 'Unauthorized')
            self.assertEqual(server._server.server_address[0], '127.0.0.1')

    def test_user_token_never_changes(self):
        with agent.UserSessionAgent(TICKET) as server:
            response = send(server.port, signed(TICKET, 'id -u'))
            self.assertTrue(response['ok'])
            self.assertEqual(int(response['stdout'].strip()), os.geteuid())


class BrokerTests(unittest.TestCase):
    def test_signed_config_and_fixed_host(self):
        self.assertEqual(broker.validate_approval(CONFIG)['slot'], 23018)
        for corrupt in ({**CONFIG, 'host': 'evil.example'}, {**CONFIG, 'port': 22},
                        {**CONFIG, 'slot': 12}, {**CONFIG, 'hostkey': 'ssh-ed25519 AAAA'}):
            with self.assertRaises(ValueError):
                broker.validate_approval(corrupt)

    def test_approve_requires_operator_and_requested_lease(self):
        history = []
        def fake_transport(url, payload=None):
            history.append((url, payload))
            if url.endswith('/v1/enroll'):
                return {'status': 'pending', 'code': 'De49', 'ticket': TICKET}
            return {'status': 'approved', 'config': CONFIG}
        api = broker.Broker(broker.BROKERS[1], transport=fake_transport)
        pending = api.submit('Test-Linux', 'ssh-ed25519 '+base64.b64encode(broker.KEY_PREFIX+bytes(32)).decode(), 'resident', 0)
        self.assertEqual(pending['code'], 'De49')
        self.assertEqual(history[0][1]['requested_mode'], 'resident')
        self.assertEqual(history[0][1]['requested_lease_seconds'], 0)
        self.assertEqual(api.poll(TICKET)['status'], 'approved')
        with self.assertRaises(ValueError):
            api.submit('Test-Linux', 'ssh-ed25519 abc', 'resident', 100)
        with self.assertRaises(ValueError):
            broker.Broker('https://evil.example/')


class LocalStateTests(unittest.TestCase):
    def test_state_keyring_and_pinned_host(self):
        with tempfile.TemporaryDirectory() as folder:
            secure = MemoryKeyring()
            store = state.State(folder, secrets=secure)
            store.store_ticket(TICKET)
            store.save({'broker': broker.BROKERS[1], 'mode': 'resident'})
            store.known_hosts(CONFIG)
            self.assertEqual(store.load_ticket(), TICKET)
            self.assertEqual(store.load()['mode'], 'resident')
            self.assertNotIn(TICKET, (pathlib.Path(folder)/'state.json').read_text())
            self.assertEqual((pathlib.Path(folder)/'state.json').stat().st_mode & 0o077, 0)
            self.assertIn('ssh-ed25519', (pathlib.Path(folder)/'known_hosts').read_text())
            with self.assertRaises(ValueError):
                store.save({'ticket': TICKET})
            store.clear_ticket()
            self.assertIsNone(store.load_ticket())

    def test_safe_ssh_options(self):
        with tempfile.TemporaryDirectory() as folder:
            store = state.State(folder, secrets=MemoryKeyring())
            args = main.ssh_args(store, CONFIG, 40001)
            self.assertIn('StrictHostKeyChecking=yes', args)
            self.assertIn('ServerAliveInterval=30', args)
            self.assertIn('ConnectTimeout=10', args)
            self.assertIn('127.0.0.1:23018:127.0.0.1:40001', args)
            self.assertFalse(any('sudo' in s or 'root@' in s for s in args))

    def test_single_user_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            with main.single_instance(root):
                with self.assertRaises(RuntimeError):
                    with main.single_instance(root):
                        pass
            with main.single_instance(root):
                pass

    def test_resident_reboot_does_not_destroy_approval(self):
        self.assertTrue(main.should_revoke_on_exit('support'))
        self.assertFalse(main.should_revoke_on_exit('resident'))

    def test_persist_downloaded_binary_for_resident_autostart(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder)
            original=root/'Downloads'/'HermesConnector'
            original.parent.mkdir()
            original.write_bytes(b'test executable; user opted in')
            target=state.State(root/'Library'/'Hermes', secrets=MemoryKeyring())
            with mock.patch.object(main.sys, 'frozen', True, create=True), \
                    mock.patch.object(main.sys, 'executable', str(original)), \
                    mock.patch.object(main, 'State', return_value=target):
                command=main._command_for_autostart()
            installed=pathlib.Path(command[0])
            self.assertEqual(installed.read_bytes(), original.read_bytes())
            self.assertEqual(installed.stat().st_mode & 0o077, 0)
            self.assertEqual(command[1:], ['connect', '--mode', 'resident'])

    def test_no_automatic_privileged_ssh_install(self):
        with mock.patch.object(main.platform, 'system', return_value='Linux'), \
                mock.patch.object(main, '_linux_package', return_value=['apt-get','install','-y','openssh-client']), \
                mock.patch.object(main.sys.stdin, 'isatty', return_value=False), \
                mock.patch.object(main.subprocess, 'run') as run:
            with self.assertRaises(RuntimeError):
                main.setup_ssh('client', install=True)
            run.assert_not_called()

    def test_broker_selection(self):
        with mock.patch.object(main, 'probe_broker', side_effect=lambda x: x == broker.BROKERS[1]):
            self.assertEqual(main.choose_broker('auto'), broker.BROKERS[1])
        with mock.patch.object(main, 'probe_broker', return_value=False):
            with self.assertRaises(ConnectionError):
                main.choose_broker('auto')


if __name__ == '__main__':
    unittest.main()
