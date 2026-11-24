"""Real OpenSSH -R -> temporary AsyncSSH Gate -> signed current-user RPC.

Runs on an isolated CI runner. NEVER opens a public listening interface or
connects to GR1/GR2 production; no production keys or tickets are involved.
"""
import asyncio
import json
import os
import pathlib
import pwd
import socket
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]/'clients'/'unix'))
from agent import UserSessionAgent
from test_connector_core import signed
import asyncssh


def available_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class ReverseGate(asyncssh.SSHServer):
    def __init__(self, port):
        self.port = port
    def begin_auth(self, username):
        return True
    def server_requested(self, listen_host, listen_port):
        return listen_host == '127.0.0.1' and listen_port == self.port


class ReverseSSHIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_real_reverse_tunnel_and_signed_command(self):
        ticket = 'R'*43
        remote_port = available_port()
        with tempfile.TemporaryDirectory(prefix='hermes-ssh-e2e-') as root:
            directory = pathlib.Path(root)
            host_key = directory/'host_ed25519'
            client_key = directory/'device_ed25519'
            for key in (host_key,client_key):
                subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],
                               check=True,stdout=subprocess.DEVNULL,timeout=12)
            server = await asyncssh.listen('127.0.0.1', 0,
                  server_host_keys=[str(host_key)],
                  authorized_client_keys=str(client_key)+'.pub',
                  server_factory=lambda: ReverseGate(remote_port))
            gate_port = server.get_port()
            known = directory/'known_hosts'
            known.write_text(f'[127.0.0.1]:{gate_port} '+host_key.with_suffix('.pub').read_text())
            process = None
            try:
                with UserSessionAgent(ticket) as agent:
                    command = ['ssh','-N','-T','-p',str(gate_port),
                      '-R',f'127.0.0.1:{remote_port}:127.0.0.1:{agent.port}',
                      '-i',str(client_key),'-o','IdentitiesOnly=yes',
                      '-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                      '-o','UserKnownHostsFile='+str(known),
                      '-o','ExitOnForwardFailure=yes','-o','ConnectTimeout=5',
                      '-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',
                      'testuser@127.0.0.1']
                    process = subprocess.Popen(command,stdin=subprocess.DEVNULL,
                                               stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                    ok = None
                    for _ in range(60):
                        if process.poll() is not None:
                            error=process.stderr.read().decode('utf-8','replace')
                            self.fail('SSH stopped before forward: '+error[:400])
                        try:
                            reader,writer = await asyncio.open_connection('127.0.0.1',remote_port)
                        except OSError:
                            await asyncio.sleep(0.1)
                            continue
                        request = signed(ticket,'id -un')
                        writer.write(json.dumps(request).encode()+b'\n')
                        await writer.drain()
                        response = await asyncio.wait_for(reader.readline(),timeout=7)
                        writer.close()
                        await writer.wait_closed()
                        if response:
                            ok=json.loads(response)
                            break
                        await asyncio.sleep(0.1)
                    self.assertIsNotNone(ok,'No response through actual reverse SSH port')
                    self.assertTrue(ok['ok'],ok)
                    self.assertEqual(ok['stdout'].strip(),pwd.getpwuid(os.geteuid()).pw_name)
                    self.assertEqual(ok['user'],pwd.getpwuid(os.geteuid()).pw_name)
                    print('PASS: authentic OpenSSH -R forwards signed command to current UID')
            finally:
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(asyncio.to_thread(process.wait),timeout=5)
                    except asyncio.TimeoutError:
                        process.kill()
                        await asyncio.to_thread(process.wait)
                server.close()
                await server.wait_closed()
