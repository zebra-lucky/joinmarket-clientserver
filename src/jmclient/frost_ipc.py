# -*- coding: utf-8 -*-

import asyncio
import pickle

import jmbitcoin as btc
from jmbase.support import jmprint, EXIT_FAILURE, twisted_sys_exit, get_log


jlog = get_log()


class IPCBase:

    def encrypt_msg(self, msg_dict):
        msg_bytes = pickle.dumps(msg_dict)
        return btc.ecies_encrypt(msg_bytes, self.pubkey) + b'\n'

    def decrypt_msg(self, enc_bytes):
        msg_bytes = btc.ecies_decrypt(self.wallet._hostseckey, enc_bytes)
        return pickle.loads(msg_bytes)


class FrostIPCServer(IPCBase):

    def __init__(self, wallet):
        self.loop = asyncio.get_event_loop()
        self.wallet = wallet
        self.pubkey = btc.privkey_to_pubkey(wallet._hostseckey)
        self.sock_path = f'{wallet._storage.get_location()}.sock'
        self.srv = None
        self.sr = None
        self.sw = None
        self.tasks = set()

    async def async_init(self):
        self.srv = await asyncio.start_unix_server(
            self.handle_connection, self.sock_path)

    async def serve_forever(self):
        return await self.srv.serve_forever()

    async def handle_connection(self, sr, sw):
        if self.sr or self.sw:
            jlog.error('FrostIPCServer.handle_connection: client '
                       'already connected, ignore other connection attempt')
            return
        jlog.info('FrostIPCServer.handle_connection: connected new client')
        self.sr = sr
        self.sw = sw
        await self.process_msgs()

    async def process_msgs(self):
        while True:
            try:
                line_data = await self.sr.readline()
                if not line_data:
                    if self.sr.at_eof():
                        jlog.info('FrostIPCServer.process_msg: '
                                  'client disconnected')
                        self.sr = None
                        self.sw = None
                        while self.tasks:
                            task = self.tasks.pop()
                            task.cancel()
                        break
                    else:
                        jlog.error('FrostIPCServer.process_msg: '
                                   'empty line ignored')
                        continue
                enc_bytes = line_data.strip()
                msg_dict = self.decrypt_msg(enc_bytes)
                msg_id = msg_dict['msg_id']
                cmd = msg_dict['cmd']
                data = msg_dict['data']
                task = None
                if cmd == 'get_dkg_pubkey':
                    task = self.loop.create_task(
                        self.on_get_dkg_pubkey(msg_id, *data))
                elif cmd == 'frost_req':
                    task = self.loop.create_task(
                        self.on_frost_req(msg_id, *data))
                if task:
                    self.tasks.add(task)
            except Exception as e:
                jlog.error(f'FrostIPCServer.process_msgs: {repr(e)}')
            await asyncio.sleep(0.1)

    async def on_get_dkg_pubkey(self, msg_id, mixdepth, address_type, index,
                                session_id=None):
        try:
            wallet = self.wallet
            dkg = wallet.dkg
            if session_id is not None:
                client = wallet.client_factory.getClient()
                frost_client = wallet.client_factory.client
                frost_client.dkg_gen_list.append(
                    (mixdepth, address_type, index))
                new_pubkey = await client.dkg_gen(session_id=session_id)
            else:
                new_pubkey = dkg.find_dkg_pubkey(mixdepth, address_type, index)
            if session_id is None and new_pubkey is None:
                client = wallet.client_factory.getClient()
                frost_client = wallet.client_factory.client
                frost_client.dkg_gen_list.append(
                    (mixdepth, address_type, index))
                client.dkg_gen()
                if session_id == b'\x00'*32:
                    new_pubkey = pub
                else:
                    new_pubkey = dkg.find_dkg_pubkey(
                        mixdepth, address_type, index)
            if new_pubkey:
                await self.send_dkg_pubkey(msg_id, new_pubkey)
            else:
                raise Exception('No pubkey found or generated')
        except Exception as e:
            await self.send_dkg_pubkey(msg_id, None)
            jlog.error(f'FrostIPCServer.on_get_dkg_pubkey: {repr(e)}')

    async def send_dkg_pubkey(self, msg_id, pubkey):
        try:
            msg_dict = {
                'msg_id': msg_id,
                'cmd': 'dkg_pubkey',
                'data': pubkey,
            }
            self.sw.write(self.encrypt_msg(msg_dict))
            await self.sw.drain()
        except Exception as e:
            jlog.error(f'FrostIPCServer.send_dkg_pubkey: {repr(e)}')

    async def on_frost_req(self, msg_id, mixdepth, address_type, index,
                            sighash):
        try:
            wallet = self.wallet
            client = wallet.client_factory.getClient()
            frost_client = wallet.client_factory.client
            dkg = wallet.dkg
            dkg_session_id = dkg.find_session(mixdepth, address_type, index)
            session_id, _, _ = client.frost_req(dkg_session_id, sighash)
            sig, tweaked_pubkey = await frost_client.wait_on_sig(session_id)
            pubkey = dkg.find_dkg_pubkey(mixdepth, address_type, index)
            await self.send_frost_sig(msg_id, sig, pubkey, tweaked_pubkey)
        except Exception as e:
            jlog.error(f'FrostIPCServer.on_frost_req: {repr(e)}')
            await self.send_frost_sig(msg_id, None, None, None)

    async def send_frost_sig(self, msg_id, sig, pubkey, tweaked_pubkey):
        try:
            msg_dict = {
                'msg_id': msg_id,
                'cmd': 'frost_sig',
                'data': (sig, pubkey, tweaked_pubkey),
            }
            self.sw.write(self.encrypt_msg(msg_dict))
            await self.sw.drain()
        except Exception as e:
            jlog.error(f'FrostIPCServer.send_frost_sig: {repr(e)}')


class FrostIPCClient(IPCBase):

    def __init__(self, wallet):
        self.loop = asyncio.get_event_loop()
        self.msg_id = 0
        self.msg_futures = {}
        self.wallet = wallet
        self.pubkey = btc.privkey_to_pubkey(wallet._hostseckey)
        self.sock_path = f'{wallet._storage.get_location()}.sock'
        self.sr = None
        self.sw = None

    async def async_init(self):
        try:
            self.sr, self.sw = await asyncio.open_unix_connection(
                self.sock_path)
            self.loop.create_task(self.process_msgs())
        except (FileNotFoundError, ConnectionRefusedError) as e:
            jmprint('No servefrost socket found. Run wallet-tool.py '
                    'wallet.jmdat servefrost in separate console.', "error")
            twisted_sys_exit(EXIT_FAILURE)

    async def process_msgs(self):
        while True:
            try:
                line_data = await self.sr.readline()
                if not line_data:
                    if self.sr.at_eof():
                        jlog.info('FrostIPCClient.process_msg: '
                                  'client disconnected')
                        self.sr = None
                        self.sw = None
                        for msg_id, fut in list(self.msg_futures.items()):
                            fut = self.msg_futures.pop(msg_id)
                            fut.cancel()
                        break
                    else:
                        jlog.error('FrostIPCClient.process_msg: '
                                   'empty line ignored')
                        continue
                enc_bytes = line_data.strip()
                msg_dict = self.decrypt_msg(enc_bytes)
                msg_id = msg_dict['msg_id']
                cmd = msg_dict['cmd']
                data = msg_dict['data']
                if cmd in ['dkg_pubkey', 'frost_sig']:
                    await self.on_response(msg_id, data)
            except Exception as e:
                jlog.error(f'FrostIPCClient.process_msgs: {repr(e)}')
            await asyncio.sleep(0.1)

    async def on_response(self, msg_id, data):
        fut = self.msg_futures.pop(msg_id, None)
        if fut:
            fut.set_result(data)

    async def get_dkg_pubkey(self, mixdepth, address_type, index,
                             session_id=None):
        jlog.debug(f'FrostIPCClient.get_dkg_pubkey for mixdepth={mixdepth}, '
                   f'address_type={address_type}, index={index}')
        try:
            self.msg_id += 1
            msg_dict = {
                'msg_id': self.msg_id,
                'cmd': 'get_dkg_pubkey',
                'data': (mixdepth, address_type, index, session_id),
            }
            self.sw.write(self.encrypt_msg(msg_dict))
            await self.sw.drain()
            fut = self.loop.create_future()
            self.msg_futures[self.msg_id] = fut
            await fut
            pubkey = fut.result()
            if pubkey is None:
                jlog.error(
                    f'FrostIPCClient.get_dkg_pubkey got None pubkey from '
                    f'FrostIPCServer for mixdepth={mixdepth}, '
                    f'address_type={address_type}, index={index}')
                return pubkey
            jlog.debug(f'FrostIPCClient.get_dkg_pubkey successfully got '
                       f'pubkey for mixdepth={mixdepth}, '
                       f'address_type={address_type}, index={index}')
            return pubkey
        except Exception as e:
            jlog.error(f'FrostIPCClient.get_dkg_pubkey: {repr(e)}')

    async def frost_req(self, mixdepth, address_type, index, sighash):
        jlog.debug(f'FrostIPCClient.frost_req for mixdepth={mixdepth}, '
                   f'address_type={address_type}, index={index}, '
                   f'sighash={sighash.hex()}')
        try:
            self.msg_id += 1
            msg_dict = {
                'msg_id': self.msg_id,
                'cmd': 'frost_req',
                'data': (mixdepth, address_type, index, sighash),
            }
            self.sw.write(self.encrypt_msg(msg_dict))
            await self.sw.drain()
            fut = self.loop.create_future()
            self.msg_futures[self.msg_id] = fut
            await fut
            sig, pubkey, tweaked_pubkey = fut.result()
            if sig is None:
                jlog.error(
                    f'FrostIPCClient.frost_req got None sig value from '
                    f'FrostIPCServer for mixdepth={mixdepth}, '
                    f'address_type={address_type}, index={index}, '
                    f'sighash={sighash.hex()}')
                return sig, pubkey, tweaked_pubkey
            jlog.debug(
                f'FrostIPCClient.frost_req successfully got signature '
                f'for mixdepth={mixdepth}, address_type={address_type}, '
                f'index={index}, sighash={sighash.hex()}')
            return sig, pubkey, tweaked_pubkey
        except Exception as e:
            jlog.error(f'FrostIPCClient.frost_req: {repr(e)}')
            return None, None, None
