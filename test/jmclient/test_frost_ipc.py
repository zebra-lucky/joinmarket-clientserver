# -*- coding: utf-8 -*-

import asyncio
import time

from unittest import IsolatedAsyncioTestCase

import jmclient  # noqa: F401 install asyncioreactor

import pytest

import jmbitcoin as btc
from jmbase import get_log
from jmclient import (
    load_test_config, jm_single, get_network, cryptoengine, VolatileStorage,
    FrostWallet, WalletService)
from jmclient import FrostIPCServer, FrostIPCClient
from jmclient.frost_clients import FROSTClient

from test_frost_clients import populate_dkg_session


pytestmark = pytest.mark.usefixtures("setup_regtest_frost_bitcoind")

log = get_log()


async def get_populated_wallet(entropy=None):
    storage = VolatileStorage()
    dkg_storage = VolatileStorage()
    recovery_storage = VolatileStorage()
    FrostWallet.initialize(storage, dkg_storage, recovery_storage,
                           get_network(), entropy=entropy)
    wlt = FrostWallet(storage, dkg_storage, recovery_storage)
    await wlt.async_init(storage)
    return wlt


class DummyFrostJMClientProtocol:

    def __init__(self, factory, client, nick):
        self.nick = nick
        self.factory = factory
        self.client = client
        self.party_clients = {}

    async def dkg_gen(self):
        log.debug('Coordinator call dkg_gen')
        client = self.factory.client
        md_type_idx = None
        session_id = None
        session = None

        while True:
            if md_type_idx is None:
                md_type_idx = await client.dkg_gen()
                if md_type_idx is None:
                    log.debug('finished dkg_gen execution')
                    break

            if session_id is None:
                session_id, _, session = self.dkg_init(*md_type_idx)
                if session_id is None:
                    log.warn('could not get session_id from dkg_init}')
                    await asyncio.sleep(5)
                    continue

            pub = await client.wait_on_dkg_output(session_id)
            if not pub:
                session_id = None
                session = None
                continue

            if session.dkg_output:
                md_type_idx = None
                session_id = None
                session = None
                client.dkg_gen_list.pop(0)
                continue

    def dkg_init(self, mixdepth, address_type, index):
        log.debug(f'Coordinator call dkg_init '
                   f'({mixdepth}, {address_type}, {index})')
        client = self.factory.client
        hostpubkeyhash, session_id, sig = client.dkg_init(
            mixdepth, address_type, index)
        coordinator = client.dkg_coordinators.get(session_id)
        session = client.dkg_sessions.get(session_id)
        if session_id and session and coordinator:
            session.dkg_init_sec = time.time()

            for _, pc in self.party_clients.items():

                async def on_dkg_init(pc, nick, hostpubkeyhash,
                                        session_id, sig):
                    await pc.on_dkg_init(
                        nick, hostpubkeyhash, session_id, sig)

                asyncio.create_task(on_dkg_init(
                    pc, self.nick, hostpubkeyhash, session_id, sig))
            return session_id, coordinator, session
        return None, None, None

    async def on_dkg_init(self, nick, hostpubkeyhash, session_id, sig):
        client = self.factory.client
        nick, hostpubkeyhash, session_id, sig, pmsg1 = client.on_dkg_init(
            nick, hostpubkeyhash, session_id, sig)
        if pmsg1:
            pc = self.party_clients[nick]
            session_id = bytes.fromhex(session_id)
            await pc.on_dkg_pmsg1(
                self.nick, hostpubkeyhash, session_id, sig, pmsg1)

    async def on_dkg_pmsg1(self, nick, hostpubkeyhash, session_id, sig, pmsg1):
        client = self.factory.client
        pmsg1 = client.deserialize_pmsg1(pmsg1)
        ready_nicks, cmsg1 = client.on_dkg_pmsg1(
            nick, hostpubkeyhash, session_id, sig, pmsg1)
        if ready_nicks and cmsg1:
            for party_nick in ready_nicks:
                pc = self.party_clients[party_nick]
                await pc.on_dkg_cmsg1(self.nick, session_id, cmsg1)

    async def on_dkg_cmsg1(self, nick, session_id, cmsg1):
        client = self.factory.client
        session = client.dkg_sessions.get(session_id)
        if not session:
            log.error(f'on_dkg_cmsg1: session {session_id} not found')
            return {'accepted': True}
        if session and session.coord_nick == nick:
            cmsg1 = client.deserialize_cmsg1(cmsg1)
            pmsg2 = client.party_step2(session_id, cmsg1)
            if pmsg2:
                pc = self.party_clients[nick]
                await pc.on_dkg_pmsg2(self.nick, session_id, pmsg2)
        else:
            log.error(f'on_dkg_cmsg1: not coordinator nick {nick}')

    async def on_dkg_pmsg2(self, nick, session_id, pmsg2):
        client = self.factory.client
        pmsg2 = client.deserialize_pmsg2(pmsg2)
        ready_nicks, cmsg2, ext_recovery = client.on_dkg_pmsg2(
            nick, session_id, pmsg2)
        if ready_nicks and cmsg2 and ext_recovery:
            for party_nick in ready_nicks:
                pc = self.party_clients[party_nick]
                await pc.on_dkg_cmsg2(
                    self.nick, session_id, cmsg2, ext_recovery)

    async def on_dkg_cmsg2(self, nick, session_id, cmsg2, ext_recovery):
        client = self.factory.client
        session = client.dkg_sessions.get(session_id)
        if not session:
            log.error(f'on_dkg_cmsg2: session {session_id} not found')
            return {'accepted': True}
        if session and session.coord_nick == nick:
            cmsg2 = client.deserialize_cmsg2(cmsg2)
            finalized = client.finalize(session_id, cmsg2, ext_recovery)
            if finalized:
                pc = self.party_clients[nick]
                await pc.on_dkg_finalized(self.nick, session_id)
        else:
            log.error(f'on_dkg_cmsg2: not coordinator nick {nick}')

    async def on_dkg_finalized(self, nick, session_id):
        client = self.factory.client
        log.debug('Coordinator get dkgfinalized')
        client.on_dkg_finalized(nick, session_id)

    def frost_req(self, dkg_session_id, msg_bytes):
        log.debug('Coordinator call frost_req')
        client = self.factory.client
        hostpubkeyhash, sig, session_id = client.frost_req(
            dkg_session_id, msg_bytes)
        coordinator = client.frost_coordinators.get(session_id)
        session = client.frost_sessions.get(session_id)
        if session_id and session and coordinator:
            coordinator.frost_req_sec = time.time()
            for _, pc in self.party_clients.items():

                async def on_frost_req(pc, nick, hostpubkeyhash,
                                       sig, session_id):
                    await pc.on_frost_req(
                        nick, hostpubkeyhash, sig, session_id)

                asyncio.create_task(on_frost_req(
                    pc, self.nick, hostpubkeyhash, sig, session_id))
        return session_id, coordinator, session

    async def on_frost_req(self, nick, hostpubkeyhash, sig, session_id):
        client = self.factory.client
        (
            nick2,
            hostpubkeyhash,
            sig,
            session_id,
        ) = client.on_frost_req(nick, hostpubkeyhash, sig, session_id)
        if sig:
            pc = self.party_clients[nick]
            session_id = bytes.fromhex(session_id)
            await pc.on_frost_ack(
                self.nick, hostpubkeyhash, sig, session_id)

    async def on_frost_ack(self, nick, hostpubkeyhash, sig, session_id):
        client = self.factory.client
        assert client.on_frost_ack(nick, hostpubkeyhash, sig, session_id)
        pc = self.party_clients[nick]
        await pc.on_frost_init(self.nick, session_id)

    async def on_frost_init(self, nick, session_id):
        client = self.factory.client
        (
            nick2,
            session_id,
            hostpubkeyhash,
            pub_nonce
        ) = client.on_frost_init(nick, session_id)
        if pub_nonce:
            pc = self.party_clients[nick]
            session_id = bytes.fromhex(session_id)
            await pc.on_frost_round1(
                self.nick, session_id, hostpubkeyhash, pub_nonce)

    async def on_frost_round1(self, nick, session_id,
                              hostpubkeyhash, pub_nonce):
        client = self.factory.client
        (
            ready_nicks,
            nonce_agg,
            dkg_session_id,
            ids,
            msg
        ) = client.on_frost_round1(
            nick, session_id, hostpubkeyhash, pub_nonce)
        if ready_nicks and nonce_agg:
            for party_nick in ready_nicks:
                pc = self.party_clients[nick]
                await pc.on_frost_agg1(
                    self.nick, session_id, nonce_agg, dkg_session_id, ids, msg)

    async def on_frost_agg1(self, nick, session_id,
                      nonce_agg, dkg_session_id, ids, msg):
        client = self.factory.client
        session = client.frost_sessions.get(session_id)
        if not session:
            log.error(f'on_frost_agg1: session {session_id} not found')
            return
        if session and session.coord_nick == nick:
            partial_sig = client.frost_round2(
                session_id, nonce_agg, dkg_session_id, ids, msg)
            if partial_sig:
                pc = self.party_clients[nick]
                await pc.on_frost_round2(self.nick, session_id, partial_sig)
        else:
            log.error(f'on_frost_agg1: not coordinator nick {nick}')

    async def on_frost_round2(self, nick, session_id, partial_sig):
        client = self.factory.client
        sig = client.on_frost_round2(nick, session_id, partial_sig)
        if sig:
            log.debug(f'Successfully get signature {sig.hex()[:8]}...')


class DummyFrostJMClientProtocolFactory:

    protocol = DummyFrostJMClientProtocol

    def __init__(self, client, nick):
        self.client = client
        self.proto_client = self.protocol(self, self.client, nick)

    def add_party_client(self, nick, party_client):
        self.proto_client.party_clients[nick] = party_client

    def getClient(self):
        return self.proto_client


class FrostIPCTestCaseBase(IsolatedAsyncioTestCase):

    def setUp(self):
        load_test_config(config_path='./test_frost')
        btc.select_chain_params("bitcoin/regtest")
        cryptoengine.BTC_P2TR.VBYTE = 100
        jm_single().bc_interface.tick_forward_chain_interval = 2

    async def asyncSetUp(self):
        self.nick1, self.nick2, self.nick3 = ['nick1', 'nick2', 'nick3']
        entropy1 = bytes.fromhex('8e5e5677fb302874a607b63ad03ba434')
        entropy2 = bytes.fromhex('38dfa80fbb21b32b2b2740e00a47de9d')
        entropy3 = bytes.fromhex('3ad9c77fcd1d537b6ef396952d1221a0')
        self.wlt1 = await get_populated_wallet(entropy1)
        self.wlt_svc1 = WalletService(self.wlt1)
        self.fc1 = FROSTClient(self.wlt_svc1)
        cfactory1 = DummyFrostJMClientProtocolFactory(self.fc1, self.nick1)
        self.wlt1.set_client_factory(cfactory1)

        self.wlt2 = await get_populated_wallet(entropy2)
        self.wlt_svc2 = WalletService(self.wlt2)
        self.fc2 = FROSTClient(self.wlt_svc2)
        cfactory2 = DummyFrostJMClientProtocolFactory(self.fc2, self.nick2)
        self.wlt2.set_client_factory(cfactory2)

        self.wlt3 = await get_populated_wallet(entropy3)
        self.wlt_svc3 = WalletService(self.wlt3)
        self.fc3 = FROSTClient(self.wlt_svc3)
        cfactory3 = DummyFrostJMClientProtocolFactory(self.fc3, self.nick3)
        self.wlt3.set_client_factory(cfactory3)

        cfactory1.add_party_client(self.nick2, cfactory2.proto_client)
        cfactory1.add_party_client(self.nick3, cfactory3.proto_client)

        cfactory2.add_party_client(self.nick1, cfactory1.proto_client)
        cfactory2.add_party_client(self.nick3, cfactory3.proto_client)

        cfactory3.add_party_client(self.nick1, cfactory1.proto_client)
        cfactory3.add_party_client(self.nick2, cfactory2.proto_client)

        await populate_dkg_session(self)

        self.ipcs = FrostIPCServer(self.wlt1)
        await self.ipcs.async_init()
        self.ipcc = FrostIPCClient(self.wlt1)
        await self.ipcc.async_init()
        self.wlt1.set_ipc_client(self.ipcc)


class FrostIPCClientTestCase(FrostIPCTestCaseBase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.serve_task = asyncio.create_task(self.ipcs.serve_forever())

    async def asyncTearDown(self):
        self.serve_task.cancel("cancel from asyncTearDown")

    async def test_get_dkg_pubkey(self):
        pubkey = await self.ipcc.get_dkg_pubkey(0, 0, 0)
        dkg = self.wlt1.dkg
        pubkeys = list(dkg._dkg_pubkey.values())
        assert pubkey and pubkey in pubkeys

        pubkey = await self.ipcc.get_dkg_pubkey(0, 0, 1)
        pubkeys = list(dkg._dkg_pubkey.values())
        assert pubkey and pubkey in pubkeys

    async def test_frost_req(self):
        sighash = bytes.fromhex('01020304'*8)
        sig, pubkey, tweaked_pubkey = await self.ipcc.frost_req(
            0, 0, 0, sighash)
        assert sig and len(sig) == 64
        assert pubkey and len(pubkey) == 33
        assert tweaked_pubkey and len(tweaked_pubkey) == 33
