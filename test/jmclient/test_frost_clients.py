# -*- coding: utf-8 -*-

from hashlib import sha256
from unittest import IsolatedAsyncioTestCase

import jmclient  # noqa: F401 install asyncioreactor

import pytest

import jmbitcoin as btc
from jmbase import get_log
from jmclient import (
    load_test_config, jm_single, get_network, cryptoengine, VolatileStorage,
    FrostWallet, WalletService)
from jmclient.frost_clients import DKGClient, FROSTClient
from jmfrost.chilldkg_ref.chilldkg import (
    hostpubkey_gen, ParticipantMsg1, CoordinatorMsg1, ParticipantMsg2,
    CoordinatorMsg2)


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


async def populate_dkg_session(test_case):
    dkgc1 = DKGClient(test_case.wlt_svc1)
    dkgc2 = DKGClient(test_case.wlt_svc2)
    dkgc3 = DKGClient(test_case.wlt_svc3)
    hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)

    (
        nick1,
        hostpubkeyhash2_hex,
        session_id2_hex,
        sig2_hex,
        pmsg1_2
    ) = dkgc2.on_dkg_init(
        test_case.nick1, hostpubkeyhash_hex, session_id, sig_hex)
    pmsg1_2 = dkgc2.deserialize_pmsg1(pmsg1_2)

    (
        nick1,
        hostpubkeyhash3_hex,
        session_id3_hex,
        sig3_hex,
        pmsg1_3
    ) = dkgc3.on_dkg_init(
        test_case.nick1, hostpubkeyhash_hex, session_id, sig_hex)
    pmsg1_3 = dkgc2.deserialize_pmsg1(pmsg1_3)

    ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
        test_case.nick2, hostpubkeyhash2_hex, session_id, sig2_hex, pmsg1_2)
    ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
        test_case.nick3, hostpubkeyhash3_hex, session_id, sig3_hex, pmsg1_3)
    cmsg1 = dkgc1.deserialize_cmsg1(cmsg1)

    pmsg2_2 = dkgc2.party_step2(session_id, cmsg1)
    pmsg2_2 = dkgc2.deserialize_pmsg2(pmsg2_2)
    pmsg2_3 = dkgc3.party_step2(session_id, cmsg1)
    pmsg2_3 = dkgc3.deserialize_pmsg2(pmsg2_3)

    ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
        test_case.nick2, session_id, pmsg2_2)
    ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
        test_case.nick3, session_id, pmsg2_3)
    cmsg2 = dkgc3.deserialize_cmsg2(cmsg2)

    assert dkgc2.finalize(session_id, cmsg2, ext_recovery)
    assert dkgc3.finalize(session_id, cmsg2, ext_recovery)
    dkgc1.on_dkg_finalized(test_case.nick2, session_id)
    dkgc1.on_dkg_finalized(test_case.nick3, session_id)
    return session_id


class DKGClientTestCaseBase(IsolatedAsyncioTestCase):

    def setUp(self):
        load_test_config(config_path='./test_frost')
        btc.select_chain_params("bitcoin/regtest")
        cryptoengine.BTC_P2TR.VBYTE = 100
        jm_single().bc_interface.tick_forward_chain_interval = 2

    async def asyncSetUp(self):
        entropy1 = bytes.fromhex('8e5e5677fb302874a607b63ad03ba434')
        entropy2 = bytes.fromhex('38dfa80fbb21b32b2b2740e00a47de9d')
        entropy3 = bytes.fromhex('3ad9c77fcd1d537b6ef396952d1221a0')
        # entropy4 wor wallet with hospubkey not in joinmarket.cfg
        entropy4 = bytes.fromhex('ce88b87f6c85d651e416b8173ab95e57')
        self.wlt1 = await get_populated_wallet(entropy1)
        self.hostpubkey1 = hostpubkey_gen(self.wlt1._hostseckey[:32])
        self.wlt_svc1 = WalletService(self.wlt1)
        self.wlt2 = await get_populated_wallet(entropy2)
        self.hostpubkey2 = hostpubkey_gen(self.wlt2._hostseckey[:32])
        self.wlt_svc2 = WalletService(self.wlt2)
        self.wlt3 = await get_populated_wallet(entropy3)
        self.hostpubkey3 = hostpubkey_gen(self.wlt3._hostseckey[:32])
        self.wlt_svc3 = WalletService(self.wlt3)
        self.wlt4= await get_populated_wallet(entropy4)
        self.hostpubkey4 = hostpubkey_gen(self.wlt4._hostseckey[:32])
        self.wlt_svc4 = WalletService(self.wlt4)
        self.nick1, self.nick2, self.nick3, self.nick4 = [
            'nick1', 'nick2', 'nick3', 'nick4'
        ]


class DKGClientTestCase(DKGClientTestCaseBase):

    async def test_dkg_init(self):
        # test wallet with unknown hostpubkey
        dkgc1 = DKGClient(self.wlt_svc4)
        hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)
        assert hostpubkeyhash_hex is None
        assert session_id is None
        assert sig_hex  is None

        dkgc1 = DKGClient(self.wlt_svc1)
        hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)
        assert hostpubkeyhash_hex and len(hostpubkeyhash_hex) == 64
        assert session_id and len(session_id) == 32
        assert sig_hex and len(sig_hex) == 128

    async def test_on_dkg_init(self):
        dkgc1 = DKGClient(self.wlt_svc1)
        dkgc2 = DKGClient(self.wlt_svc2)
        hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)

        # fail with wrong pubkeyhash
        hostpubkeyhash4_hex = sha256(self.hostpubkey4).digest()
        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1
        ) = dkgc2.on_dkg_init(
            self.nick1, hostpubkeyhash4_hex, session_id, sig_hex)
        for v in [nick1, hostpubkeyhash2_hex, session_id2_hex,
                  sig2_hex, pmsg1]:
            assert v is None

        # fail with wrong sig
        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1
        ) = dkgc2.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, '01020304'*16)
        for v in [nick1, hostpubkeyhash2_hex, session_id2_hex,
                  sig2_hex, pmsg1]:
            assert v is None

        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1
        ) = dkgc2.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        assert nick1 == self.nick1
        assert hostpubkeyhash2_hex and len(hostpubkeyhash2_hex) == 64
        assert session_id2_hex and len(session_id2_hex) == 64
        assert bytes.fromhex(session_id2_hex) == session_id
        assert sig_hex and len(sig_hex) == 128
        assert pmsg1 is not None

        # fail on second call with right params
        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1
        ) = dkgc2.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        for v in [nick1, hostpubkeyhash2_hex, session_id2_hex,
                  sig2_hex, pmsg1]:
            assert v is None

    async def test_party_step1(self):
        dkgc1 = DKGClient(self.wlt_svc1)
        dkgc2 = DKGClient(self.wlt_svc2)
        hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)

        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1
        ) = dkgc2.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)

        # fail with unknown session_id
        pmsg1 = dkgc2.party_step1(b'\x05'*32)
        assert pmsg1 is None

        # fail when session.state1 aleready set
        pmsg1 = dkgc2.party_step1(session_id)
        assert pmsg1 is None

        session = dkgc2.dkg_sessions.get(session_id)
        session.state1 = None
        pmsg1 = dkgc2.party_step1(session_id)
        assert pmsg1 is not None
        assert isinstance(pmsg1, bytes)

        session.state1 = None
        pmsg1 = dkgc2.party_step1(session_id, serialize=False)
        assert pmsg1 is not None
        assert isinstance(pmsg1, ParticipantMsg1)

    def test_on_dkg_pmsg1(self):
        dkgc1 = DKGClient(self.wlt_svc1)
        dkgc2 = DKGClient(self.wlt_svc2)
        dkgc3 = DKGClient(self.wlt_svc3)
        hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)

        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1_2
        ) = dkgc2.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_2 = dkgc2.deserialize_pmsg1(pmsg1_2)

        (
            nick1,
            hostpubkeyhash3_hex,
            session_id3_hex,
            sig3_hex,
            pmsg1_3
        ) = dkgc3.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_3 = dkgc2.deserialize_pmsg1(pmsg1_3)

        # party2 added pmsg1, no ready_list, no cmsg1 returned yet
        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick2, hostpubkeyhash2_hex, session_id, sig2_hex, pmsg1_2)
        assert ready_list is None
        assert cmsg1 is None

        # unknown coordinator session
        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick3, hostpubkeyhash3_hex, b'\xaa'*32, sig3_hex, pmsg1_3)
        assert ready_list is None
        assert cmsg1 is None

        # unknown pubkeyhash
        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick3, b'\xaa'*32, session_id, sig3_hex, pmsg1_3)
        assert ready_list is None
        assert cmsg1 is None

        # wrong sig
        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick3, hostpubkeyhash3_hex, session_id, 'aa'*64, pmsg1_3)
        assert ready_list is None
        assert cmsg1 is None

        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick3, hostpubkeyhash3_hex, session_id, sig3_hex, pmsg1_3)
        assert ready_list == set([self.nick2, self.nick3])
        cmsg1 = dkgc1.deserialize_cmsg1(cmsg1)
        assert isinstance(cmsg1, CoordinatorMsg1)

    def test_coordinator_step1(self):
        dkgc1 = DKGClient(self.wlt_svc1)
        dkgc2 = DKGClient(self.wlt_svc2)
        dkgc3 = DKGClient(self.wlt_svc3)
        hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)

        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1_2
        ) = dkgc2.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_2 = dkgc2.deserialize_pmsg1(pmsg1_2)

        (
            nick1,
            hostpubkeyhash3_hex,
            session_id3_hex,
            sig3_hex,
            pmsg1_3
        ) = dkgc3.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_3 = dkgc2.deserialize_pmsg1(pmsg1_3)

        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick2, hostpubkeyhash2_hex, session_id, sig2_hex, pmsg1_2)
        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick3, hostpubkeyhash3_hex, session_id, sig3_hex, pmsg1_3)

        # unknown session_id
        cmsg1 = dkgc1.coordinator_step1(b'\xaa'*32)
        assert cmsg1 is None

        # coordinator.state already set
        cmsg1 = dkgc1.coordinator_step1(session_id)
        assert cmsg1 is None

        coordinator = dkgc1.dkg_coordinators.get(session_id)
        coordinator.state = None
        cmsg1 = dkgc1.coordinator_step1(session_id)

    def test_party_step2(self):
        dkgc1 = DKGClient(self.wlt_svc1)
        dkgc2 = DKGClient(self.wlt_svc2)
        dkgc3 = DKGClient(self.wlt_svc3)
        hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)

        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1_2
        ) = dkgc2.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_2 = dkgc2.deserialize_pmsg1(pmsg1_2)

        (
            nick1,
            hostpubkeyhash3_hex,
            session_id3_hex,
            sig3_hex,
            pmsg1_3
        ) = dkgc3.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_3 = dkgc2.deserialize_pmsg1(pmsg1_3)

        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick2, hostpubkeyhash2_hex, session_id, sig2_hex, pmsg1_2)
        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick3, hostpubkeyhash3_hex, session_id, sig3_hex, pmsg1_3)
        cmsg1 = dkgc1.deserialize_cmsg1(cmsg1)

        # unknown session_id
        pmsg2 = dkgc2.party_step2(b'\xaa'*32, cmsg1)
        assert pmsg2 is None

        pmsg2 = dkgc2.party_step2(session_id, cmsg1)
        assert cmsg1 is not None
        pmsg2 = dkgc1.deserialize_pmsg2(pmsg2)
        assert isinstance(pmsg2, ParticipantMsg2)

        # session.state2 already set
        pmsg2 = dkgc2.party_step2(session_id, cmsg1)
        assert pmsg2 is None

    def test_on_dkg_pmsg2(self):
        dkgc1 = DKGClient(self.wlt_svc1)
        dkgc2 = DKGClient(self.wlt_svc2)
        dkgc3 = DKGClient(self.wlt_svc3)
        hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)

        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1_2
        ) = dkgc2.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_2 = dkgc2.deserialize_pmsg1(pmsg1_2)

        (
            nick1,
            hostpubkeyhash3_hex,
            session_id3_hex,
            sig3_hex,
            pmsg1_3
        ) = dkgc3.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_3 = dkgc2.deserialize_pmsg1(pmsg1_3)

        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick2, hostpubkeyhash2_hex, session_id, sig2_hex, pmsg1_2)
        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick3, hostpubkeyhash3_hex, session_id, sig3_hex, pmsg1_3)
        cmsg1 = dkgc1.deserialize_cmsg1(cmsg1)

        pmsg2_2 = dkgc2.party_step2(session_id, cmsg1)
        pmsg2_2 = dkgc2.deserialize_pmsg2(pmsg2_2)
        assert isinstance(pmsg2_2, ParticipantMsg2)
        pmsg2_3 = dkgc3.party_step2(session_id, cmsg1)
        pmsg2_3 = dkgc3.deserialize_pmsg2(pmsg2_3)
        assert isinstance(pmsg2_3, ParticipantMsg2)

        # party2 added pmsg2, no ready_list, no cmsg2 returned yet
        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            self.nick2, session_id, pmsg2_2)
        assert ready_list is None
        assert cmsg2 is None
        assert ext_recovery is None

        # unknown coordinator session
        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            self.nick3, b'\xaa'*32, pmsg2_3)
        assert ready_list is None
        assert cmsg2 is None
        assert ext_recovery is None

        # unknown party nick
        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            self.nick4, session_id, pmsg2_3)
        assert ready_list is None
        assert cmsg2 is None
        assert ext_recovery is None

        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            self.nick3, session_id, pmsg2_3)
        cmsg2 = dkgc1.deserialize_cmsg2(cmsg2)
        assert ready_list == set([self.nick2, self.nick3])
        assert isinstance(cmsg2, CoordinatorMsg2)
        assert isinstance(ext_recovery, bytes)

        # party pubkey for nick3 not found
        coordinator = dkgc1.dkg_coordinators.get(session_id)
        session3 = coordinator.sessions.pop(self.hostpubkey3)
        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            self.nick3, session_id, pmsg2_3)
        assert ready_list is None
        assert cmsg2 is None
        assert ext_recovery is None
        coordinator.sessions[self.hostpubkey3] = session3

        # pmsg2 already set in coordinator sessions
        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            self.nick3, session_id, pmsg2_3)
        assert ready_list is None
        assert cmsg2 is None
        assert ext_recovery is None

    def test_coordinator_step2(self):
        dkgc1 = DKGClient(self.wlt_svc1)
        dkgc2 = DKGClient(self.wlt_svc2)
        dkgc3 = DKGClient(self.wlt_svc3)
        hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)

        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1_2
        ) = dkgc2.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_2 = dkgc2.deserialize_pmsg1(pmsg1_2)

        (
            nick1,
            hostpubkeyhash3_hex,
            session_id3_hex,
            sig3_hex,
            pmsg1_3
        ) = dkgc3.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_3 = dkgc2.deserialize_pmsg1(pmsg1_3)

        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick2, hostpubkeyhash2_hex, session_id, sig2_hex, pmsg1_2)
        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick3, hostpubkeyhash3_hex, session_id, sig3_hex, pmsg1_3)
        cmsg1 = dkgc1.deserialize_cmsg1(cmsg1)

        pmsg2_2 = dkgc2.party_step2(session_id, cmsg1)
        pmsg2_2 = dkgc2.deserialize_pmsg2(pmsg2_2)
        pmsg2_3 = dkgc3.party_step2(session_id, cmsg1)
        pmsg2_3 = dkgc3.deserialize_pmsg2(pmsg2_3)

        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            self.nick2, session_id, pmsg2_2)
        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            self.nick3, session_id, pmsg2_3)

        # unknown session_id
        cmsg2 = dkgc1.coordinator_step2(b'\xaa'*32)
        assert cmsg2 is None

        # coordinator.cmsg2 already set
        cmsg2 = dkgc1.coordinator_step2(session_id)
        assert cmsg2 is None

        coordinator = dkgc1.dkg_coordinators.get(session_id)
        coordinator.cmsg2 = None
        cmsg2 = dkgc1.coordinator_step2(session_id)
        cmsg2 = dkgc1.deserialize_cmsg2(cmsg2)
        assert isinstance(cmsg2, CoordinatorMsg2)

    def test_dkg_finalize(self):
        dkgc1 = DKGClient(self.wlt_svc1)
        dkgc2 = DKGClient(self.wlt_svc2)
        dkgc3 = DKGClient(self.wlt_svc3)
        hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)

        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1_2
        ) = dkgc2.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_2 = dkgc2.deserialize_pmsg1(pmsg1_2)

        (
            nick1,
            hostpubkeyhash3_hex,
            session_id3_hex,
            sig3_hex,
            pmsg1_3
        ) = dkgc3.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_3 = dkgc2.deserialize_pmsg1(pmsg1_3)

        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick2, hostpubkeyhash2_hex, session_id, sig2_hex, pmsg1_2)
        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick3, hostpubkeyhash3_hex, session_id, sig3_hex, pmsg1_3)
        cmsg1 = dkgc1.deserialize_cmsg1(cmsg1)

        pmsg2_2 = dkgc2.party_step2(session_id, cmsg1)
        pmsg2_2 = dkgc2.deserialize_pmsg2(pmsg2_2)
        pmsg2_3 = dkgc3.party_step2(session_id, cmsg1)
        pmsg2_3 = dkgc3.deserialize_pmsg2(pmsg2_3)

        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            self.nick2, session_id, pmsg2_2)
        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            self.nick3, session_id, pmsg2_3)
        cmsg2 = dkgc3.deserialize_cmsg2(cmsg2)

        # unknown session_id
        assert not dkgc2.finalize(b'\xaa'*32, cmsg2, ext_recovery)

        assert dkgc2.finalize(session_id, cmsg2, ext_recovery)
        assert dkgc3.finalize(session_id, cmsg2, ext_recovery)

        # session.dkg_output already set
        assert not dkgc2.finalize(session_id, cmsg2, ext_recovery)
        assert not dkgc3.finalize(session_id, cmsg2, ext_recovery)

    def test_on_dkg_finalized(self):
        dkgc1 = DKGClient(self.wlt_svc1)
        dkgc2 = DKGClient(self.wlt_svc2)
        dkgc3 = DKGClient(self.wlt_svc3)
        hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)

        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1_2
        ) = dkgc2.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_2 = dkgc2.deserialize_pmsg1(pmsg1_2)

        (
            nick1,
            hostpubkeyhash3_hex,
            session_id3_hex,
            sig3_hex,
            pmsg1_3
        ) = dkgc3.on_dkg_init(
            self.nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_3 = dkgc2.deserialize_pmsg1(pmsg1_3)

        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick2, hostpubkeyhash2_hex, session_id, sig2_hex, pmsg1_2)
        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            self.nick3, hostpubkeyhash3_hex, session_id, sig3_hex, pmsg1_3)
        cmsg1 = dkgc1.deserialize_cmsg1(cmsg1)

        pmsg2_2 = dkgc2.party_step2(session_id, cmsg1)
        pmsg2_2 = dkgc2.deserialize_pmsg2(pmsg2_2)
        pmsg2_3 = dkgc3.party_step2(session_id, cmsg1)
        pmsg2_3 = dkgc3.deserialize_pmsg2(pmsg2_3)

        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            self.nick2, session_id, pmsg2_2)
        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            self.nick3, session_id, pmsg2_3)
        cmsg2 = dkgc3.deserialize_cmsg2(cmsg2)

        assert dkgc2.finalize(session_id, cmsg2, ext_recovery)
        assert dkgc3.finalize(session_id, cmsg2, ext_recovery)

        # unknown session_id
        dkgc1.on_dkg_finalized(self.nick2, b'\xaa'*32)

        assert not dkgc1.on_dkg_finalized(self.nick2, session_id)
        assert dkgc1.on_dkg_finalized(self.nick3, session_id)


class FROSTClientTestCase(DKGClientTestCaseBase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.dkg_session_id = await populate_dkg_session(self)
        self.fc1 = FROSTClient(self.wlt_svc1)
        self.fc2 = FROSTClient(self.wlt_svc2)
        self.fc3 = FROSTClient(self.wlt_svc3)
        self.fc4 = FROSTClient(self.wlt_svc4)

    async def test_frost_req(self):
        msg_bytes = bytes.fromhex('aabb'*16)
        # test wallet with unknown hostpubkey
        hostpubkeyhash_hex, sig_hex, session_id = self.fc4.frost_req(
            self.dkg_session_id, msg_bytes)
        assert hostpubkeyhash_hex is None
        assert sig_hex  is None
        assert session_id is None

        hostpubkeyhash_hex, sig_hex, session_id = self.fc1.frost_req(
            self.dkg_session_id, msg_bytes)
        assert hostpubkeyhash_hex and len(hostpubkeyhash_hex) == 64
        assert sig_hex and len(sig_hex) == 128
        assert session_id and len(session_id) == 32

    async def test_on_frost_req(self):
        msg_bytes = bytes.fromhex('aabb'*16)
        hostpubkeyhash_hex, sig_hex, session_id = self.fc1.frost_req(
            self.dkg_session_id, msg_bytes)

        # fail with wrong pubkeyhash
        hostpubkeyhash4_hex = sha256(self.hostpubkey4).digest()
        (
            nick2,
            hostpubkeyhash2_hex,
            sig2_hex,
            session_id2_hex,
        ) = self.fc2.on_frost_req(
            self.nick1, hostpubkeyhash4_hex, sig_hex, session_id)
        for v in [nick2, hostpubkeyhash2_hex, sig2_hex, session_id2_hex]:
            assert v is None

        # fail with wrong sig
        (
            nick2,
            hostpubkeyhash2_hex,
            sig2_hex,
            session_id2_hex,
        ) = self.fc2.on_frost_req(
            self.nick1, hostpubkeyhash_hex, '01020304'*16, session_id)
        for v in [nick2, hostpubkeyhash2_hex, sig2_hex, session_id2_hex]:
            assert v is None

        (
            nick2,
            hostpubkeyhash2_hex,
            sig2_hex,
            session_id2_hex,
        ) = self.fc2.on_frost_req(
            self.nick1, hostpubkeyhash_hex, sig_hex, session_id)
        assert nick2 == self.nick1
        assert hostpubkeyhash2_hex and len(hostpubkeyhash2_hex) == 64
        assert sig_hex and len(sig_hex) == 128
        assert session_id2_hex and len(session_id2_hex) == 64
        assert bytes.fromhex(session_id2_hex) == session_id

        # fail on second call with right params
        (
            nick2,
            hostpubkeyhash2_hex,
            sig2_hex,
            session_id2_hex,
        ) = self.fc2.on_frost_req(
            self.nick1, hostpubkeyhash_hex, sig_hex, session_id)
        for v in [nick2, hostpubkeyhash2_hex, sig2_hex, session_id2_hex]:
            assert v is None

    async def test_on_frost_ack(self):
        msg_bytes = bytes.fromhex('aabb'*16)
        hostpubkeyhash_hex, sig_hex, session_id = self.fc1.frost_req(
            self.dkg_session_id, msg_bytes)

        (
            nick2,
            hostpubkeyhash2,
            sig2_hex,
            session_id_hex
        ) = self.fc2.on_frost_req(
            self.nick1, hostpubkeyhash_hex, sig_hex, session_id)

        # fail with wrong pubkeyhash
        hostpubkeyhash4_hex = sha256(self.hostpubkey4).digest()
        assert not self.fc1.on_frost_ack(
            self.nick4, hostpubkeyhash4_hex, sig2_hex, session_id)

        # fail with wrong sig
        hostpubkeyhash4_hex = sha256(self.hostpubkey4).digest()
        assert not self.fc1.on_frost_ack(
            self.nick2, hostpubkeyhash2, '01020304'*16, session_id)

        assert self.fc1.on_frost_ack(
            self.nick2, hostpubkeyhash2, sig2_hex, session_id)

    async def test_on_frost_init(self):
        msg_bytes = bytes.fromhex('aabb'*16)
        hostpubkeyhash_hex, sig_hex, session_id = self.fc1.frost_req(
            self.dkg_session_id, msg_bytes)

        (
            nick2,
            hostpubkeyhash2,
            sig2_hex,
            session_id_hex
        ) = self.fc2.on_frost_req(
            self.nick1, hostpubkeyhash_hex, sig_hex, session_id)

        assert self.fc1.on_frost_ack(
            self.nick2, hostpubkeyhash2, sig2_hex, session_id)

        (
            nick1,
            session_id2_hex,
            pub_nonce
        ) = self.fc2.on_frost_init(self.nick1, session_id)
        assert nick1 == self.nick1
        assert session_id2_hex and len(session_id2_hex) == 64
        assert bytes.fromhex(session_id2_hex) == session_id
        assert pub_nonce and len(pub_nonce) == 66

        # fail on second call with right params
        (
            nick1,
            session_id2_hex,
            pub_nonce2
        ) = self.fc2.on_frost_init(self.nick1, session_id)
        for v in [nick1, session_id2_hex, pub_nonce2]:
            assert v is None

    def test_frost_round1(self):
        msg_bytes = bytes.fromhex('aabb'*16)
        hostpubkeyhash_hex, sig_hex, session_id = self.fc1.frost_req(
            self.dkg_session_id, msg_bytes)

        (
            nick2,
            hostpubkeyhash2,
            sig2_hex,
            session_id_hex
        ) = self.fc2.on_frost_req(
            self.nick1, hostpubkeyhash_hex, sig_hex, session_id)

        assert self.fc1.on_frost_ack(
            self.nick2, hostpubkeyhash2, sig2_hex, session_id)

        (
            nick1,
            session_id2_hex,
            pub_nonce2
        ) = self.fc2.on_frost_init(self.nick1, session_id)

        # fail with unknown session_id
        pub_nonce = self.fc2.frost_round1(b'\x05'*32)
        assert pub_nonce is None

        # fail with session.sec_nonce already set
        pub_nonce = self.fc2.frost_round1(session_id)
        assert pub_nonce is None

        session = self.fc2.frost_sessions.get(session_id)
        session.sec_nonce = None
        pub_nonce = self.fc2.frost_round1(session_id)
        assert pub_nonce and len(pub_nonce) == 66

    def test_on_frost_round1(self):
        msg_bytes = bytes.fromhex('aabb'*16)
        hostpubkeyhash_hex, sig_hex, session_id = self.fc1.frost_req(
            self.dkg_session_id, msg_bytes)

        (
            nick2,
            hostpubkeyhash2,
            sig2_hex,
            session_id_hex
        ) = self.fc2.on_frost_req(
            self.nick1, hostpubkeyhash_hex, sig_hex, session_id)

        assert self.fc1.on_frost_ack(
            self.nick2, hostpubkeyhash2, sig2_hex, session_id)

        (
            nick1,
            session_id2_hex,
            pub_nonce2
        ) = self.fc2.on_frost_init(self.nick1, session_id)

        (
            nick1,
            session_id3_hex,
            pub_nonce3
        ) = self.fc3.on_frost_init(self.nick1, session_id)

        # unknown session_id
        (
            ready_list,
            nonce_agg,
            dkg_session_id,
            ids,
            msg
        ) = self.fc1.on_frost_round1(
            self.nick2, b'\xaa'*32, pub_nonce2)
        for v in [ready_list, nonce_agg, dkg_session_id, ids, msg]:
            assert v is None

        (
            ready_list,
            nonce_agg,
            dkg_session_id,
            ids,
            msg
        ) = self.fc1.on_frost_round1(
            self.nick2, session_id, pub_nonce2)
        assert ready_list == set([self.nick2])
        assert nonce_agg and len(nonce_agg)== 66
        assert dkg_session_id and dkg_session_id == self.dkg_session_id
        assert ids == [0, 1]
        assert msg and len(msg) == 32 and msg == msg_bytes

        # miminum pub_nonce set already presented, ignoring additional
        (
            ready_list,
            nonce_agg,
            dkg_session_id,
            ids,
            msg
        ) = self.fc1.on_frost_round1(
            self.nick3, session_id, pub_nonce3)
        for v in [ready_list, nonce_agg, dkg_session_id, ids, msg]:
            assert v is None

    def test_frost_agg1(self):
        msg_bytes = bytes.fromhex('aabb'*16)
        hostpubkeyhash_hex, sig_hex, session_id = self.fc1.frost_req(
            self.dkg_session_id, msg_bytes)

        (
            nick2,
            hostpubkeyhash2,
            sig2_hex,
            session_id_hex
        ) = self.fc2.on_frost_req(
            self.nick1, hostpubkeyhash_hex, sig_hex, session_id)

        assert self.fc1.on_frost_ack(
            self.nick2, hostpubkeyhash2, sig2_hex, session_id)

        (
            nick1,
            session_id2_hex,
            pub_nonce2
        ) = self.fc2.on_frost_init(self.nick1, session_id)

        (
            ready_list,
            nonce_agg,
            dkg_session_id,
            ids,
            msg
        ) = self.fc1.on_frost_round1(
            self.nick2, session_id, pub_nonce2)

        # fail on unknown session_id
        (
            nonce_agg,
            dkg_session_id,
            ids,
            msg
        ) = self.fc1.frost_agg1(b'\xaa'*32)
        for v in [nonce_agg, dkg_session_id, ids, msg]:
            assert v is None

        # fail with coordinator.nonce_agg already set
        (
            nonce_agg,
            dkg_session_id,
            ids,
            msg
        ) = self.fc1.frost_agg1(session_id)
        for v in [nonce_agg, dkg_session_id, ids, msg]:
            assert v is None

        coordinator = self.fc1.frost_coordinators.get(session_id)
        coordinator.nonce_agg = None
        (
            nonce_agg,
            dkg_session_id,
            ids,
            msg
        ) = self.fc1.frost_agg1(session_id)
        assert nonce_agg and len(nonce_agg)== 66
        assert dkg_session_id and dkg_session_id == self.dkg_session_id
        assert ids == [0, 1]
        assert msg and len(msg) == 32 and msg == msg_bytes

    def test_frost_round2(self):
        msg_bytes = bytes.fromhex('aabb'*16)
        hostpubkeyhash_hex, sig_hex, session_id = self.fc1.frost_req(
            self.dkg_session_id, msg_bytes)

        (
            nick2,
            hostpubkeyhash2,
            sig2_hex,
            session_id_hex
        ) = self.fc2.on_frost_req(
            self.nick1, hostpubkeyhash_hex, sig_hex, session_id)

        assert self.fc1.on_frost_ack(
            self.nick2, hostpubkeyhash2, sig2_hex, session_id)

        (
            nick1,
            session_id2_hex,
            pub_nonce2
        ) = self.fc2.on_frost_init(self.nick1, session_id)

        (
            ready_list,
            nonce_agg,
            dkg_session_id,
            ids,
            msg
        ) = self.fc1.on_frost_round1(
            self.nick2, session_id, pub_nonce2)

        # fail on unknown session_id
        partial_sig = self.fc2.frost_round2(
            b'\xaa'*32, nonce_agg, self.dkg_session_id, ids, msg)

        # fail on unknown dkg_session_id
        partial_sig = self.fc2.frost_round2(
            session_id, nonce_agg, b'\xdd'*32, ids, msg)

        partial_sig = self.fc2.frost_round2(
            session_id, nonce_agg, self.dkg_session_id, ids, msg)
        assert partial_sig and len(partial_sig) == 32

        # session.partial_sig already set
        partial_sig = self.fc2.frost_round2(
            session_id, nonce_agg, self.dkg_session_id, ids, msg)
        assert partial_sig is None

    def test_on_frost_round2(self):
        msg_bytes = bytes.fromhex('aabb'*16)
        hostpubkeyhash_hex, sig_hex, session_id = self.fc1.frost_req(
            self.dkg_session_id, msg_bytes)

        (
            nick2,
            hostpubkeyhash2,
            sig2_hex,
            session_id_hex
        ) = self.fc2.on_frost_req(
            self.nick1, hostpubkeyhash_hex, sig_hex, session_id)

        assert self.fc1.on_frost_ack(
            self.nick2, hostpubkeyhash2, sig2_hex, session_id)

        (
            nick1,
            session_id2_hex,
            pub_nonce2
        ) = self.fc2.on_frost_init(self.nick1, session_id)

        (
            ready_list,
            nonce_agg,
            dkg_session_id,
            ids,
            msg
        ) = self.fc1.on_frost_round1(
            self.nick2, session_id, pub_nonce2)

        partial_sig = self.fc2.frost_round2(
            session_id, nonce_agg, self.dkg_session_id, ids, msg)

        # unknown party nick
        sig = self.fc1.on_frost_round2(self.nick4, session_id, partial_sig)
        assert sig is None

        # party pubkey for nick3 not found
        coordinator = self.fc1.frost_coordinators.get(session_id)
        session2 = coordinator.sessions.pop(self.hostpubkey2)
        sig = self.fc1.on_frost_round2(self.nick2, session_id, partial_sig)
        assert sig is None
        coordinator.sessions[self.hostpubkey2] = session2

        # fail on unknown session_id
        sig = self.fc1.on_frost_round2(self.nick2, b'\xaa'*32, partial_sig)
        assert sig is None

        sig = self.fc1.on_frost_round2(self.nick2, session_id, partial_sig)
        assert sig and len(sig) == 64

        # partial_sig already set in coordinator
        sig = self.fc1.on_frost_round2(self.nick2, session_id, partial_sig)
        assert sig is None
