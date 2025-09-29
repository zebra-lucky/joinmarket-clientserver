'''Wallet functionality tests.'''
import os
import json
from pprint import pprint

from unittest import IsolatedAsyncioTestCase

import bencoder

import jmclient  # install asyncioreactor
from twisted.internet import reactor

import pytest
import jmbitcoin as btc
from jmbase import get_log
from jmclient import (
    load_test_config, jm_single, VolatileStorage, get_network, cryptoengine,
    create_wallet, open_test_wallet_maybe, FrostWallet, DKGManager,
    WalletService)

from jmfrost.chilldkg_ref.chilldkg import DKGOutput, hostpubkey_gen
from jmclient.frost_clients import (
    serialize_ext_recovery, decrypt_ext_recovery, DKGClient)

pytestmark = pytest.mark.usefixtures("setup_regtest_frost_bitcoind")

test_create_wallet_filename = "frost_testwallet_for_create_wallet_test"

log = get_log()


async def get_populated_wallet(entropy=None):
    storage = VolatileStorage()
    dkg_storage = VolatileStorage()
    recovery_storage = VolatileStorage()
    FrostWallet.initialize(storage, dkg_storage, recovery_storage,
                           get_network(), entropy=entropy)
    wallet = FrostWallet(storage, dkg_storage, recovery_storage)
    await wallet.async_init(storage)
    return wallet


def populate_dkg(wlt, add_party=True, add_coordinator=True, save_dkg=True):
    pubkey = hostpubkey_gen(wlt._hostseckey[:32])
    md_type_idx = (0, 0, 0)  # mixdepth, address_type, index
    ext_recovery_bytes = serialize_ext_recovery(*md_type_idx)
    ext_recovery = btc.ecies_encrypt(ext_recovery_bytes, pubkey)
    if add_party:
        wlt.dkg.add_party_data(
            session_id=bytes.fromhex('aa'*32),
            dkg_output=DKGOutput(
                bytes.fromhex('01'*32),         # secshare
                bytes.fromhex('02'*32 + '01'),  # threshold_pubkey
                [                               # pubshares
                    bytes.fromhex('03'*32 + '02'),
                    bytes.fromhex('03'*32 + '03'),
                    bytes.fromhex('03'*32 + '04'),
                ]
            ),
            hostpubkeys=[
                bytes.fromhex('02'*32 + '05'),
                bytes.fromhex('02'*32 + '06'),
                bytes.fromhex('02'*32 + '07'),
            ],
            t=2,
            recovery_data=bytes.fromhex('0102030405'*10),
            ext_recovery=ext_recovery,
            save_dkg=save_dkg
        )
    if add_coordinator:
        wlt.dkg.add_coordinator_data(
            session_id=bytes.fromhex('bb'*32),
            dkg_output=DKGOutput(
                bytes.fromhex('11'*32),         # secshare
                bytes.fromhex('02'*32 + '11'),  # threshold_pubkey
                [                               # pubshares
                    bytes.fromhex('03'*32 + '12'),
                    bytes.fromhex('03'*32 + '13'),
                    bytes.fromhex('03'*32 + '14'),
                ]
            ),
            hostpubkeys=[
                bytes.fromhex('02'*32 + '15'),
                bytes.fromhex('02'*32 + '16'),
                bytes.fromhex('02'*32 + '17'),
            ],
            t=2,
            recovery_data=bytes.fromhex('0102030405'*10),
            ext_recovery=ext_recovery,
            save_dkg=save_dkg
        )
    return ext_recovery


def check_dkg(wlt, ext_recovery, check_party=True, check_coordinator=True):
    if check_party:
        dkg_dict = wlt._dkg_storage.data[DKGManager.STORAGE_KEY]
        assert dkg_dict[DKGManager.SECSHARE_SUBKEY] == {
            b'\xaa'*32: b'\x01'*32
        }
        assert dkg_dict[DKGManager.PUBSHARES_SUBKEY] == {
            b'\xaa'*32: [
                bytes.fromhex('03'*32 + '02'),
                bytes.fromhex('03'*32 + '03'),
                bytes.fromhex('03'*32 + '04'),
            ]
        }
        assert dkg_dict[DKGManager.PUBKEY_SUBKEY] == {
            b'\xaa'*32: bytes.fromhex('02'*32 + '01'),
        }
        assert dkg_dict[DKGManager.HOSTPUBKEYS_SUBKEY] == {
            b'\xaa'*32: [
                bytes.fromhex('02'*32 + '05'),
                bytes.fromhex('02'*32 + '06'),
                bytes.fromhex('02'*32 + '07'),
            ]
        }
        assert dkg_dict[DKGManager.T_SUBKEY] == {
            b'\xaa'*32: 2,
        }
        assert dkg_dict[DKGManager.SESSIONS_SUBKEY] == dict()
        rec_dict = wlt._recovery_storage.data[DKGManager.RECOVERY_STORAGE_KEY]
        assert rec_dict == {
            b'\xaa'*32: [
                ext_recovery,
                bytes.fromhex('0102030405'*10),
            ],
        }
    if check_coordinator:
        ext_recovery_bytes = decrypt_ext_recovery(wlt._hostseckey,
                                                  ext_recovery)
        dkg_dict = wlt._dkg_storage.data[DKGManager.STORAGE_KEY]
        assert dkg_dict[DKGManager.SECSHARE_SUBKEY] == {
            b'\xbb'*32: b'\x11'*32
        }
        assert dkg_dict[DKGManager.PUBSHARES_SUBKEY] == {
            b'\xbb'*32: [
                bytes.fromhex('03'*32 + '12'),
                bytes.fromhex('03'*32 + '13'),
                bytes.fromhex('03'*32 + '14'),
            ]
        }
        assert dkg_dict[DKGManager.PUBKEY_SUBKEY] == {
            b'\xbb'*32: bytes.fromhex('02'*32 + '11'),
        }
        assert dkg_dict[DKGManager.HOSTPUBKEYS_SUBKEY] == {
            b'\xbb'*32: [
                bytes.fromhex('02'*32 + '15'),
                bytes.fromhex('02'*32 + '16'),
                bytes.fromhex('02'*32 + '17'),
            ]
        }
        assert dkg_dict[DKGManager.T_SUBKEY] == {
            b'\xbb'*32: 2,
        }
        assert dkg_dict[DKGManager.SESSIONS_SUBKEY] == {
            ext_recovery_bytes: b'\xbb'*32
        }
        rec_dict = wlt._recovery_storage.data[DKGManager.RECOVERY_STORAGE_KEY]
        assert rec_dict == {
            b'\xbb'*32: [
                ext_recovery,
                bytes.fromhex('0102030405'*10),
            ],
        }


class AsyncioTestCase(IsolatedAsyncioTestCase):

    params = {
        'test_is_standard_wallet_script': [FrostWallet]
    }

    def setUp(self):
        load_test_config(config_path='./test_frost')
        btc.select_chain_params("bitcoin/regtest")
        #see note in cryptoengine.py:
        cryptoengine.BTC_P2TR.VBYTE = 100
        jm_single().bc_interface.tick_forward_chain_interval = 2

    def tearDown(self):
        if os.path.exists(test_create_wallet_filename):
            os.remove(test_create_wallet_filename)
        dkg_filename = f'{test_create_wallet_filename}.dkg'
        recovery_filename = f'{test_create_wallet_filename}.dkg_recovery'
        if os.path.exists(dkg_filename):
            os.remove(dkg_filename)
        if os.path.exists(recovery_filename):
            os.remove(recovery_filename)

    async def test_create_wallet(self):
        password = b"hunter2"
        wallet_name = test_create_wallet_filename
        # test mainnet (we are not transacting)
        btc.select_chain_params("bitcoin")
        wallet = await create_wallet(wallet_name, password, 4, FrostWallet)
        mnemonic = wallet.get_mnemonic_words()[0]
        wallet.close()
        # ensure that the wallet file created is openable with the password,
        # and has the parameters that were claimed on creation:
        new_wallet = await open_test_wallet_maybe(
            wallet_name, "", 4, password=password, ask_for_password=False)
        assert new_wallet.get_mnemonic_words()[0] == mnemonic
        btc.select_chain_params("bitcoin/regtest")

    async def test_dkg_manager_initialized(self):
        wlt = await get_populated_wallet()
        dkg_dict = wlt._dkg_storage.data[DKGManager.STORAGE_KEY]
        assert set(dkg_dict.keys()) == set([
            DKGManager.SECSHARE_SUBKEY,
            DKGManager.PUBSHARES_SUBKEY,
            DKGManager.PUBKEY_SUBKEY,
            DKGManager.HOSTPUBKEYS_SUBKEY,
            DKGManager.T_SUBKEY,
            DKGManager.SESSIONS_SUBKEY,
        ])

        assert dkg_dict[DKGManager.SECSHARE_SUBKEY] == dict()
        assert dkg_dict[DKGManager.PUBSHARES_SUBKEY] == dict()
        assert dkg_dict[DKGManager.PUBKEY_SUBKEY] == dict()
        assert dkg_dict[DKGManager.HOSTPUBKEYS_SUBKEY] == dict()
        assert dkg_dict[DKGManager.T_SUBKEY] == dict()
        assert dkg_dict[DKGManager.SESSIONS_SUBKEY] == dict()
        rec_dict = wlt._recovery_storage.data[DKGManager.RECOVERY_STORAGE_KEY]
        assert rec_dict == dict()

    async def test_dkg_add_party_data(self):
        wlt = await get_populated_wallet()
        ext_recovery = populate_dkg(wlt, True, False)
        check_dkg(wlt, ext_recovery, True, False)

    async def test_dkg_add_coordinator_data(self):
        wlt = await get_populated_wallet()
        ext_recovery = populate_dkg(wlt, False, True)
        check_dkg(wlt, ext_recovery, False, True)

    async def test_dkg_save(self):
        wlt = await get_populated_wallet()
        ext_recovery = populate_dkg(wlt, True, True, save_dkg=False)
        ext_recovery_bytes = decrypt_ext_recovery(wlt._hostseckey,
                                                  ext_recovery)

        saved_dkg = bencoder.bdecode(wlt._dkg_storage.file_data[8:])
        STORAGE_KEY = DKGManager.STORAGE_KEY
        HOSTPUBKEYS_SUBKEY = DKGManager.HOSTPUBKEYS_SUBKEY
        PUBKEY_SUBKEY = DKGManager.PUBKEY_SUBKEY
        PUBSHARES_SUBKEY = DKGManager.PUBSHARES_SUBKEY
        SECSHARE_SUBKEY = DKGManager.SECSHARE_SUBKEY
        T_SUBKEY = DKGManager.T_SUBKEY
        SESSIONS_SUBKEY = DKGManager.SESSIONS_SUBKEY

        assert saved_dkg[STORAGE_KEY][SECSHARE_SUBKEY] == dict()
        assert saved_dkg[STORAGE_KEY][PUBSHARES_SUBKEY] == dict()
        assert saved_dkg[STORAGE_KEY][PUBKEY_SUBKEY] == dict()
        assert saved_dkg[STORAGE_KEY][HOSTPUBKEYS_SUBKEY] == dict()
        assert saved_dkg[STORAGE_KEY][T_SUBKEY] == dict()
        assert saved_dkg[STORAGE_KEY][SESSIONS_SUBKEY] == dict()

        saved_rec = bencoder.bdecode(wlt._recovery_storage.file_data[8:])
        assert saved_rec[b'dkg'] == dict()

        wlt.dkg.save()

        saved_dkg = bencoder.bdecode(wlt._dkg_storage.file_data[8:])
        assert set(saved_dkg[STORAGE_KEY][SECSHARE_SUBKEY].keys()) == set([
            b'\xaa'*32,
            b'\xbb'*32,
        ])
        assert set(saved_dkg[STORAGE_KEY][PUBSHARES_SUBKEY].keys()) == set([
            b'\xaa'*32,
            b'\xbb'*32,
        ])
        assert set(saved_dkg[STORAGE_KEY][PUBKEY_SUBKEY].keys()) == set([
            b'\xaa'*32,
            b'\xbb'*32,
        ])
        assert set(saved_dkg[STORAGE_KEY][HOSTPUBKEYS_SUBKEY].keys()) == set([
            b'\xaa'*32,
            b'\xbb'*32,
        ])
        assert set(saved_dkg[STORAGE_KEY][T_SUBKEY].keys()) == set([
            b'\xaa'*32,
            b'\xbb'*32,
        ])
        assert set(saved_dkg[STORAGE_KEY][SESSIONS_SUBKEY].keys()) == set([
            ext_recovery_bytes
        ])

        saved_rec = bencoder.bdecode(wlt._recovery_storage.file_data[8:])
        RECOVERY_STORAGE_KEY = DKGManager.RECOVERY_STORAGE_KEY
        assert set(saved_rec[RECOVERY_STORAGE_KEY].keys()) == set([
            b'\xaa'*32,
            b'\xbb'*32,
        ])

    async def test_dkg_load_storage(self):
        password = b"hunter2"
        wlt = await create_wallet(
            test_create_wallet_filename, password, 4, FrostWallet)
        mnemonic = wlt.get_mnemonic_words()[0]
        ext_recovery = populate_dkg(wlt, False, True)
        check_dkg(wlt, ext_recovery, False, True)
        wlt.save()
        wlt.close()

        new_wlt = await open_test_wallet_maybe(
            test_create_wallet_filename, "", 4, password=password,
            ask_for_password=False,
            load_dkg=True, dkg_read_only=False, read_only=True)

        dkgman = DKGManager(
            new_wlt, new_wlt._dkg_storage, new_wlt._recovery_storage)
        new_wlt._dkg = dkgman
        check_dkg(new_wlt, ext_recovery, False, True)

    async def test_dkg_find_session(self):
        wlt = await get_populated_wallet()
        ext_recovery = populate_dkg(wlt, True, True)
        assert wlt.dkg.find_session(0, 0, 0) == b'\xbb'*32
        assert wlt.dkg.find_session(0, 0, 1) is None

    async def test_dkg_find_dkg_pubkey(self):
        wlt = await get_populated_wallet()
        ext_recovery = populate_dkg(wlt, True, True)
        assert wlt.dkg.find_dkg_pubkey(0, 0, 0) == b'\x02'*32 + b'\x11'
        assert wlt.dkg.find_dkg_pubkey(0, 0, 1) is None

    async def test_dkg_recover(self):
        entropy1 = bytes.fromhex('8e5e5677fb302874a607b63ad03ba434')
        entropy2 = bytes.fromhex('38dfa80fbb21b32b2b2740e00a47de9d')
        entropy3 = bytes.fromhex('3ad9c77fcd1d537b6ef396952d1221a0')
        wlt1 = await get_populated_wallet(entropy1)
        hostpubkey1 = hostpubkey_gen(wlt1._hostseckey[:32])
        wlt_svc1 = WalletService(wlt1)
        wlt2 = await get_populated_wallet(entropy2)
        hostpubkey2 = hostpubkey_gen(wlt2._hostseckey[:32])
        wlt_svc2 = WalletService(wlt2)
        wlt3 = await get_populated_wallet(entropy3)
        hostpubkey3 = hostpubkey_gen(wlt3._hostseckey[:32])
        wlt_svc3 = WalletService(wlt3)
        nick1, nick2, nick3, nick4 = [
            'nick1', 'nick2', 'nick3', 'nick4'
        ]


        dkgc1 = DKGClient(wlt_svc1)
        dkgc2 = DKGClient(wlt_svc2)
        dkgc3 = DKGClient(wlt_svc3)
        hostpubkeyhash_hex, session_id, sig_hex = dkgc1.dkg_init(0, 0, 0)

        (
            nick1,
            hostpubkeyhash2_hex,
            session_id2_hex,
            sig2_hex,
            pmsg1_2
        ) = dkgc2.on_dkg_init(
            nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_2 = dkgc2.deserialize_pmsg1(pmsg1_2)

        (
            nick1,
            hostpubkeyhash3_hex,
            session_id3_hex,
            sig3_hex,
            pmsg1_3
        ) = dkgc3.on_dkg_init(
            nick1, hostpubkeyhash_hex, session_id, sig_hex)
        pmsg1_3 = dkgc2.deserialize_pmsg1(pmsg1_3)

        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            nick2, hostpubkeyhash2_hex, session_id, sig2_hex, pmsg1_2)
        ready_list, cmsg1 = dkgc1.on_dkg_pmsg1(
            nick3, hostpubkeyhash3_hex, session_id, sig3_hex, pmsg1_3)
        cmsg1 = dkgc1.deserialize_cmsg1(cmsg1)

        pmsg2_2 = dkgc2.party_step2(session_id, cmsg1)
        pmsg2_2 = dkgc2.deserialize_pmsg2(pmsg2_2)
        pmsg2_3 = dkgc3.party_step2(session_id, cmsg1)
        pmsg2_3 = dkgc3.deserialize_pmsg2(pmsg2_3)

        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            nick2, session_id, pmsg2_2)
        ready_list, cmsg2, ext_recovery = dkgc1.on_dkg_pmsg2(
            nick3, session_id, pmsg2_3)
        cmsg2 = dkgc3.deserialize_cmsg2(cmsg2)

        assert dkgc2.finalize(session_id, cmsg2, ext_recovery)
        assert dkgc3.finalize(session_id, cmsg2, ext_recovery)

        assert not dkgc1.on_dkg_finalized(nick2, session_id)
        assert dkgc1.on_dkg_finalized(nick3, session_id)

        wlt_rec = await get_populated_wallet(entropy1)
        wlt1._storage.data[b'created'] = wlt_rec._storage.data[b'created']
        wlt1._dkg_storage.data[b'created'] = \
            wlt_rec._dkg_storage.data[b'created']
        wlt1._recovery_storage.data[b'created'] = \
            wlt_rec._recovery_storage.data[b'created']
        assert wlt1._storage.data == wlt_rec._storage.data  # empty wallet
        assert wlt1._dkg_storage.data != wlt_rec._dkg_storage.data
        assert wlt1._recovery_storage.data != wlt_rec._recovery_storage.data

        wlt_rec.dkg.dkg_recover(wlt1._recovery_storage)

        assert wlt1._storage.data == wlt_rec._storage.data
        assert wlt1._dkg_storage.data == wlt_rec._dkg_storage.data
        assert wlt1._recovery_storage.data == wlt_rec._recovery_storage.data

    async def test_dkg_ls(self):
        wlt = await get_populated_wallet()
        ext_recovery = populate_dkg(wlt, True, True)
        ls_data = wlt.dkg.dkg_ls()
        ls_title = 'DKG data:\n'
        ls_title_len = len(ls_title)
        assert ls_data.startswith(ls_title)
        ls_data = ls_data[ls_title_len:]
        ls_json = json.loads(ls_data)
        assert set(ls_json.keys()) == set(['sessions', 'a'*64, 'b'*64])
        assert ls_json['sessions']['0,0,0'] == 'b'*64
        ls_json_a = ls_json['a'*64]
        ls_json_b = ls_json['b'*64]

        assert ls_json_a['secshare'] == '01'*32
        assert set(ls_json_a['pubshares']) == set(['03'*32 + '02',
                                                   '03'*32 + '03',
                                                   '03'*32 + '04'])
        assert ls_json_a['pubkey'] == '02'*32 + '01'
        assert set(ls_json_a['hostpubkeys']) == set(['02'*32 + '05',
                                                     '02'*32 + '06',
                                                     '02'*32 + '07'])
        assert ls_json_a['t'] == 2

        assert ls_json_b['secshare'] == '11'*32
        assert set(ls_json_b['pubshares']) == set(['03'*32 + '12',
                                                   '03'*32 + '13',
                                                   '03'*32 + '14'])
        assert ls_json_b['pubkey'] == '02'*32 + '11'
        assert set(ls_json_b['hostpubkeys']) == set(['02'*32 + '15',
                                                     '02'*32 + '16',
                                                     '02'*32 + '17'])
        assert ls_json_b['t'] == 2

    async def test_dkg_rm(self):
        wlt = await get_populated_wallet()
        ext_recovery = populate_dkg(wlt, True, True)
        rm_data = wlt.dkg.dkg_rm(['a'*64])
        rm_lines = rm_data.split('\n')
        assert rm_lines[0] == f'dkg data for session {"a"*64} deleted'
        rm_data = wlt.dkg.dkg_rm(['a'*64])
        rm_lines = rm_data.split('\n')
        assert rm_lines[0] == f'not found dkg data for session {"a"*64}'

        rm_data = wlt.dkg.dkg_rm(['b'*64])
        rm_lines = rm_data.split('\n')
        assert rm_lines[0] == f'dkg data for session {"b"*64} deleted'
        assert rm_lines[1] == f'session data for session {"b"*64} deleted'
        rm_data = wlt.dkg.dkg_rm(['b'*64])
        rm_lines = rm_data.split('\n')
        assert rm_lines[0] == f'not found dkg data for session {"b"*64}'

    async def test_recdkg_ls(self):
        wlt = await get_populated_wallet()
        ext_recovery = populate_dkg(wlt, True, True)
        ls_data = wlt.dkg.recdkg_ls()
        ls_lines = ls_data.split('\n')
        assert ls_lines[1] == 'Decrypted sesions:'
        assert ls_lines[-2] == 'Not decrypted sesions:'
        assert ls_lines[-1] == '[]'
        ls_json = json.loads('\n'.join(ls_lines[2:-3]))
        assert ls_json[0] == ['a'*64, '0'*12, '0102030405'*10]
        assert ls_json[1] == ['b'*64, '0'*12, '0102030405'*10]

    async def test_recdkg_rm(self):
        wlt = await get_populated_wallet()
        ext_recovery = populate_dkg(wlt, True, True)
        rm_data = wlt.dkg.recdkg_rm(['a'*64])
        rm_lines = rm_data.split('\n')
        assert rm_lines[0] == f'dkg recovery data for session {"a"*64} deleted'
        rm_data = wlt.dkg.recdkg_rm(['a'*64])
        rm_lines = rm_data.split('\n')
        assert rm_lines[0] == \
            f'not found dkg recovery data for session {"a"*64}'
        rm_data = wlt.dkg.recdkg_rm(['b'*64])
        rm_lines = rm_data.split('\n')
        assert rm_lines[0] == f'dkg recovery data for session {"b"*64} deleted'
        rm_data = wlt.dkg.recdkg_rm(['b'*64])
        rm_lines = rm_data.split('\n')
        assert rm_lines[0] == \
            f'not found dkg recovery data for session {"b"*64}'
