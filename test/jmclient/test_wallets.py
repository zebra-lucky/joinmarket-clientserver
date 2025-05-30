#! /usr/bin/env python
'''Wallet functionality tests.'''

import os
import time
import binascii
from commontest import create_wallet_for_sync, make_sign_and_push
import json

from unittest import IsolatedAsyncioTestCase

import pytest
from jmbase import get_log, hextobin
from jmclient import (
    load_test_config, jm_single,
    estimate_tx_fee, BitcoinCoreInterface, Mnemonic)
from taker_test_data import t_raw_signed_tx

pytestmark = pytest.mark.usefixtures("setup_regtest_bitcoind")

testdir = os.path.dirname(os.path.realpath(__file__))
log = get_log()


async def do_tx(wallet_service, amount):
    ins_full = await wallet_service.select_utxos(0, amount)
    cj_addr = await wallet_service.get_internal_addr(1)
    change_addr = await wallet_service.get_internal_addr(0)
    wallet_service.save_wallet()
    txid = await make_sign_and_push(ins_full,
                                    wallet_service,
                                    amount,
                                    output_addr=cj_addr,
                                    change_addr=change_addr,
                                    estimate_fee=True)
    assert txid
    time.sleep(2)  #blocks
    wallet_service.sync_unspent()
    return txid


def check_bip39_case(vectors, language="english"):
    mnemo = Mnemonic(language)
    for v in vectors:
        code = mnemo.to_mnemonic(binascii.unhexlify(v[0]))
        seed = binascii.hexlify(Mnemonic.to_seed(code, passphrase=v[4])).decode('ascii')
        print('checking this phrase: ' + v[1])
        assert mnemo.check(v[1])
        assert v[1] == code
        assert v[2] == seed


@pytest.mark.usefixtures("setup_wallets")
class AsyncioTestCase(IsolatedAsyncioTestCase):

    async def test_query_utxo_set(self):
        load_test_config()
        jm_single().bc_interface.tick_forward_chain_interval = 1
        wallet_service = await create_wallet_for_sync([2, 3, 0, 0, 0],
                                        ["wallet4utxo.json", "4utxo", [2, 3]])
        await wallet_service.sync_wallet(fast=True)
        txid = await do_tx(wallet_service, 90000000)
        txid2 = await do_tx(wallet_service, 20000000)
        print("Got txs: ", txid, txid2)
        res1 = jm_single().bc_interface.query_utxo_set(
            (txid, 0), include_mempool=True)
        res2 = jm_single().bc_interface.query_utxo_set(
            [(txid, 0), (txid2, 1)],
            includeconfs=True, include_mempool=True)
        assert len(res1) == 1
        assert len(res2) == 2
        assert all([x in res1[0] for x in ['script', 'value']])
        assert not 'confirms' in res1[0]
        assert 'confirms' in res2[0]
        assert 'confirms' in res2[1]
        res3 = jm_single().bc_interface.query_utxo_set((b"\xee" * 32, 25))
        assert res3 == [None]

    """Purely blockchaininterface related error condition tests"""
    async def test_wrong_network_bci(self):
        rpc = jm_single().bc_interface.jsonRpc
        with pytest.raises(Exception) as e_info:
            x = BitcoinCoreInterface(rpc, 'mainnet')

    async def test_pushtx_errors(self):
        """Ensure pushtx fails return False
        """
        badtx = b"\xaa\xaa"
        assert not jm_single().bc_interface.pushtx(badtx)
        #Break the authenticated jsonrpc and try again
        jm_single().bc_interface.jsonRpc.port = 18333
        assert not jm_single().bc_interface.pushtx(hextobin(t_raw_signed_tx))
        #rebuild a valid jsonrpc inside the bci
        load_test_config()

    """Tests mainly for wallet.py"""
    async def test_absurd_fee(self):
        jm_single().config.set("POLICY", "absurd_fee_per_kb", "1000")
        with pytest.raises(ValueError) as e_info:
            estimate_tx_fee(10, 2)
        load_test_config()

    """
    Sanity check of basic bip39 functionality for 12 words seed, copied from
    https://github.com/trezor/python-mnemonic/blob/master/tests/test_mnemonic.py
    """
    async def test_bip39_vectors(self):
        with open(os.path.join(testdir, 'bip39vectors.json'), 'r') as f:
            vectors_full = json.load(f)
        data = vectors_full['english']
        #default from-file cases use passphrase 'TREZOR'; TODO add other
        #extensions, but note there is coverage of that in the below test
        for d in data:
            d.append("TREZOR")
        vectors = []
        for d in data:
            vectors.append(tuple(d))
        #12 word seeds only
        vectors = filter(lambda x: len(x[1].split())==12, vectors)
        check_bip39_case(vectors)


@pytest.fixture(scope="module")
def setup_wallets():
    load_test_config()
    jm_single().bc_interface.tick_forward_chain_interval = 2
