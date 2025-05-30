
"""Blockchaininterface functionality tests."""

import binascii
import pytest
from unittest import IsolatedAsyncioTestCase

from unittest_parametrize import parametrize, ParametrizedTestCase

from jmbase import get_log
from jmclient import load_test_config, jm_single, BaseWallet

from commontest import create_wallet_for_sync

log = get_log()

pytestmark = pytest.mark.usefixtures("setup_regtest_bitcoind")


async def sync_test_wallet(fast, wallet_service):
    sync_count = 0
    wallet_service.synced = False
    while not wallet_service.synced:
        await wallet_service.sync_wallet(fast=fast)
        sync_count += 1
        # avoid infinite loop
        assert sync_count < 10
        log.debug("Tried " + str(sync_count) + " times")


@pytest.mark.usefixtures("setup_wallets")
class AsyncioTestCase(IsolatedAsyncioTestCase, ParametrizedTestCase):

    @parametrize(
        'fast',
        [
            (False,),
            (True,),
        ])
    async def test_empty_wallet_sync(self, fast):
        wallet_service = await create_wallet_for_sync(
            [0, 0, 0, 0, 0], ['test_empty_wallet_sync'])

        await sync_test_wallet(fast, wallet_service)

        broken = True
        for md in range(wallet_service.max_mixdepth + 1):
            for internal in (BaseWallet.ADDRESS_TYPE_INTERNAL,
                             BaseWallet.ADDRESS_TYPE_EXTERNAL):
                broken = False
                assert 0 == wallet_service.get_next_unused_index(md, internal)
        assert not broken

    @parametrize(
        'fast,internal',
        [
            (False, BaseWallet.ADDRESS_TYPE_EXTERNAL),
            (False, BaseWallet.ADDRESS_TYPE_INTERNAL),
            (True, BaseWallet.ADDRESS_TYPE_EXTERNAL),
            (True, BaseWallet.ADDRESS_TYPE_INTERNAL)
        ])
    async def test_sequentially_used_wallet_sync(self, fast, internal):
        used_count = [1, 3, 6, 2, 23]
        wallet_service = await create_wallet_for_sync(
            used_count, ['test_sequentially_used_wallet_sync'],
            populate_internal=internal)

        await sync_test_wallet(fast, wallet_service)

        broken = True
        for md in range(len(used_count)):
            broken = False
            assert used_count[md] == wallet_service.get_next_unused_index(md, internal)
        assert not broken

    @parametrize(
        'fast',
        [
            (False,),
        ])
    async def test_gap_used_wallet_sync(self, fast):
        """ After careful examination this test now only includes the Recovery sync.
        Note: pre-Aug 2019, because of a bug, this code was not in fact testing both
        Fast and Recovery sync, but only Recovery (twice). Also, the scenario set
        out in this test (where coins are funded to a wallet which has no index-cache,
        and initially no imports) is only appropriate for recovery-mode sync, not for
        fast-mode (the now default).
        """
        used_count = [1, 3, 6, 2, 23]
        wallet_service = await create_wallet_for_sync(
            used_count, ['test_gap_used_wallet_sync'])
        wallet_service.gap_limit = 20

        for md in range(len(used_count)):
            x = -1
            for x in range(md):
                assert x <= wallet_service.gap_limit, "test broken"
                # create some unused addresses
                await wallet_service.get_new_script(
                    md, BaseWallet.ADDRESS_TYPE_INTERNAL)
                await wallet_service.get_new_script(
                    md, BaseWallet.ADDRESS_TYPE_EXTERNAL)
            used_count[md] += x + 2
            jm_single().bc_interface.grab_coins(
                await wallet_service.get_new_addr(
                    md, BaseWallet.ADDRESS_TYPE_INTERNAL), 1)
            jm_single().bc_interface.grab_coins(
                await wallet_service.get_new_addr(
                    md, BaseWallet.ADDRESS_TYPE_EXTERNAL), 1)

        # reset indices to simulate completely unsynced wallet
        for md in range(wallet_service.max_mixdepth + 1):
            wallet_service.set_next_index(md, BaseWallet.ADDRESS_TYPE_INTERNAL, 0)
            wallet_service.set_next_index(md, BaseWallet.ADDRESS_TYPE_EXTERNAL, 0)
        await sync_test_wallet(fast, wallet_service)

        broken = True
        for md in range(len(used_count)):
            broken = False
            assert md + 1 == wallet_service.get_next_unused_index(md,
                                                BaseWallet.ADDRESS_TYPE_INTERNAL)
            assert used_count[md] == wallet_service.get_next_unused_index(md,
                                                BaseWallet.ADDRESS_TYPE_EXTERNAL)
        assert not broken

    @parametrize(
        'fast',
        [
            (False,),
        ])
    async def test_multigap_used_wallet_sync(self, fast):
        """ See docstring for test_gap_used_wallet_sync; exactly the
        same applies here.
        """
        start_index = 5
        used_count = [start_index, 0, 0, 0, 0]
        wallet_service = await create_wallet_for_sync(
            used_count, ['test_multigap_used_wallet_sync'])
        wallet_service.gap_limit = 5

        mixdepth = 0
        for w in range(5):
            for x in range(int(wallet_service.gap_limit * 0.6)):
                assert x <= wallet_service.gap_limit, "test broken"
                # create some unused addresses
                await wallet_service.get_new_script(
                    mixdepth, BaseWallet.ADDRESS_TYPE_INTERNAL)
                await wallet_service.get_new_script(
                    mixdepth, BaseWallet.ADDRESS_TYPE_EXTERNAL)
            used_count[mixdepth] += x + 2
            jm_single().bc_interface.grab_coins(
                await wallet_service.get_new_addr(
                    mixdepth, BaseWallet.ADDRESS_TYPE_INTERNAL), 1)
            jm_single().bc_interface.grab_coins(
                await wallet_service.get_new_addr(
                    mixdepth, BaseWallet.ADDRESS_TYPE_EXTERNAL), 1)

        # reset indices to simulate completely unsynced wallet
        for md in range(wallet_service.max_mixdepth + 1):
            wallet_service.set_next_index(md, BaseWallet.ADDRESS_TYPE_INTERNAL, 0)
            wallet_service.set_next_index(md, BaseWallet.ADDRESS_TYPE_EXTERNAL, 0)

        await sync_test_wallet(fast, wallet_service)

        assert used_count[mixdepth] - start_index == \
               wallet_service.get_next_unused_index(
                    mixdepth, BaseWallet.ADDRESS_TYPE_INTERNAL)
        assert used_count[mixdepth] == wallet_service.get_next_unused_index(
            mixdepth, BaseWallet.ADDRESS_TYPE_EXTERNAL)

    @parametrize(
        'fast',
        [
            (False,),
            (True,),
        ])
    async def test_retain_unused_indices_wallet_sync(self, fast):
        used_count = [0, 0, 0, 0, 0]
        wallet_service = await create_wallet_for_sync(
            used_count, ['test_retain_unused_indices_wallet_sync'])

        for x in range(9):
            await wallet_service.get_new_script(
                0, BaseWallet.ADDRESS_TYPE_INTERNAL)

        await sync_test_wallet(fast, wallet_service)

        assert wallet_service.get_next_unused_index(0,
                        BaseWallet.ADDRESS_TYPE_INTERNAL) == 9

    @parametrize(
        'fast',
        [
            (False,),
            (True,),
        ])
    async def test_imported_wallet_sync(self, fast):
        used_count = [0, 0, 0, 0, 0]
        wallet_service = await create_wallet_for_sync(
            used_count, ['test_imported_wallet_sync'])
        source_wallet_service = await create_wallet_for_sync(
            used_count, ['test_imported_wallet_sync_origin'])

        address = await source_wallet_service.get_internal_addr(0)
        await wallet_service.import_private_key(0, source_wallet_service.get_wif(0, 1, 0))
        txid = binascii.unhexlify(jm_single().bc_interface.grab_coins(address, 1))

        await sync_test_wallet(fast, wallet_service)

        assert wallet_service._utxos.have_utxo(txid, 0) == 0


@pytest.fixture(scope='module')
def setup_wallets():
    load_test_config()
    jm_single().bc_interface.tick_forward_chain_interval = 1
