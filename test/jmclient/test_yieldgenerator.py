
import unittest

import pytest
from jmbitcoin import CMutableTxOut, CMutableTransaction
from jmclient import load_test_config, jm_single,\
    SegwitLegacyWallet, VolatileStorage, YieldGeneratorBasic, \
    get_network, WalletService
from commontest import AsyncioTestCase

pytestmark = pytest.mark.usefixtures("setup_regtest_bitcoind")


class CustomUtxoWallet(SegwitLegacyWallet):
    """A wallet instance that makes it easy to do the tasks we need for
    the tests.  It has convenience methods to add UTXOs with pre-defined
    balances for all mixdepths, and to verify if a given UTXO or address
    corresponds to the mixdepth it should."""

    def __init__(self, balances):
        """Creates the wallet, setting the balances of the mixdepths
        as given by the array.  (And the number of mixdepths from the array
        elements."""

        load_test_config()

        self._storage = storage = VolatileStorage()
        self.balances = balances
        super().initialize(storage, get_network(), max_mixdepth=len(balances)-1)
        super().__init__(storage)

    async def async_init(self, storage, **kwargs):
        await super().async_init(storage)
        for m, b in enumerate(self.balances):
            await self.add_utxo_at_mixdepth(m, b)

    async def add_utxo_at_mixdepth(self, mixdepth, balance):
        txout = CMutableTxOut(
            balance, await self.get_internal_script(mixdepth))
        tx = CMutableTransaction()
        tx.vout = [txout]
        # (note: earlier requirement that txid be generated uniquely is now
        # automatic; tx.GetTxid() functions correctly within the wallet).
        self.add_new_utxos(tx, 1)

    def assert_utxos_from_mixdepth(self, utxos, expected):
        """Asserts that the list of UTXOs (as returned from UTXO selection
        of the wallet) is all from the given expected mixdepth."""

        for u in utxos.values():
            assert self.get_addr_mixdepth(u['address']) == expected


async def create_yg_basic(balances, txfee_contribution=0, cjfee_a=0, cjfee_r=0,
                          ordertype='swabsoffer', minsize=0):
    """Constructs a YieldGeneratorBasic instance with a fake wallet.  The
    wallet will have the given balances at mixdepths, and the offer params
    will be set as given here."""

    wallet = CustomUtxoWallet(balances)
    await wallet.async_init(wallet._storage)
    offerconfig = (txfee_contribution, cjfee_a, cjfee_r, ordertype, minsize,
        None, None, None)

    yg = YieldGeneratorBasic(WalletService(wallet), offerconfig)

    # We don't need any of the logic from Maker, including the waiting
    # loop.  Just stop it, so that it does not linger around and create
    # unclean-reactor failures.
    if yg.sync_wait_loop.running:
        yg.sync_wait_loop.stop()

    return yg


class CreateMyOrdersTests(AsyncioTestCase):
    """Unit tests for YieldGeneratorBasic.create_my_orders."""

    async def test_no_coins(self):
        yg = await create_yg_basic([0] * 3)
        self.assertEqual(yg.create_my_orders(), [])

    async def test_abs_fee(self):
        jm_single().DUST_THRESHOLD = 10
        yg = await create_yg_basic(
            [0, 2000000, 1000000], txfee_contribution=1000,
            cjfee_a=10, ordertype='swabsoffer', minsize=100000)
        self.assertEqual(yg.create_my_orders(), [
          {'oid': 0,
           'ordertype': 'swabsoffer',
           'minsize': 100000,
           'maxsize': 1999000,
           'txfee': 1000,
           'cjfee': '1010'},
        ])

    async def test_rel_fee(self):
        jm_single().DUST_THRESHOLD = 10
        yg = await create_yg_basic(
            [0, 2000000, 1000000], txfee_contribution=1000,
            cjfee_r=0.1, ordertype='sw0reloffer', minsize=10)
        self.assertEqual(yg.create_my_orders(), [
          {'oid': 0,
           'ordertype': 'sw0reloffer',
           'minsize': 15000,
           'maxsize': 1999000,
           'txfee': 1000,
           'cjfee': 0.1},
        ])

    async def test_dust_threshold(self):
        jm_single().DUST_THRESHOLD = 1000
        yg = await create_yg_basic(
            [0, 2000000, 1000000], txfee_contribution=10,
            cjfee_a=10, ordertype='swabsoffer', minsize=100000)
        self.assertEqual(yg.create_my_orders(), [
          {'oid': 0,
           'ordertype': 'swabsoffer',
           'minsize': 100000,
           'maxsize': 1999000,
           'txfee': 10,
           'cjfee': '20'},
        ])

    async def test_minsize_above_maxsize(self):
        jm_single().DUST_THRESHOLD = 10
        yg = await create_yg_basic(
            [0, 20000, 10000], txfee_contribution=1000,
            cjfee_a=10, ordertype='swabsoffer', minsize=100000)
        self.assertEqual(yg.create_my_orders(), [])


class OidToOrderTests(AsyncioTestCase):
    """Tests YieldGeneratorBasic.oid_to_order."""

    async def call_oid_to_order(self, yg, amount):
        """Calls oid_to_order on the given yg instance.  It passes the
        txfee and abs fee from yg as offer."""
        offer = {'txfee': yg.txfee_contribution,
                 'cjfee': str(yg.cjfee_a),
                 'ordertype': 'swabsoffer'}
        return await yg.oid_to_order(offer, amount)

    async def test_not_enough_balance(self):
        yg = await create_yg_basic([100], txfee_contribution=0, cjfee_a=10)
        self.assertEqual(
            await self.call_oid_to_order(yg, 1000), (None, None, None))

    async def test_chooses_single_utxo(self):
        jm_single().DUST_THRESHOLD = 10
        yg = await create_yg_basic([10, 1000, 2000])
        utxos, cj_addr, change_addr = await self.call_oid_to_order(yg, 500)
        self.assertEqual(len(utxos), 1)
        yg.wallet_service.wallet.assert_utxos_from_mixdepth(utxos, 1)
        self.assertEqual(yg.wallet_service.wallet.get_addr_mixdepth(cj_addr), 2)
        self.assertEqual(yg.wallet_service.wallet.get_addr_mixdepth(change_addr), 1)

    async def test_not_enough_balance_with_dust_threshold(self):
        # 410 is exactly the size of the change output.  So it will be
        # right at the dust threshold.  The wallet won't be able to find
        # any extra inputs, though.
        jm_single().DUST_THRESHOLD = 410
        yg = await create_yg_basic(
            [10, 1000, 10], txfee_contribution=100, cjfee_a=10)
        self.assertEqual(
            await self.call_oid_to_order(yg, 500), (None, None, None))

    async def test_extra_with_dust_threshold(self):
        # The output will be right at the dust threshold, so that we will
        # need to include the extra_utxo from the wallet as well to get
        # over the threshold.
        jm_single().DUST_THRESHOLD = 410
        yg = await create_yg_basic(
            [10, 1000, 10], txfee_contribution=100, cjfee_a=10)
        await yg.wallet_service.wallet.add_utxo_at_mixdepth(1, 500)
        utxos, cj_addr, change_addr = await self.call_oid_to_order(yg, 500)
        self.assertEqual(len(utxos), 2)
        yg.wallet_service.wallet.assert_utxos_from_mixdepth(utxos, 1)
        self.assertEqual(yg.wallet_service.wallet.get_addr_mixdepth(cj_addr), 2)
        self.assertEqual(yg.wallet_service.wallet.get_addr_mixdepth(change_addr), 1)


class OfferReannouncementTests(AsyncioTestCase):
    """Tests offer reannouncement logic from on_tx_unconfirmed."""

    def call_on_tx_unconfirmed(self, yg):
        """Calls yg.on_tx_unconfirmed with fake arguments."""
        return yg.on_tx_unconfirmed({'cjaddr': 'addr'}, 'txid')

    async def create_yg_and_offer(self, maxsize):
        """Constructs a fake yg instance that has an offer with the given
        maxsize.  Returns it together with the offer."""
        jm_single().DUST_THRESHOLD = 10
        yg = await create_yg_basic(
            [100 + maxsize], txfee_contribution=100, ordertype='swabsoffer')
        offers = yg.create_my_orders()
        self.assertEqual(len(offers), 1)
        self.assertEqual(offers[0]['maxsize'], maxsize)
        return yg, offers[0]

    async def test_no_new_offers(self):
        yg = await create_yg_basic([0] * 3)
        yg.offerlist = [{'oid': 0}]
        self.assertEqual(self.call_on_tx_unconfirmed(yg), ([0], []))

    async def test_no_old_offers(self):
        yg, offer = await self.create_yg_and_offer(100)
        yg.offerlist = []
        self.assertEqual(self.call_on_tx_unconfirmed(yg), ([], [offer]))

    async def test_offer_unchanged(self):
        yg, offer = await self.create_yg_and_offer(100)
        yg.offerlist = [offer]
        self.assertEqual(self.call_on_tx_unconfirmed(yg), ([], []))

    async def test_offer_changed(self):
        yg, offer = await self.create_yg_and_offer(100)
        yg.offerlist = [{'oid': 0, 'maxsize': 10}]
        self.assertEqual(self.call_on_tx_unconfirmed(yg), ([], [offer]))
