
"""
Test doing full coinjoins, bypassing IRC
"""

import os
import sys
import copy
import shutil
import tempfile

from unittest import IsolatedAsyncioTestCase

from unittest_parametrize import parametrize, ParametrizedTestCase

import jmclient  # noqa: F401 install asyncioreactor
from twisted.internet import reactor

import pytest
from _pytest.monkeypatch import MonkeyPatch

from jmbase import get_log
from jmclient import load_test_config, jm_single,\
    YieldGeneratorBasic, Taker, LegacyWallet, SegwitLegacyWallet, SegwitWallet,\
    NO_ROUNDING
from jmclient.podle import set_commitment_file
from commontest import make_wallets, default_max_cj_fee
from test_taker import dummy_filter_orderbook
import jmbitcoin as btc

pytestmark = pytest.mark.usefixtures("setup_regtest_bitcoind")

testdir = os.path.dirname(os.path.realpath(__file__))
log = get_log()

# map wallet types to offer types:
absoffer_type_map = {LegacyWallet: "absoffer",
                  SegwitLegacyWallet: "swabsoffer",
                  SegwitWallet: "sw0absoffer"}


def make_wallets_to_list(make_wallets_data):
    wallets = [None for x in range(len(make_wallets_data))]
    for i in make_wallets_data:
        wallets[i] = make_wallets_data[i]['wallet']
    assert all(wallets)
    return wallets


async def sync_wallets(wallet_services, fast=True):
    for wallet_service in wallet_services:
        wallet_service.synced = False
        wallet_service.gap_limit = 0
        for x in range(20):
            if wallet_service.synced:
                break
            await wallet_service.sync_wallet(fast=fast)
        else:
            assert False, "Failed to sync wallet"
    # because we don't run the monitoring loops for the
    # wallet services, we need to update them on the latest
    # block manually:
    for wallet_service in wallet_services:
        wallet_service.update_blockheight()


def create_orderbook(makers):
    orderbook = []
    for i in range(len(makers)):
        m = makers[i]
        assert len(m.offerlist) == 1
        m.offerlist[0]['counterparty'] = str(i)
        orderbook.extend(m.offerlist)
    return orderbook


def create_taker(wallet, schedule, monkeypatch):
    def on_finished_callback(*args, **kwargs):
        log.debug("on finished called with: {}, {}".format(args, kwargs))
        on_finished_callback.status = args[0]
        on_finished_callback.called = True
    on_finished_callback.called = False
    on_finished_callback.status = None
    taker = Taker(wallet, schedule, default_max_cj_fee,
                callbacks=(dummy_filter_orderbook, None, on_finished_callback))

    # we have skipped irc key setup and key exchange, handled by jmdaemon
    monkeypatch.setattr(taker, 'auth_counterparty', lambda *args: True)
    return taker


async def create_orders(makers):
    # fire the order creation immediately (delayed 2s in prod,
    # but this is too slow for test):
    for maker in makers:
        await maker.try_to_create_my_orders()


async def init_coinjoin(taker, makers, orderbook, cj_amount):
    init_data = await taker.initialize(orderbook, [])
    assert init_data[0], "taker.initialize error"
    active_orders = init_data[4]
    maker_data = {}
    for mid in init_data[4]:
        m = makers[int(mid)]
        # note: '00' is kphex, usually set up by jmdaemon
        response = await m.on_auth_received(
            'TAKER', init_data[4][mid], init_data[2][1:],
            init_data[3], init_data[1], '00')
        assert response[0], "maker.on_auth_received error"

        ioauth_data = list(response[1:])
        ioauth_data[0] = list(ioauth_data[0].keys())
        # maker_pk which is set up by jmdaemon
        ioauth_data.append("00")
        maker_data[mid] = ioauth_data

        # this is handled by jmdaemon
        active_orders[mid]['utxos'] = response[1]
        active_orders[mid]['cjaddr'] = ioauth_data[2]
        active_orders[mid]['changeaddr'] = ioauth_data[3]
        active_orders[mid]['offer'] = copy.deepcopy(m.offerlist[0])
        active_orders[mid]['amount'] = cj_amount
    return active_orders, maker_data


async def do_tx_signing(taker, makers, active_orders, txdata):
    taker_final_result = 'not called'
    maker_signatures = {}  # left here for easier debugging
    for mid in txdata[1]:
        m = makers[int(mid)]
        result = await m.on_tx_received('TAKER', txdata[2], active_orders[mid])
        assert result[0], "maker.on_tx_received error"
        maker_signatures[mid] = result[1]
        for sig in result[1]:
            taker_final_result = await taker.on_sig(mid, sig)

    assert taker_final_result != 'not called'
    return taker_final_result


#@pytest.mark.usefixtures("setup_cj")
class AsyncioTestCase(IsolatedAsyncioTestCase, ParametrizedTestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        load_test_config()
        jm_single().config.set('POLICY', 'tx_broadcast', 'self')
        jm_single().bc_interface.tick_forward_chain_interval = 5
        jm_single().bc_interface.simulate_blocks()
        sys._exit_ = sys.exit

    def tearDown(self):
        monkeypatch = MonkeyPatch()
        monkeypatch.setattr(sys, 'exit', sys._exit_)
        for dc in reactor.getDelayedCalls():
            dc.cancel()
        shutil.rmtree(self.tmpdir)

    @parametrize(
        'wallet_cls',
        [
            (LegacyWallet,),
            (SegwitLegacyWallet,),
            (SegwitWallet,),
        ])
    async def test_simple_coinjoin(self, wallet_cls):
        def raise_exit(i):
            raise Exception("sys.exit called")
        monkeypatch = MonkeyPatch()
        monkeypatch.setattr(sys, 'exit', raise_exit)
        commitment_file = os.path.join(self.tmpdir, 'commitments.json')
        set_commitment_file(commitment_file)

        MAKER_NUM = 3
        wallets = await make_wallets(
            MAKER_NUM + 1, wallet_structures=[[4, 0, 0, 0, 0]] * (MAKER_NUM + 1),
            mean_amt=1, wallet_cls=wallet_cls)
        wallet_services = make_wallets_to_list(wallets)

        jm_single().bc_interface.tickchain()
        jm_single().bc_interface.tickchain()

        await sync_wallets(wallet_services)

        makers = [
            YieldGeneratorBasic(
                wallet_services[i],
                [0, 2000, 0, absoffer_type_map[wallet_cls],
                 10**7, None, None, None])
            for i in range(MAKER_NUM)]
        await create_orders(makers)
        orderbook = create_orderbook(makers)
        assert len(orderbook) == MAKER_NUM

        cj_amount = int(1.1 * 10**8)
        # mixdepth, amount, counterparties, dest_addr, waittime, rounding
        schedule = [(0, cj_amount, MAKER_NUM, 'INTERNAL', 0, NO_ROUNDING)]
        taker = create_taker(wallet_services[-1], schedule, monkeypatch)

        active_orders, maker_data = await init_coinjoin(
            taker, makers, orderbook, cj_amount)

        txdata = await taker.receive_utxos(maker_data)
        assert txdata[0], "taker.receive_utxos error"

        taker_final_result = await do_tx_signing(
            taker, makers, active_orders, txdata)
        assert taker_final_result is not False
        assert taker.on_finished_callback.status is not False

    async def test_coinjoin_mixdepth_wrap_taker(self):
        def raise_exit(i):
            raise Exception("sys.exit called")
        monkeypatch = MonkeyPatch()
        monkeypatch.setattr(sys, 'exit', raise_exit)
        commitment_file = os.path.join(self.tmpdir, 'commitments.json')
        set_commitment_file(commitment_file)

        MAKER_NUM = 3
        wallets = await make_wallets(
            MAKER_NUM + 1,
            wallet_structures=[[4, 0, 0, 0, 0]] * MAKER_NUM + [[0, 0, 0, 0, 3]],
            mean_amt=1)
        wallet_services = make_wallets_to_list(wallets)

        for wallet_service in wallet_services:
            assert wallet_service.max_mixdepth == 4

        jm_single().bc_interface.tickchain()
        jm_single().bc_interface.tickchain()

        await sync_wallets(wallet_services)

        cj_fee = 2000
        makers = [
            YieldGeneratorBasic(
                wallet_services[i],
                [0, cj_fee, 0, absoffer_type_map[SegwitWallet],
                 10**7, None, None, None])
            for i in range(MAKER_NUM)]
        await create_orders(makers)
        orderbook = create_orderbook(makers)
        assert len(orderbook) == MAKER_NUM

        cj_amount = int(1.1 * 10**8)
        # mixdepth, amount, counterparties, dest_addr, waittime, rounding
        schedule = [(4, cj_amount, MAKER_NUM, 'INTERNAL', 0, NO_ROUNDING)]
        taker = create_taker(wallet_services[-1], schedule, monkeypatch)

        active_orders, maker_data = await init_coinjoin(
            taker, makers, orderbook, cj_amount)

        txdata = await taker.receive_utxos(maker_data)
        assert txdata[0], "taker.receive_utxos error"

        taker_final_result = await do_tx_signing(
            taker, makers, active_orders, txdata)
        assert taker_final_result is not False

        tx = btc.CMutableTransaction.deserialize(txdata[2])

        wallet_service = wallet_services[-1]
        # TODO change for new tx monitoring:
        await wallet_service.remove_old_utxos(tx)
        wallet_service.add_new_utxos(tx)

        balances = wallet_service.get_balance_by_mixdepth()
        assert balances[0] == cj_amount
        # <= because of tx fee
        assert balances[4] <= 3 * 10**8 - cj_amount - (cj_fee * MAKER_NUM)

    async def test_coinjoin_mixdepth_wrap_maker(self):
        def raise_exit(i):
            raise Exception("sys.exit called")
        monkeypatch = MonkeyPatch()
        monkeypatch.setattr(sys, 'exit', raise_exit)
        commitment_file = os.path.join(self.tmpdir, 'commitments.json')
        set_commitment_file(commitment_file)

        MAKER_NUM = 2
        wallets = await make_wallets(
            MAKER_NUM + 1,
            wallet_structures=[[0, 0, 0, 0, 4]] * MAKER_NUM + [[3, 0, 0, 0, 0]],
            mean_amt=1)
        wallet_services = make_wallets_to_list(wallets)

        for wallet_service in wallet_services:
            assert wallet_service.max_mixdepth == 4

        jm_single().bc_interface.tickchain()
        jm_single().bc_interface.tickchain()

        await sync_wallets(wallet_services)

        cj_fee = 2000
        makers = [
            YieldGeneratorBasic(
                wallet_services[i],
                [0, cj_fee, 0, absoffer_type_map[SegwitWallet],
                 10**7, None, None, None])
            for i in range(MAKER_NUM)]
        await create_orders(makers)
        orderbook = create_orderbook(makers)
        assert len(orderbook) == MAKER_NUM

        cj_amount = int(1.1 * 10**8)
        # mixdepth, amount, counterparties, dest_addr, waittime, rounding
        schedule = [(0, cj_amount, MAKER_NUM, 'INTERNAL', 0, NO_ROUNDING)]
        taker = create_taker(wallet_services[-1], schedule, monkeypatch)

        active_orders, maker_data = await init_coinjoin(
            taker, makers, orderbook, cj_amount)

        txdata = await taker.receive_utxos(maker_data)
        assert txdata[0], "taker.receive_utxos error"

        taker_final_result = await do_tx_signing(
            taker, makers, active_orders, txdata)
        assert taker_final_result is not False

        tx = btc.CMutableTransaction.deserialize(txdata[2])

        for i in range(MAKER_NUM):
            wallet_service = wallet_services[i]
            # TODO as above re: monitoring
            await wallet_service.remove_old_utxos(tx)
            wallet_service.add_new_utxos(tx)

            balances = wallet_service.get_balance_by_mixdepth()
            assert balances[0] == cj_amount
            assert balances[4] == 4 * 10**8 - cj_amount + cj_fee
