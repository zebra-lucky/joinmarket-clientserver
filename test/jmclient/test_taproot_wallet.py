'''Wallet functionality tests.'''
import datetime
import os
import time
import json
from binascii import hexlify, unhexlify

from unittest import IsolatedAsyncioTestCase

from unittest_parametrize import parametrize, ParametrizedTestCase

import jmclient  # noqa: F401 install asyncioreactor

import pytest
from _pytest.monkeypatch import MonkeyPatch
import jmbitcoin as btc
from commontest import ensure_bip65_activated
from jmbase import get_log, hextobin, bintohex
from jmclient import (
    load_test_config, jm_single, BaseWallet, BIP32Wallet, VolatileStorage,
    get_network, cryptoengine, WalletError, BIP49Wallet, WalletService,
    TaprootWalletFidelityBonds, create_wallet, open_test_wallet_maybe,
    open_wallet, FidelityBondMixin, LegacyWallet,
    wallet_gettimelockaddress, UnknownAddressForLabel, TaprootWallet,
    get_blockchain_interface_instance, TaprootFidelityBondWatchonlyWallet)
from test_blockchaininterface import sync_test_wallet
from freezegun import freeze_time

pytestmark = pytest.mark.usefixtures("setup_regtest_taproot_bitcoind")

testdir = os.path.dirname(os.path.realpath(__file__))

test_create_wallet_filename = "taproot_testwallet_for_create_wallet_test"
test_cache_cleared_filename = "taproot_testwallet_for_cache_clear_test"

log = get_log()


def assert_taproot(tx):
    assert (tx.has_witness()
            and tx.vout[0].scriptPubKey.is_witness_v1_taproot())


async def get_populated_wallet(amount=10**8, num=3):
    storage = VolatileStorage()
    TaprootWallet.initialize(storage, get_network())
    wallet = TaprootWallet(storage)
    await wallet.async_init(storage)

    # fund three wallet addresses at mixdepth 0
    for i in range(num):
        addr = await wallet.get_internal_addr(0)
        fund_wallet_addr(wallet, addr, amount / 10**8)

    return wallet


def fund_wallet_addr(wallet, addr, value_btc=1):
    # special case, grab_coins returns hex from rpc:
    txin_id = hextobin(jm_single().bc_interface.grab_coins(addr, value_btc))
    txinfo = jm_single().bc_interface.get_transaction(txin_id)
    txin = btc.CMutableTransaction.deserialize(btc.x(txinfo["hex"]))
    utxo_in = wallet.add_new_utxos(txin, 1)
    assert len(utxo_in) == 1
    return list(utxo_in.keys())[0]


def get_bip39_vectors():
    fh = open(os.path.join(testdir, 'bip39vectors.json'))
    data = json.load(fh)['english']
    data_with_tuples = []
    for d in data:
        data_with_tuples.append(tuple(d))
    fh.close()
    return data_with_tuples


class AsyncioTestCase(IsolatedAsyncioTestCase, ParametrizedTestCase):

    params = {
        'test_is_standard_wallet_script':
            [TaprootWallet, TaprootWalletFidelityBonds]
    }

    def setUp(self):
        load_test_config(config_path='./test_taproot')
        btc.select_chain_params("bitcoin/regtest")
        #see note in cryptoengine.py:
        cryptoengine.BTC_P2TR.VBYTE = 100
        jm_single().bc_interface.tick_forward_chain_interval = 2
        TaprootWallet._get_mixdepth_from_path_ = \
            TaprootWallet._get_mixdepth_from_path
        TaprootWallet._get_bip32_mixdepth_path_level_ = \
            TaprootWallet._get_bip32_mixdepth_path_level
        TaprootWallet._get_bip32_base_path_ = \
            TaprootWallet._get_bip32_base_path
        TaprootWallet._create_master_key_ = \
            TaprootWallet._create_master_key

    def tearDown(self):
        monkeypatch = MonkeyPatch()
        monkeypatch.setattr(TaprootWallet, '_get_mixdepth_from_path',
                            TaprootWallet._get_mixdepth_from_path_)
        monkeypatch.setattr(TaprootWallet, '_get_bip32_mixdepth_path_level',
                            TaprootWallet._get_bip32_mixdepth_path_level_)
        monkeypatch.setattr(TaprootWallet, '_get_bip32_base_path',
                            TaprootWallet._get_bip32_base_path_)
        monkeypatch.setattr(TaprootWallet, '_create_master_key',
                            TaprootWallet._create_master_key_)

        if os.path.exists(test_create_wallet_filename):
            os.remove(test_create_wallet_filename)
        if os.path.exists(test_cache_cleared_filename):
            os.remove(test_cache_cleared_filename)

    @parametrize(
        'entropy,mnemonic,key,xpriv',
        get_bip39_vectors())
    async def test_bip39_seeds(self, entropy, mnemonic, key, xpriv):
        jm_single().config.set('BLOCKCHAIN', 'network', 'mainnet')
        created_entropy = TaprootWallet.entropy_from_mnemonic(mnemonic)
        assert entropy == hexlify(created_entropy).decode('ascii')
        storage = VolatileStorage()
        TaprootWallet.initialize(
            storage, get_network(), entropy=created_entropy,
            entropy_extension='TREZOR', max_mixdepth=4)
        wallet = TaprootWallet(storage)
        await wallet.async_init(storage)
        assert (mnemonic, b'TREZOR') == wallet.get_mnemonic_words()
        assert key == hexlify(wallet._create_master_key()).decode('ascii')

        # need to monkeypatch this, else we'll default to the BIP-49 path
        monkeypatch = MonkeyPatch()
        monkeypatch.setattr(TaprootWallet, '_get_bip32_base_path',
                            BIP32Wallet._get_bip32_base_path)
        assert xpriv == wallet.get_bip32_priv_export()

    async def test_bip86_seed(self):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
        mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        master_xpriv = 'tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd'
        account0_xpriv = 'tprv8gytrHbFLhE7zLJ6BvZWEDDGJe8aS8VrmFnvqpMv8CEZtUbn2NY5KoRKQNpkcL1yniyCBRi7dAPy4kUxHkcSvd9jzLmLMEG96TPwant2jbX'
        addr0_script = '51203b82b2b2a9185315da6f80da5f06d0440d8a5e1457fa93387c2d919c86ec8786'

        entropy = TaprootWallet.entropy_from_mnemonic(mnemonic)
        storage = VolatileStorage()
        TaprootWallet.initialize(
            storage, get_network(), entropy=entropy, max_mixdepth=0)
        wallet = TaprootWallet(storage)
        await wallet.async_init(storage)
        assert (mnemonic, None) == wallet.get_mnemonic_words()
        assert account0_xpriv == wallet.get_bip32_priv_export(0)
        script = await wallet.get_external_script(0)
        assert addr0_script == hexlify(script).decode('ascii')

        # FIXME: is this desired behaviour? BIP49 wallet will not return xpriv for
        # the root key but only for key after base path
        monkeypatch = MonkeyPatch()
        monkeypatch.setattr(TaprootWallet, '_get_bip32_base_path',
                            BIP32Wallet._get_bip32_base_path)
        assert master_xpriv == wallet.get_bip32_priv_export()

    async def test_bip32_test_vector_1(self):
        jm_single().config.set('BLOCKCHAIN', 'network', 'mainnet')

        entropy = unhexlify('000102030405060708090a0b0c0d0e0f')
        storage = VolatileStorage()
        TaprootWallet.initialize(
            storage, get_network(), entropy=entropy, max_mixdepth=0)

        # test vector 1 is using hardened derivation for the account/mixdepth level
        monkeypatch = MonkeyPatch()
        monkeypatch.setattr(TaprootWallet, '_get_mixdepth_from_path',
                            BIP49Wallet._get_mixdepth_from_path)
        monkeypatch.setattr(TaprootWallet, '_get_bip32_mixdepth_path_level',
                            BIP49Wallet._get_bip32_mixdepth_path_level)
        monkeypatch.setattr(TaprootWallet, '_get_bip32_base_path',
                            BIP32Wallet._get_bip32_base_path)
        monkeypatch.setattr(TaprootWallet, '_create_master_key',
                            BIP32Wallet._create_master_key)

        wallet = TaprootWallet(storage)
        await wallet.async_init(storage)

        assert wallet.get_bip32_priv_export() == 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
        assert wallet.get_bip32_pub_export() == 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        assert wallet.get_bip32_priv_export(0) == 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'
        assert wallet.get_bip32_pub_export(0) == 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw'
        assert wallet.get_bip32_priv_export(0, 1) == 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'
        assert wallet.get_bip32_pub_export(0, 1) == 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'
        # there are more test vectors but those don't match joinmarket's wallet
        # structure, hence they make litte sense to test here

    async def test_bip32_test_vector_2(self):
        jm_single().config.set('BLOCKCHAIN', 'network', 'mainnet')

        entropy = unhexlify('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542')
        storage = VolatileStorage()
        LegacyWallet.initialize(
            storage, get_network(), entropy=entropy, max_mixdepth=0)

        monkeypatch = MonkeyPatch()
        monkeypatch.setattr(LegacyWallet, '_get_bip32_base_path',
                            BIP32Wallet._get_bip32_base_path)
        monkeypatch.setattr(LegacyWallet, '_create_master_key',
                            BIP32Wallet._create_master_key)

        wallet = LegacyWallet(storage)
        await wallet.async_init(storage)

        assert wallet.get_bip32_priv_export() == 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U'
        assert wallet.get_bip32_pub_export() == 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        assert wallet.get_bip32_priv_export(0) == 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'
        assert wallet.get_bip32_pub_export(0) == 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'
        # there are more test vectors but those don't match joinmarket's wallet
        # structure, hence they make litte sense to test here

    async def test_bip32_test_vector_3(self):
        jm_single().config.set('BLOCKCHAIN', 'network', 'mainnet')

        entropy = unhexlify('4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be')
        storage = VolatileStorage()
        TaprootWallet.initialize(
            storage, get_network(), entropy=entropy, max_mixdepth=0)

        # test vector 3 is using hardened derivation for the account/mixdepth level
        monkeypatch = MonkeyPatch()
        monkeypatch.setattr(TaprootWallet, '_get_mixdepth_from_path',
                            BIP49Wallet._get_mixdepth_from_path)
        monkeypatch.setattr(TaprootWallet, '_get_bip32_mixdepth_path_level',
                            BIP49Wallet._get_bip32_mixdepth_path_level)
        monkeypatch.setattr(TaprootWallet, '_get_bip32_base_path',
                            BIP32Wallet._get_bip32_base_path)
        monkeypatch.setattr(TaprootWallet, '_create_master_key',
                            BIP32Wallet._create_master_key)

        wallet = TaprootWallet(storage)
        await wallet.async_init(storage)

        assert wallet.get_bip32_priv_export() == 'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6'
        assert wallet.get_bip32_pub_export() == 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13'
        assert wallet.get_bip32_priv_export(0) == 'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L'
        assert wallet.get_bip32_pub_export(0) == 'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y'

    @parametrize(
        'mixdepth,internal,index,address,wif',
        [
            (0, BaseWallet.ADDRESS_TYPE_EXTERNAL, 0,
             'bcrt1pwr88j8y5hs57fktnlxvs8ynzpx2v78vcn3z2wjq3gxjhec8naedsenq84j',
             'cUYX9yfrAnbm7LyjiaYUjVAp83pD6WMffaQNyKUf6ubUuFUcwWGx'),
            (0, BaseWallet.ADDRESS_TYPE_EXTERNAL, 5,
             'bcrt1pj9y406c0fwtsj6ntnnpzkwzq3tmsa3t9n6rcwelut8cs48a8sp7qmfylrx',
             'cUxhCGWR7DddkKthD2zFf22RLJzQQfPeMvPxQHfYaPNwQy1fB7TH'),
            (0, BaseWallet.ADDRESS_TYPE_INTERNAL, 3,
             'bcrt1plajm8x83lekgnvhkxtm5jehmsvlkdfefnxln7lpka0psgk0vn8nqjhgrhn',
             'cTwM3mu54nJt2DJ51RfJxHAivVUdazNW7nXgwaejHfg86Xd6NHe9'),
            (2, BaseWallet.ADDRESS_TYPE_INTERNAL, 2,
             'bcrt1pgfhvh4f699qujwnmd9kylv86uf5shc3ecz0ggvte0rza7rejhvwqz3mnal',
             'cPx3oVxi2Frn54n4uFTpfTEbqpgPpqC7RMrcCbUCSNSv1Y9RyLUA')
        ])
    async def test_bip32_addresses_p2tr(self, mixdepth,
                                        internal, index, address, wif):
        """
        Test with a random but fixed entropy
        """
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')

        entropy = unhexlify('2e0339ba89b4a1272cdf78b27ee62669ee01992a59e836e2807051be128ca817')
        storage = VolatileStorage()
        TaprootWallet.initialize(
            storage, get_network(), entropy=entropy, max_mixdepth=3)

        monkeypatch = MonkeyPatch()
        monkeypatch.setattr(TaprootWallet, '_get_bip32_base_path',
                            BIP32Wallet._get_bip32_base_path)
        monkeypatch.setattr(TaprootWallet, '_create_master_key',
                            BIP32Wallet._create_master_key)

        wallet = TaprootWallet(storage)
        await wallet.async_init(storage)

        # wallet needs to know about all intermediate keys
        for i in range(index + 1):
            await wallet.get_new_script(mixdepth, internal)

        assert wif == wallet.get_wif(mixdepth, internal, index)
        assert address == await wallet.get_addr(mixdepth, internal, index)

    @parametrize(
        'timenumber,address,wif',
        [
            (0,
             'bcrt1qj9ewr9kq0043dj90l9w28znydtzcmqgeqs3gua8c2ph6aj5v2d5s459kxa',
              'cW5MjSamNpGVqwd1xMdUa6bHBdkKxCb8QovCrm44juAAfD6N64Ud'),
            (50,
             'bcrt1qjsnz39xvguzxjnydg89zkx25rv2sdnlsa9q6q0s0rkk925xru5mqn6en8c',
             'cVXG11bFA6fiey2nAgBwNe7Y4cL1ZqLJ5uYtDiJsXoUV91phNk8n'),
            (1,
            'bcrt1q249qewynmkhyqzplrezg0xjcughgguzgh7wznagewwxpq3838r9sfw2yks',
            'cTGBzJXiSsTArDFNtpyAgDRuumBK4Gj7S6RjuVYiLHytnLNgHGTw')
        ])
    async def test_bip32_timelocked_addresses(self, timenumber,
                                              address, wif):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')

        entropy = unhexlify('2e0339ba89b4a1272cdf78b27ee62669ee01992a59e836e2807051be128ca817')
        storage = VolatileStorage()
        TaprootWalletFidelityBonds.initialize(
            storage, get_network(), entropy=entropy, max_mixdepth=1)
        wallet = TaprootWalletFidelityBonds(storage)
        await wallet.async_init(storage)
        mixdepth = FidelityBondMixin.FIDELITY_BOND_MIXDEPTH
        address_type = FidelityBondMixin.BIP32_TIMELOCK_ID

        assert address == await wallet.get_addr(
            mixdepth, address_type, timenumber)
        assert wif == wallet.get_wif_path(
            wallet.get_path(mixdepth, address_type, timenumber))

    @parametrize(
        'timenumber,locktime_string',
        [
            (0, "2020-01"),
            (20, "2021-09"),
            (100, "2028-05"),
            (150, "2032-07"),
            (350, "2049-03")
        ])
    @freeze_time("2019-12")
    async def test_gettimelockaddress_method(self,
                                             timenumber, locktime_string):
        jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
        storage = VolatileStorage()
        TaprootWalletFidelityBonds.initialize(storage, get_network())
        wallet = TaprootWalletFidelityBonds(storage)
        await wallet.async_init(storage)

        m = FidelityBondMixin.FIDELITY_BOND_MIXDEPTH
        address_type = FidelityBondMixin.BIP32_TIMELOCK_ID
        script = await wallet.get_script(m, address_type, timenumber)
        addr = await wallet.script_to_addr(script)

        addr_from_method = await wallet_gettimelockaddress(
            wallet, locktime_string)

        assert addr == addr_from_method

    @freeze_time("2021-01")
    async def test_gettimelockaddress_in_past(self):
        jm_single().config.set("BLOCKCHAIN", "network", "mainnet")
        storage = VolatileStorage()
        TaprootWalletFidelityBonds.initialize(storage, get_network())
        wallet = TaprootWalletFidelityBonds(storage)
        await wallet.async_init(storage)

        assert await wallet_gettimelockaddress(wallet, "2020-01") == ""
        assert await wallet_gettimelockaddress(wallet, "2021-01") == ""
        assert await wallet_gettimelockaddress(wallet, "2021-02") != ""

    @parametrize(
        'index,wif',
        [
            (0, 'cU3iQ73p1mYyJ9aDY4VahGFG8cqK3QAW3VeSiStEXm1sBiFgdiSJ'),
            (9, 'cT2X1VVE48NfAiuPzgsc8ogJ19cXWV17S4AkUgzWD61jEd6ZtezZ'),
            (50, 'cQrqAeoSVFHUM2wkt11YkCUc3erkVkhr2KaxrbqxKtuA8ztt2qCr')
        ])
    async def test_bip32_burn_keys(self, index, wif):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')

        entropy = unhexlify('2e0339ba89b4a1272cdf78b27ee62669ee01992a59e836e2807051be128ca817')
        storage = VolatileStorage()
        TaprootWalletFidelityBonds.initialize(
            storage, get_network(), entropy=entropy, max_mixdepth=1)
        wallet = TaprootWalletFidelityBonds(storage)
        await wallet.async_init(storage)
        mixdepth = FidelityBondMixin.FIDELITY_BOND_MIXDEPTH
        address_type = FidelityBondMixin.BIP32_BURN_ID

        #advance index_cache enough
        wallet.set_next_index(mixdepth, address_type, index, force=True)

        assert wif == wallet.get_wif_path(
            wallet.get_path(mixdepth, address_type, index))

    async def test_import_key(self):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
        storage = VolatileStorage()
        TaprootWallet.initialize(storage, get_network())
        wallet = TaprootWallet(storage)
        await wallet.async_init(storage)

        await wallet.import_private_key(
            0, 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM')
        await wallet.import_private_key(
            1, 'cVqtSSoVxFyPqTRGfeESi31uCYfgTF4tGWRtGeVs84fzybiX5TPk')

        with pytest.raises(WalletError):
            await wallet.import_private_key(
                1, 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM')

        # test persist imported keys
        wallet.save()
        data = storage.file_data

        del wallet
        del storage

        storage = VolatileStorage(data=data)
        wallet = TaprootWallet(storage)
        await wallet.async_init(storage)

        imported_paths_md0 = list(wallet.yield_imported_paths(0))
        imported_paths_md1 = list(wallet.yield_imported_paths(1))
        assert len(imported_paths_md0) == 1
        assert len(imported_paths_md1) == 1

        # verify imported addresses
        assert await wallet.get_address_from_path(imported_paths_md0[0]) == \
            'bcrt1p3e8d2nwlpf6rm0q36auq736cpj5y5uw337kf2nj9yn9tkg48n9dq5zgmdq'
        assert await wallet.get_address_from_path(imported_paths_md1[0]) == \
            'bcrt1ph8wfv0zm42lgvd23xe2070khe285grmum6fm8ehv7e2zkpnvcs6qjjm7nr'

        # test remove key
        await wallet.remove_imported_key(path=imported_paths_md0[0])
        assert not list(wallet.yield_imported_paths(0))

        assert wallet.get_details(imported_paths_md1[0]) == (1, 'imported', 0)

    @parametrize(
        'wif, type_check',
        [
            ('cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM',
             assert_taproot)
        ])
    async def test_signing_imported(self, wif, type_check):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
        storage = VolatileStorage()
        TaprootWallet.initialize(storage, get_network())
        wallet = TaprootWallet(storage)
        await wallet.async_init(storage)

        MIXDEPTH = 0
        path = await wallet.import_private_key(MIXDEPTH, wif)
        addr = await wallet.get_address_from_path(path)
        utxo = fund_wallet_addr(wallet, addr)
        # The dummy output is constructed as an unspendable p2sh:
        p2tr_script = btc.CScript(bytes.fromhex('5120' + '00'*32))
        tx = btc.mktx([utxo],
                    [{"address":
                        str(btc.CCoinAddress.from_scriptPubKey(p2tr_script)),
                      "value": 10**8 - 9000}])
        script = await wallet.get_script_from_path(path)
        success, msg = await wallet.sign_tx(tx, {0: (script, 10**8)})
        assert success, msg
        type_check(tx)
        txout = jm_single().bc_interface.pushtx(tx.serialize())
        assert txout

    @parametrize(
        'wallet_cls,type_check',
        [
            (TaprootWallet, assert_taproot),
        ])
    async def test_signing_simple(self, wallet_cls, type_check):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
        storage = VolatileStorage()
        wallet_cls.initialize(storage, get_network(), entropy=b"\xaa"*16)
        wallet = wallet_cls(storage)
        await wallet.async_init(storage)
        addr = await wallet.get_internal_addr(0)
        utxo = fund_wallet_addr(wallet, addr)
        path = "m/86'/1'/0'/0/0"
        privkey, engine = wallet._get_key_from_path(
            wallet.path_repr_to_path(path))
        pubkey = engine.privkey_to_pubkey(privkey)
        tx = btc.mktx([utxo],
                      [{"address": str(btc.CCoinAddress.from_scriptPubKey(
                            btc.pubkey_to_p2tr_script(pubkey))),
                        "value": 10**8 - 9000}])
        script = await wallet.get_script(
            0, BaseWallet.ADDRESS_TYPE_INTERNAL, 0)
        success, msg = await wallet.sign_tx(tx, {0: (script, 10**8)})
        assert success, msg
        type_check(tx)
        txout = jm_single().bc_interface.pushtx(tx.serialize())
        assert txout

    # note that address validation is tested separately;
    # this test functions only to make sure that given a valid
    # taproot address, we can actually spend to it
    @parametrize(
        'hexspk',
        [
            ("512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",),
            ("5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",),
            ("5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",),
        ])
    async def test_spend_to_p2traddr(self, hexspk):
        storage = VolatileStorage()
        TaprootWallet.initialize(storage, get_network(), entropy=b"\xaa"*16)
        wallet = TaprootWallet(storage)
        await wallet.async_init(storage)
        addr = await wallet.get_internal_addr(0)
        utxo = fund_wallet_addr(wallet, addr)
        sPK = btc.CScript(hextobin(hexspk))
        tx = btc.mktx(
            [utxo],
            [{"address": str(btc.CCoinAddress.from_scriptPubKey(sPK)),
            "value": 10**8 - 9000}])
        script = await wallet.get_script(
            0, BaseWallet.ADDRESS_TYPE_INTERNAL, 0)
        success, msg = await wallet.sign_tx(tx, {0: (script, 10**8)})
        assert success, msg
        txout = jm_single().bc_interface.pushtx(tx.serialize())
        assert txout
        # probably unnecessary, but since we are sanity checking:
        # does the output of the in-mempool tx have the sPK we expect?
        txid = tx.GetTxid()[::-1]
        txres = btc.CTransaction.deserialize(hextobin(jm_single().bc_interface._rpc(
            "getrawtransaction", [bintohex(txid), True])["hex"]))
        assert txres.vout[0].scriptPubKey == sPK
        assert txres.vout[0].nValue == 10**8 - 9000

    async def test_timelocked_output_signing(self):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
        ensure_bip65_activated()
        storage = VolatileStorage()
        TaprootWalletFidelityBonds.initialize(storage, get_network())
        wallet = TaprootWalletFidelityBonds(storage)
        await wallet.async_init(storage)

        timenumber = 0
        script = await wallet.get_script(
            FidelityBondMixin.FIDELITY_BOND_MIXDEPTH,
            FidelityBondMixin.BIP32_TIMELOCK_ID, timenumber)
        utxo = fund_wallet_addr(wallet, await wallet.script_to_addr(script))
        timestamp = wallet._time_number_to_timestamp(timenumber)

        tx = btc.mktx([utxo], [{
            "address": str(btc.CCoinAddress.from_scriptPubKey(
                btc.standard_scripthash_scriptpubkey(btc.Hash160(b"\x00")))),
            "value":10**8 - 9000}], locktime=timestamp+1)
        success, msg = await wallet.sign_tx(tx, {0: (script, 10**8)})
        assert success, msg
        txout = jm_single().bc_interface.pushtx(tx.serialize())
        assert txout

    async def test_get_bbm(self):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
        amount = 10**8
        num_tx = 3
        wallet = await get_populated_wallet(amount, num_tx)
        # disable a utxo and check we can correctly report
        # balance with the disabled flag off:
        utxos = await wallet._utxos.get_utxos_at_mixdepth(0)
        utxo_1 = list(utxos.keys())[0]
        wallet.disable_utxo(*utxo_1)
        balances = wallet.get_balance_by_mixdepth(include_disabled=True)
        assert balances[0] == num_tx * amount
        balances = wallet.get_balance_by_mixdepth()
        assert balances[0] == (num_tx - 1) * amount
        wallet.toggle_disable_utxo(*utxo_1)
        balances = wallet.get_balance_by_mixdepth()
        assert balances[0] == num_tx * amount

    async def test_add_utxos(self):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
        amount = 10**8
        num_tx = 3

        wallet =  await get_populated_wallet(amount, num_tx)

        balances = wallet.get_balance_by_mixdepth()
        assert balances[0] == num_tx * amount
        for md in range(1, wallet.max_mixdepth + 1):
            assert balances[md] == 0

        utxos = await wallet.get_utxos_by_mixdepth()
        assert len(utxos[0]) == num_tx
        for md in range(1, wallet.max_mixdepth + 1):
            assert not utxos[md]

        with pytest.raises(Exception):
            # no funds in mixdepth
            await wallet.select_utxos(1, amount)

        with pytest.raises(Exception):
            # not enough funds
            await wallet.select_utxos(0, amount * (num_tx + 1))

        wallet.reset_utxos()
        assert wallet.get_balance_by_mixdepth()[0] == 0

    async def test_select_utxos(self):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
        amount = 10**8

        wallet =  await get_populated_wallet(amount)
        utxos = await wallet.select_utxos(0, amount // 2)

        assert len(utxos) == 1
        utxos = list(utxos.keys())

        more_utxos = await wallet.select_utxos(
            0, int(amount * 1.5), utxo_filter=utxos)
        assert len(more_utxos) == 2
        assert utxos[0] not in more_utxos

    async def test_add_new_utxos(self):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
        wallet =  await get_populated_wallet(num=1)

        scripts = [(await wallet.get_new_script(
                        x, BaseWallet.ADDRESS_TYPE_INTERNAL))
                   for x in range(3)]
        tx_scripts = list(scripts)
        tx = btc.mktx(
                [(b"\x00"*32, 2)],
                [{"address": await wallet.script_to_addr(s),
                  "value": 10**8} for s in tx_scripts])
        added = wallet.add_new_utxos(tx, 1)
        assert len(added) == len(scripts)

        added_scripts = {x['script'] for x in added.values()}
        for s in scripts:
            assert s in added_scripts

        balances = wallet.get_balance_by_mixdepth()
        assert balances[0] == 2 * 10**8
        assert balances[1] == 10**8
        assert balances[2] == 10**8
        assert len(balances) == wallet.max_mixdepth + 1

    async def test_remove_old_utxos(self):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
        wallet =  await get_populated_wallet()

        # add some more utxos to mixdepth 1
        for i in range(3):
            addr = await wallet.get_internal_addr(1)
            txin = jm_single().bc_interface.grab_coins(addr, 1)
            script = await wallet.get_script(
                1, BaseWallet.ADDRESS_TYPE_INTERNAL, i)
            wallet.add_utxo(btc.x(txin), 0, script, 10**8, 1)

        inputs = await wallet.select_utxos(0, 10**8)
        inputs.update(await wallet.select_utxos(1, 2 * 10**8))
        assert len(inputs) == 3

        tx_inputs = list(inputs.keys())
        tx_inputs.append((b'\x12'*32, 6))

        tx = btc.mktx(tx_inputs,
            [{"address": "2N9gfkUsFW7Kkb1Eurue7NzUxUt7aNJiS1U",
              "value": 3 * 10**8 - 1000}])

        removed = await wallet.remove_old_utxos(tx)
        assert len(removed) == len(inputs)

        for txid in removed:
            assert txid in inputs

        balances = wallet.get_balance_by_mixdepth()
        assert balances[0] == 2 * 10**8
        assert balances[1] == 10**8
        assert balances[2] == 0
        assert len(balances) == wallet.max_mixdepth + 1

    async def test_address_labels(self):
        wallet = await get_populated_wallet(num=2)
        addr1 = await wallet.get_internal_addr(0)
        addr2 = await wallet.get_internal_addr(1)
        assert wallet.get_address_label(addr2) is None
        assert wallet.get_address_label(addr2) is None
        wallet.set_address_label(addr1, "test")
        # utf-8 characters here are on purpose, to test utf-8 encoding / decoding
        wallet.set_address_label(addr2, "glāžšķūņu rūķīši")
        assert wallet.get_address_label(addr1) == "test"
        assert wallet.get_address_label(addr2) == "glāžšķūņu rūķīši"
        wallet.set_address_label(addr1, "")
        wallet.set_address_label(addr2, None)
        assert wallet.get_address_label(addr2) is None
        assert wallet.get_address_label(addr2) is None
        with pytest.raises(UnknownAddressForLabel):
            wallet.get_address_label("2MzY5yyonUY7zpHspg7jB7WQs1uJxKafQe4")
            wallet.set_address_label("2MzY5yyonUY7zpHspg7jB7WQs1uJxKafQe4",
                "test")
            # we no longer decode addresses just to see if we know about them,
            # so we won't get a CCoinAddressError for invalid addresses
            #with pytest.raises(CCoinAddressError):
            wallet.get_address_label("badaddress")
            wallet.set_address_label("badaddress", "test")

    async def test_initialize_twice(self):
        wallet =  await get_populated_wallet(num=0)
        storage = wallet._storage
        with pytest.raises(WalletError):
            TaprootWallet.initialize(storage, get_network())

    async def test_is_known(self):
        wallet =  await get_populated_wallet(num=0)
        script = await wallet.get_new_script(
            1, BaseWallet.ADDRESS_TYPE_INTERNAL)
        addr = await wallet.get_external_addr(2)

        assert wallet.is_known_script(script)
        assert wallet.is_known_addr(addr)
        assert wallet.is_known_addr(await wallet.script_to_addr(script))
        assert wallet.is_known_script(wallet.addr_to_script(addr))

        assert not wallet.is_known_script(b'\x12' * len(script))
        assert not wallet.is_known_addr('2MzY5yyonUY7zpHspg7jB7WQs1uJxKafQe4')

    async def test_wallet_save(self):
        wallet =  await get_populated_wallet()

        script = await wallet.get_external_script(1)

        wallet.save()
        storage = wallet._storage
        data = storage.file_data

        del wallet
        del storage

        storage = VolatileStorage(data=data)
        wallet = TaprootWallet(storage)
        await wallet.async_init(storage)

        assert wallet.get_next_unused_index(0, BaseWallet.ADDRESS_TYPE_INTERNAL) == 3
        assert wallet.get_next_unused_index(0, BaseWallet.ADDRESS_TYPE_EXTERNAL) == 0
        assert wallet.get_next_unused_index(1, BaseWallet.ADDRESS_TYPE_INTERNAL) == 0
        assert wallet.get_next_unused_index(1, BaseWallet.ADDRESS_TYPE_EXTERNAL) == 1
        assert wallet.is_known_script(script)

    async def test_set_next_index(self):
        wallet =  await get_populated_wallet()

        assert wallet.get_next_unused_index(0,
                    BaseWallet.ADDRESS_TYPE_INTERNAL) == 3

        with pytest.raises(Exception):
            # cannot advance index without force=True
            wallet.set_next_index(0, BaseWallet.ADDRESS_TYPE_INTERNAL, 5)

        wallet.set_next_index(0, BaseWallet.ADDRESS_TYPE_INTERNAL, 1)
        assert wallet.get_next_unused_index(0, BaseWallet.ADDRESS_TYPE_INTERNAL) == 1

        wallet.set_next_index(0, BaseWallet.ADDRESS_TYPE_INTERNAL, 20, force=True)
        assert wallet.get_next_unused_index(0, BaseWallet.ADDRESS_TYPE_INTERNAL) == 20

        script = await wallet.get_new_script(
            0, BaseWallet.ADDRESS_TYPE_INTERNAL)
        path = wallet.script_to_path(script)
        index = wallet.get_details(path)[2]
        assert index == 20

    async def test_path_repr(self):
        wallet =  await get_populated_wallet()
        path = wallet.get_path(2, BIP32Wallet.ADDRESS_TYPE_EXTERNAL, 0)
        path_repr = wallet.get_path_repr(path)
        path_new = wallet.path_repr_to_path(path_repr)

        assert path_new == path

    async def test_path_repr_imported(self):
        wallet =  await get_populated_wallet(num=0)
        path = await wallet.import_private_key(
            0, 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM')
        path_repr = wallet.get_path_repr(path)
        path_new = wallet.path_repr_to_path(path_repr)

        assert path_new == path

    async def test_wrong_wallet_cls(self):
        storage = VolatileStorage()
        TaprootWallet.initialize(storage, get_network())
        wallet = TaprootWallet(storage)
        await wallet.async_init(storage)

        wallet.save()
        data = storage.file_data

        del wallet
        del storage

        storage = VolatileStorage(data=data)

        with pytest.raises(Exception):
            wallet = LegacyWallet(storage)
            await wallet.async_init(storage)

    async def test_wallet_id(self):
        storage1 = VolatileStorage()
        TaprootWallet.initialize(storage1, get_network())
        wallet1 = TaprootWallet(storage1)
        await wallet1.async_init(storage1)

        storage2 = VolatileStorage()
        LegacyWallet.initialize(storage2, get_network(),
                                entropy=wallet1._entropy)
        wallet2 = LegacyWallet(storage2)
        await wallet2.async_init(storage2)

        assert wallet1.get_wallet_id() != wallet2.get_wallet_id()

        storage2 = VolatileStorage()
        TaprootWallet.initialize(storage2, get_network(),
                                      entropy=wallet1._entropy)
        wallet2 = TaprootWallet(storage2)
        await wallet2.async_init(storage2)

        assert wallet1.get_wallet_id() == wallet2.get_wallet_id()

    async def test_cache_cleared(self):
        orig_bc_interface = jm_single().bc_interface

        def place_back_bc_interface():
            jm_single().bc_interface = orig_bc_interface

        self.addCleanup(place_back_bc_interface)
        time_ms = int(time.time() * 1000)
        jm_single().bc_interface = get_blockchain_interface_instance(
            jm_single().config,
            rpc_wallet_name=f'jm-test-taproot-wallet-noprivkeys-{time_ms}')
        # test plan:
        # 1. create a new wallet and sync from scratch
        # 2. read its cache as an object
        # 3. close the wallet, reopen it, sync it.
        # 4. corrupt its cache and save.
        # 5. Re open the wallet with recoversync
        #    and check that the corrupted data is not present.
        if os.path.exists(test_cache_cleared_filename):
            os.remove(test_cache_cleared_filename)
        wallet = await create_wallet(test_cache_cleared_filename,
                                     b"hunter2", 2, TaprootWallet)
        # note: we use the WalletService as an encapsulation
        # of the wallet here because we want to be able to sync,
        # but we do not actually start the service and go into
        # the monitoring loop.
        wallet_service = WalletService(wallet)
        # default fast sync, no coins, so no loop
        await wallet_service.sync_wallet()
        wallet_service.update_blockheight()
        # to get the cache to save, we need to
        # use an address:
        addr = await wallet_service.get_new_addr(0,0)
        orig_bc_interface.grab_coins(addr, 1.0)
        await wallet_service.transaction_monitor()
        path_to_corrupt = list(wallet._cache.keys())[0]
        # we'll just corrupt the first address and script:
        entry_to_corrupt = wallet._cache[path_to_corrupt][b"86'"][b"1'"][b"0'"][b'0'][b'0']
        entry_to_corrupt[b'A'] = "notanaddress"
        entry_to_corrupt[b'S'] = "notascript"
        wallet_service.wallet.save()
        wallet_service.wallet.close()
        jm_single().config.set("POLICY", "wallet_caching_disabled", "true")
        wallet2 = await open_wallet(test_cache_cleared_filename,
                                    ask_for_password=False,
                                    password=b"hunter2")
        jm_single().config.set("POLICY", "wallet_caching_disabled", "false")
        wallet_service2 = WalletService(wallet2)
        while not wallet_service2.synced:
            await wallet_service2.sync_wallet(fast=False)
        await wallet_service.transaction_monitor()
        # we ignored the corrupt cache?
        assert wallet_service2.get_balance_at_mixdepth(0) == 10 ** 8

    async def test_addr_script_conversion(self):
        wallet =  await get_populated_wallet(num=1)

        path = wallet.get_path(0, BaseWallet.ADDRESS_TYPE_INTERNAL, 0)
        script = await wallet.get_script_from_path(path)
        addr = await wallet.script_to_addr(script)

        assert script == wallet.addr_to_script(addr)
        addr_path = wallet.addr_to_path(addr)
        assert path == addr_path

    async def test_imported_key_removed(self):
        wif = 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM'

        storage = VolatileStorage()
        TaprootWallet.initialize(storage, get_network())
        wallet = TaprootWallet(storage)
        await wallet.async_init(storage)

        path = await wallet.import_private_key(1, wif)
        script = await wallet.get_script_from_path(path)
        assert wallet.is_known_script(script)

        await wallet.remove_imported_key(path=path)
        assert not wallet.is_known_script(script)

        with pytest.raises(WalletError):
            await wallet.get_script_from_path(path)

    async def test_wallet_mixdepth_simple(self):
        wallet =  await get_populated_wallet(num=0)
        mixdepth = wallet.mixdepth
        assert wallet.max_mixdepth == mixdepth

        wallet.close()
        storage_data = wallet._storage.file_data

        storage = VolatileStorage(data=storage_data)
        new_wallet = type(wallet)(storage)
        await new_wallet.async_init(storage)
        assert new_wallet.mixdepth == mixdepth
        assert new_wallet.max_mixdepth == mixdepth

    async def test_wallet_mixdepth_increase(self):
        wallet =  await get_populated_wallet(num=0)
        mixdepth = wallet.mixdepth

        wallet.close()
        storage_data = wallet._storage.file_data

        new_mixdepth = mixdepth + 2
        storage = VolatileStorage(data=storage_data)
        new_wallet = type(wallet)(storage, mixdepth=new_mixdepth)
        await new_wallet.async_init(storage, mixdepth=new_mixdepth)
        assert new_wallet.mixdepth == new_mixdepth
        assert new_wallet.max_mixdepth == new_mixdepth

    async def test_wallet_mixdepth_decrease(self):
        wallet =  await get_populated_wallet(num=1)

        # setup
        max_mixdepth = wallet.max_mixdepth
        assert max_mixdepth >= 1, "bad default value for mixdepth for this test"
        addr = await wallet.get_internal_addr(max_mixdepth)
        utxo = fund_wallet_addr(wallet, addr, 1)
        bci = jm_single().bc_interface
        unspent_list = bci.listunspent(0)
        # filter on label, but note (a) in certain circumstances (in-
        # wallet transfer) it is possible for the utxo to be labeled
        # with the external label, and (b) the wallet will know if it
        # belongs or not anyway (is_known_addr):
        our_unspent_list = [x for x in unspent_list if (
            bci.is_address_labeled(x, wallet.get_wallet_name()))]
        assert wallet.get_balance_by_mixdepth()[max_mixdepth] == 10**8
        wallet.close()
        storage_data = wallet._storage.file_data

        # actual test
        orig_bc_interface = jm_single().bc_interface

        def place_back_bc_interface():
            jm_single().bc_interface = orig_bc_interface

        self.addCleanup(place_back_bc_interface)
        time_ms = int(time.time() * 1000)
        jm_single().bc_interface = get_blockchain_interface_instance(
            jm_single().config,
            rpc_wallet_name=f'jm-test-taproot-wallet-noprivkeys-{time_ms}')

        new_mixdepth = max_mixdepth - 1
        storage = VolatileStorage(data=storage_data)
        new_wallet = type(wallet)(storage, mixdepth=new_mixdepth)
        await new_wallet.async_init(storage, mixdepth=new_mixdepth)
        assert new_wallet.max_mixdepth == max_mixdepth
        assert new_wallet.mixdepth == new_mixdepth
        await sync_test_wallet(True, WalletService(new_wallet))

        assert max_mixdepth not in new_wallet.get_balance_by_mixdepth()
        assert max_mixdepth not in await new_wallet.get_utxos_by_mixdepth()

        # wallet.select_utxos will still return utxos from higher mixdepths
        # because we explicitly ask for a specific mixdepth
        assert utxo in await new_wallet.select_utxos(max_mixdepth, 10**7)

    async def test_watchonly_wallet(self):
        jm_single().config.set('BLOCKCHAIN', 'network', 'testnet')
        storage = VolatileStorage()
        TaprootWalletFidelityBonds.initialize(storage, get_network())
        wallet = TaprootWalletFidelityBonds(storage)
        await wallet.async_init(storage)

        paths = [
            "m/86'/1'/0'/0/0",
            "m/86'/1'/0'/1/0",
            "m/86'/1'/0'/2/0:1577836800",
            "m/86'/1'/0'/2/0:2314051200"
        ]
        burn_path = "m/49'/1'/0'/3/0"

        scripts = [
            await wallet.get_script_from_path(wallet.path_repr_to_path(path))
            for path in paths]
        privkey, engine = wallet._get_key_from_path(
            wallet.path_repr_to_path(burn_path))
        burn_pubkey = engine.privkey_to_pubkey(privkey)

        master_pub_key = wallet.get_bip32_pub_export(
            FidelityBondMixin.FIDELITY_BOND_MIXDEPTH)
        watchonly_storage = VolatileStorage()
        entropy = FidelityBondMixin.get_xpub_from_fidelity_bond_master_pub_key(
            master_pub_key).encode()
        TaprootFidelityBondWatchonlyWallet.initialize(
            watchonly_storage, get_network(), entropy=entropy)
        watchonly_wallet = TaprootFidelityBondWatchonlyWallet(
            watchonly_storage)
        await watchonly_wallet.async_init(watchonly_storage)

        watchonly_scripts = [
            await watchonly_wallet.get_script_from_path(
            watchonly_wallet.path_repr_to_path(path)) for path in paths]
        privkey, engine = wallet._get_key_from_path(wallet.path_repr_to_path(burn_path))
        watchonly_burn_pubkey = engine.privkey_to_pubkey(privkey)

        for script, watchonly_script in zip(scripts, watchonly_scripts):
            assert script == watchonly_script
        assert burn_pubkey == watchonly_burn_pubkey

    async def test_calculate_timelocked_fidelity_bond_value(self):
        EPSILON = 0.000001
        YEAR = 60*60*24*356.25

        # the function should be flat anywhere before the locktime ends
        values = [FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
            utxo_value=100000000,
            confirmation_time=0,
            locktime=6*YEAR,
            current_time=y*YEAR,
            interest_rate=0.01
            )
            for y in range(4)
        ]
        value_diff = [values[i] - values[i+1] for i in range(len(values)-1)]
        for vd in value_diff:
            assert abs(vd) < EPSILON

        # after locktime, the value should go down
        values = [FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
            utxo_value=100000000,
            confirmation_time=0,
            locktime=6*YEAR,
            current_time=(6+y)*YEAR,
            interest_rate=0.01
            )
            for y in range(5)
        ]
        value_diff = [values[i+1] - values[i] for i in range(len(values)-1)]
        for vrd in value_diff:
            assert vrd < 0

        # value of a bond goes up as the locktime goes up
        values = [FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
            utxo_value=100000000,
            confirmation_time=0,
            locktime=y*YEAR,
            current_time=0,
            interest_rate=0.01
            )
            for y in range(5)
        ]
        value_ratio = [values[i] / values[i+1] for i in range(len(values)-1)]
        value_ratio_diff = [value_ratio[i] - value_ratio[i+1]
                            for i in range(len(value_ratio)-1)]
        for vrd in value_ratio_diff:
            assert vrd < 0

        # value of a bond locked into the far future is constant,
        # clamped at the value of burned coins
        values = [FidelityBondMixin.calculate_timelocked_fidelity_bond_value(
            utxo_value=100000000,
            confirmation_time=0,
            locktime=(200+y)*YEAR,
            current_time=0,
            interest_rate=0.01
            )
            for y in range(5)
        ]
        value_diff = [values[i] - values[i+1] for i in range(len(values)-1)]
        for vd in value_diff:
            assert abs(vd) < EPSILON

    @parametrize(
        'password, wallet_cls',
        [
            ("hunter2", TaprootWallet),
        ])
    async def test_create_wallet(self, password, wallet_cls):
        wallet_name = test_create_wallet_filename
        password = password.encode("utf-8")
        # test mainnet (we are not transacting)
        btc.select_chain_params("bitcoin")
        wallet = await create_wallet(wallet_name, password, 4, wallet_cls)
        mnemonic = wallet.get_mnemonic_words()[0]
        addr = await wallet.get_addr(0,0,0)
        firstkey = wallet.get_key_from_addr(addr)
        print("Created mnemonic, firstkey: ", mnemonic, firstkey)
        wallet.close()
        # ensure that the wallet file created is openable with the password,
        # and has the parameters that were claimed on creation:
        new_wallet = await open_test_wallet_maybe(
            wallet_name, "", 4, password=password, ask_for_password=False)
        assert new_wallet.get_mnemonic_words()[0] == mnemonic
        addr = await new_wallet.get_addr(0,0,0)
        assert new_wallet.get_key_from_addr(addr) == firstkey
        os.remove(wallet_name)
        btc.select_chain_params("bitcoin/regtest")

    @parametrize(
        'wallet_cls',
        [
            (TaprootWallet,),
            (TaprootWalletFidelityBonds,)
        ])
    async def test_is_standard_wallet_script(self, wallet_cls):
        storage = VolatileStorage()
        wallet_cls.initialize(
            storage, get_network(), max_mixdepth=0)
        wallet = wallet_cls(storage)
        await wallet.async_init(storage)
        script = await wallet.get_new_script(0, 1)
        assert wallet.is_known_script(script)
        path = wallet.script_to_path(script)
        assert await wallet.is_standard_wallet_script(path)

    async def test_is_standard_wallet_script_nonstandard(self):
        storage = VolatileStorage()
        TaprootWalletFidelityBonds.initialize(
            storage, get_network(), max_mixdepth=0)
        wallet = TaprootWalletFidelityBonds(storage)
        await wallet.async_init(storage)
        import_path = await wallet.import_private_key(
            0, 'cRAGLvPmhpzJNgdMT4W2gVwEW3fusfaDqdQWM2vnWLgXKzCWKtcM')
        assert await wallet.is_standard_wallet_script(import_path)
        ts = wallet.datetime_to_time_number(
            datetime.datetime.strptime("2021-07", "%Y-%m"))
        tl_path = wallet.get_path(0, wallet.BIP32_TIMELOCK_ID, ts)
        assert not await wallet.is_standard_wallet_script(tl_path)
