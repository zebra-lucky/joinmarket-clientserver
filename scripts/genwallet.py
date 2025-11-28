#!/usr/bin/env python3

# A script for noninteractively creating wallets.
# The implementation is similar to wallet_generate_recover_bip39 in jmclient/wallet_utils.py

import asyncio
import os
from optparse import OptionParser

import jmclient  # install asyncioreactor
from twisted.internet import reactor
from scripts_support import wrap_main, finalize_main_task

from pathlib import Path
from jmclient import (
    load_program_config, add_base_options, SegwitWalletFidelityBonds, SegwitLegacyWallet,
    create_wallet, jm_single, wallet_utils
)
from jmbase.support import get_log, jmprint

log = get_log()

async def main():
    parser = OptionParser(
        usage='usage: %prog [options] wallet_file_name [password]',
        description='Create a wallet with the given wallet name and password.'
    )
    add_base_options(parser)
    parser.add_option(
        '--recovery-seed-file',
        dest='seed_file',
        default=None,
        help=('File containing a mnemonic recovery phrase. If provided, the wallet '
              'is recovered from this seed instead of being newly generated.')
    )
    (options, args) = parser.parse_args()
    wallet_name = args[0]
    if options.wallet_password_stdin:
        password = wallet_utils.read_password_stdin()
    else:
        assert len(args) > 1, "must provide password via stdin (see --help), or as second argument."
        password = args[1].encode("utf-8")
    seed = options.seed_file and Path(options.seed_file).read_text().rstrip()

    load_program_config(config_path=options.datadir)
    wallet_root_path = os.path.join(jm_single().datadir, "wallets")
    wallet_path = os.path.join(wallet_root_path, wallet_name)
    if jm_single().config.get("POLICY", "native") == "true":
        walletclass = SegwitWalletFidelityBonds
    else:
        # Fidelity Bonds are not available for segwit legacy wallets
        walletclass = SegwitLegacyWallet
    entropy = seed and SegwitLegacyWallet.entropy_from_mnemonic(seed)
    wallet = await create_wallet(
        wallet_path, password, wallet_utils.DEFAULT_MIXDEPTH,
        walletclass, entropy=entropy)
    jmprint("recovery_seed:{}"
         .format(wallet.get_mnemonic_words()[0]), "important")
    wallet.close()


@wrap_main
async def _main():
    await main()


if __name__ == "__main__":
    asyncio_loop = asyncio.get_event_loop()
    main_task = asyncio_loop.create_task(_main())
    reactor.run()
    finalize_main_task(main_task)
