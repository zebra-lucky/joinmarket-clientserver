#!/usr/bin/env python3

import asyncio

import jmclient  # noqa: F401 install asyncioreactor
from twisted.internet import reactor
from jmclient.scripts_support import wrap_main, finalize_main_task

from jmbase import jmprint
from jmclient import YieldGeneratorBasic, ygmain

# YIELD GENERATOR SETTINGS ARE NOW IN YOUR joinmarket.cfg CONFIG FILE
# (You can also use command line flags; see --help for this script).


@wrap_main
async def _main():
    await ygmain(YieldGeneratorBasic, nickserv_password='')
    jmprint("done", "success")


if __name__ == "__main__":
    asyncio_loop = asyncio.get_event_loop()
    main_task = asyncio_loop.create_task(_main())
    reactor.run()
    finalize_main_task(main_task)
