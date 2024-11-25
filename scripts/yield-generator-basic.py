#!/usr/bin/env python3

import asyncio

import jmclient  # install asyncioreactor
from twisted.internet import reactor

from jmbase import jmprint
from jmclient import YieldGeneratorBasic, ygmain

# YIELD GENERATOR SETTINGS ARE NOW IN YOUR joinmarket.cfg CONFIG FILE
# (You can also use command line flags; see --help for this script).


async def _main():
    await ygmain(YieldGeneratorBasic, nickserv_password='')
    jmprint("done", "success")


if __name__ == "__main__":
    asyncio_loop = asyncio.get_event_loop()
    asyncio_loop.create_task(_main())
    reactor.run()
