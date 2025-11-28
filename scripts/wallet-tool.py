#!/usr/bin/env python3

import asyncio
import sys

import jmclient  # install asyncioreactor
from twisted.internet import reactor
from jmclient.scripts_support import wrap_main, finalize_main_task

from jmbase import jmprint
from jmclient import wallet_tool_main


@wrap_main
async def _main():
    res = await wallet_tool_main("wallets")
    if res:
        jmprint(res, "success")
    else:
        jmprint("Finished", "success")


if __name__ == "__main__":
    asyncio_loop = asyncio.get_event_loop()
    main_task = asyncio_loop.create_task(_main())
    reactor.run()
    finalize_main_task(main_task)
