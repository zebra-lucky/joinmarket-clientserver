#!/usr/bin/env python3

import asyncio
import sys

import jmclient  # install asyncioreactor
from twisted.internet import reactor

from jmbase import jmprint
from jmclient import wallet_tool_main


async def _main():
    try:
        res = await wallet_tool_main("wallets")
        if res:
            jmprint(res, "success")
        else:
            jmprint("Finished", "success")
    except SystemExit as e:
        return e.args[0] if e.args else None
    finally:
        for task in asyncio.all_tasks():
            task.cancel()
        if reactor.running:
            reactor.stop()


if __name__ == "__main__":
    asyncio_loop = asyncio.get_event_loop()
    main_task = asyncio_loop.create_task(_main())
    reactor.run()
    if main_task.done():
        try:
            exit_status = main_task.result()
            if exit_status:
                sys.exit(exit_status)
        except asyncio.CancelledError:
            pass
        except Exception:
            raise
