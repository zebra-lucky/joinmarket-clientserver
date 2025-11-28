# -*- coding: utf-8 -*-

import asyncio
from functools import wraps

import jmclient  # install asyncioreactor
from twisted.internet import reactor

from jmbase import jmprint


def wrap_main(func):

    @wraps(func)
    async def func_wrapper(*args, **kwargs):

        try:
            return await func(*args, **kwargs)
        except SystemExit as e:
            return e.args[0] if e.args else None
        finally:
            try:
                for task in asyncio.all_tasks():
                    task.cancel()
                if reactor.running:
                    reactor.stop()
            except Exception as e:
                jmprint(f'Errors during reactor cleaenup/stop: {e}', 'debug')

    return func_wrapper
