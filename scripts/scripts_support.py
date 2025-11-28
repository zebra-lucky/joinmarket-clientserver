# -*- coding: utf-8 -*-

import asyncio
import sys
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


def finalize_main_task(main_task):
    if main_task.done():
        try:
            exit_status = main_task.result()
            if exit_status:
                sys.exit(exit_status)
        except asyncio.CancelledError:
            pass
        except Exception:
            raise
