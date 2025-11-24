#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import click
import json
from pprint import pprint
from fastbencode import bdecode


def debyte_list(lst):
    res = []
    for item in lst:
        if isinstance(item, bytes):
            item = item.decode('ISO-8859-1')
        elif isinstance(item, list):
            item = debyte_list(item)
        res.append(item)
    return res


def debyte_dict(d):
    res = {}
    for k, v in d.items():
        if isinstance(k, bytes):
            k = k.decode('ISO-8859-1')
        if isinstance(v, dict):
            v = debyte_dict(v)
        elif isinstance(v, bytes):
            v = v.decode('ISO-8859-1')
        elif isinstance(v, list):
            v = debyte_list(v)
        res[k] = v
    return res


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-i', '--input-file', required=True,
              help='Input file')
@click.option('-n', '--no-decode', is_flag=True, default=False,
              help='Do not decode to ISO-8859-1')
def main(**kwargs):
    input_file = kwargs.pop('input_file')
    no_decode = kwargs.pop('no_decode')
    with open(input_file, 'rb') as fd:
        data = fd.read()
        if no_decode:
            d = bdecode(data[8:])
            pprint(d)
        else:
            d = debyte_dict(bdecode(data[8:]))
            print(json.dumps(d, indent=4))


if __name__ == '__main__':
    main()
