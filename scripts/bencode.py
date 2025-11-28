#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import click
import json
from fastbencode import bencode_utf8


def enbyte_list(lst):
    res = []
    for item in lst:
        if isinstance(item, str):
            item = item.encode('ISO-8859-1')
        elif isinstance(item, list):
            item = enbyte_list(item)
        res.append(item)
    return res


def enbyte_dict(d):
    res = {}
    for k, v in d.items():
        if isinstance(k, str):
            k = k.encode('ISO-8859-1')
        if isinstance(v, dict):
            v = enbyte_dict(v)
        elif isinstance(v, str):
            v = v.encode('ISO-8859-1')
        elif isinstance(v, list):
            v = enbyte_list(v)
        res[k] = v
    return res


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-i', '--input-file', required=True,
              help='Unencoded file')
@click.option('-o', '--output-file', required=True,
              help='Output file')
@click.option('-d', '--dkg-magic', is_flag=True, default=False,
              help='Prepend dkg storage magic')
@click.option('-r', '--recovery-magic', is_flag=True, default=False,
              help='Prepend recovery storage magic')
def main(**kwargs):
    input_file = kwargs.pop('input_file')
    output_file = kwargs.pop('output_file')
    dkg_magic = kwargs.pop('dkg_magic')
    recovery_magic = kwargs.pop('recovery_magic')
    if dkg_magic and recovery_magic:
        raise click.UsageError('Options -d and -r is mutually exclusive')
    if dkg_magic:
        MAGIC_UNENC = b'JMDKGDAT'
    elif recovery_magic:
        MAGIC_UNENC = b'JMDKGREC'
    else:
        MAGIC_UNENC = b'JMWALLET'

    with open(input_file, 'r') as fd:
        data = json.loads(fd.read())
    data = enbyte_dict(data)

    with open(output_file, 'wb') as wfd:
        wfd.write(MAGIC_UNENC + bencode_utf8(data))


if __name__ == '__main__':
    main()
