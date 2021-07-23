#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
#  Parse command line arguments
#


import argparse
import sys
import os


def parse_args():
    parser = argparse.ArgumentParser(description='* A simple tool. *\n',
                                     usage='infoScan.py [options]')

    group_target = parser.add_argument_group('Targets')
    group_target.add_argument('--file', metavar='TargetFile', type=str, default='',
                              help='Load new line delimited targets from TargetFile')

    group_http = parser.add_argument_group('HTTP proxy')
    group_http.add_argument('--proxy', metavar='Socks5', type=str, default=False, nargs='*',
                            help='http/https Socks5 proxy.')

    if len(sys.argv) == 1:
        sys.argv.append('-h')

    args = parser.parse_args()
    check_args(args)
    if args.file:
        args.input_files = args.file
    if args.proxy:
        args.proxy = {"http": "http://%s"%args.proxy[0],"https": "https://%s"%args.proxy[0]}

    return args


def check_args(args):
    if not (args.file):
        msg = 'Args missing! One of following args should be specified  \n' \
              '           -f TargetFile \n' 
        print(msg)
        exit(-1)

    if args.file and not os.path.isfile(args.file):
        print('[ERROR] TargetFile not found: %s' % args.file)
        exit(-1)
