# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

import argparse
import os.path
import sys

def Filename(val):
    """Used with argparse.add_argument() to assert a value is a filename
    """
    if val != '-' and (not os.path.exists(val) or os.path.isdir(val)):
        raise argparse.ArgumentTypeError('file ' + val + ' does not exist')
    return val

def parse_args(raw_args=sys.argv):
    raw_args = list(raw_args)
    parser = argparse.ArgumentParser(
        prog=raw_args.pop(0),
        description='Capture packets and save to a pcap file for future\
 use in a FASGuard bloom filter.',
    )
    parser.add_argument('-c', '--config',
                        type=Filename,
                        default='-',
                        metavar='<configfile>',
                        help='specify the configuration file pathname,' \
                            + ' or "-" for standard input (default)')
    parser.add_argument('--self-test',
                        action='store_true',
                        help='run diagnostic self tests and exit')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='increase log message verbosity')
    parser.add_argument('-V', '--version', action='version', version='0.0')
    return parser.parse_args(args=raw_args)
