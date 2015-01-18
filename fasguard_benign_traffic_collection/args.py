# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

import argparse
import sys

def parse_args(raw_args=sys.argv):
    raw_args = list(raw_args)
    parser = argparse.ArgumentParser(
        prog=raw_args.pop(0),
        description='Capture packets and save to a pcap file for future\
 use in a FASGuard bloom filter.',
    )
    parser.add_argument('-V', '--version', action='version', version='0.0')
    return parser.parse_args(args=raw_args)
