# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

# relative imports must go first; see
# http://stackoverflow.com/q/28006766
from .args import parse_args

import sys

def main(raw_args=sys.argv):
    args = parse_args(raw_args)

    raise NotImplementedError()
