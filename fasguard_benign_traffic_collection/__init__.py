# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

# relative imports must go first; see
# http://stackoverflow.com/q/28006766
from .args import parse_args
from .logging import config as logging_config

import logging
import sys

log = logging.getLogger(__name__)

def main(raw_args=sys.argv):
    args = parse_args(raw_args)

    logging_config(log, args.verbose)

    raise NotImplementedError()
