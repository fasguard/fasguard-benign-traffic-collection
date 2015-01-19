# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

# relative imports must go first; see
# http://stackoverflow.com/q/28006766
from .args import parse_args
from .config import parse_config, process_config
from .logging import config as logging_config

import logging
import sys

log = logging.getLogger(__name__)

def main(raw_args=sys.argv):
    args = parse_args(raw_args)

    logging_config(log, args.verbose)

    if args.self_test:
        return self_test()

    raw_config = parse_config(args.config)
    config = process_config(raw_config)

    raise NotImplementedError()

def self_test():
    import unittest
    from .test import TAPTestRunner
    tests_dir = __name__
    loader = unittest.TestLoader()
    tests = loader.discover(tests_dir, pattern='*.py')
    runner = TAPTestRunner()
    results = runner.run(tests)
    return 0 if results.wasSuccessful() else 1
