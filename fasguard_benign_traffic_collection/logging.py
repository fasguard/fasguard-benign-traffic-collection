# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

import logging

def config(log, verbose=False):
    handler = logging.StreamHandler()
    format = '%(asctime)s %(levelname)s %(name)s %(message)s'
    datefmt = '%Y-%m-%dT%H:%M:%S%z'
    formatter = logging.Formatter(format, datefmt)
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
