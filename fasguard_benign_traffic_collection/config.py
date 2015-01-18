# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

from .util import dummy_context_manager

import ast
import logging
import sys

log = logging.getLogger(__name__)

def parse_config(config_filename):
    """evaluate the python literal in the config file (or stdin if '-')
    """
    log.debug('parsing config from %s', 'stdin' if config_filename == '-' \
              else config_filename)
    with dummy_context_manager(sys.stdin) if config_filename == '-' \
         else open(config_filename, 'r') as f:
        config_text = ''.join(f.read()).strip()
        log.debug('config_text = %s', config_text)
        if not config_text:
            return None
        return ast.literal_eval(config_text)
