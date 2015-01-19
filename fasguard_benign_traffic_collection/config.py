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

def process_config(raw_config):
    """process the raw literal from the config file into a config dict

    raw_config is the dict returned from parse_config().  It maps
    strings to objects.  For each key 'foo' with val 'obj', this calls
    config_handle_foo(obj), which is expected to return a value that
    will be associated with 'foo' in the returned config dict.
    """
    config = {}
    if raw_config is None:
        raw_config = {}
    for keyword, obj in raw_config.iteritems():
        try:
            handler = config_handlers[keyword]
        except KeyError:
            log.warning('unknown keyword in config: %s', keyword)
            continue
        val = handler(obj)
        config[keyword] = val
    return config

config_handlers = {}
def config_handler(keyword=None):
    """decorator to register a function to handle a chunk of raw config data
    """
    def g(f):
        kw = keyword
        if kw is None:
            pfx = 'config_handle_'
            if not f.__name__.startswith(pfx):
                raise ValueError('missing keyword')
            kw = f.__name__[len(pfx):]
        config_handlers[kw] = f
        return f
    return g

@config_handler()
def config_handle_interfaces(raw):
    """construct the set of interfaces and/or filenames to read from

    The 'interfaces' keyword is mapped to an iterable of strings where
    each string names either an interface or a pcap filename.  For
    each named interface and file, a separate capture thread will be
    created to read packets from that interface or file.

    If the 'interface' keyword is not specified in the config then
    this function won't be called and packets will be read from a
    default interface.
    """
    return set(raw)
