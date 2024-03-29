# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

# relative imports must go first; see
# http://stackoverflow.com/q/28006766
from .args import parse_args
from .capture import CaptureParams, CaptureThread, CaptureThreadError
from .config import parse_config, process_config
from .dumpfiles import Dumpfiles
from .logging import config as logging_config
from .stats import Stats, StatsLoggerThread

import logging
try:
    import queue
except ImportError:
    import Queue as queue
import sys
import threading

log = logging.getLogger(__name__)

def main(raw_args=sys.argv):
    args = parse_args(raw_args)

    logging_config(log, args.verbose)

    if args.self_test:
        return self_test()

    raw_config = parse_config(args.config)
    config = process_config(raw_config)

    try:
        run(config)
    except KeyboardInterrupt:
        return 1
    return 0

def run(config):
    capture_threads = set()
    shutdown_event = threading.Event()
    # when a capture thread exits it will place a message on this
    # queue (which might be an exception) to let the main thread know
    # that it is done
    status_q = queue.Queue()
    stats = Stats()

    # linktype must match among all pcap instances.  Packets from
    # multiple packet capture threads might go to the same dumpfile,
    # and each dumpfile has a specific linktype, so each capture
    # thread's pcap instance must have a matching linktype.
    #
    # linktype starts off as None until a capture interface is opened
    # and its linktype is discovered.
    capture_params = CaptureParams(
        linktype = None,
        snaplen = 65535,
    )

    with Dumpfiles(config, capture_params, stats) as dumpfiles:
        stats_thread = StatsLoggerThread(stats, shutdown_event)
        stats_thread.start()
        try:
            for iface in config.get('interfaces', (None,)):
                log.info('reading packets from %s',
                         iface if iface is not None else 'default interface')
                # libpcap doesn't support capturing from multiple
                # interfaces at the same time, so launch a separate
                # thread for each interface.  It is possible to use
                # select() or poll() to keep this single-threaded, but
                # separate threads might help with performance on
                # multi-core systems and it might help keep the
                # packets in chronological order.  (The packets are
                # still not guaranteed to be in chronoligical order
                # for numerous reasons, but truly fixing this would
                # require copying the packet data into a reorder
                # buffer, plus sufficiently precise and accurate
                # timestamps.)
                ct = CaptureThread(
                    iface, shutdown_event, dumpfiles, capture_params,
                    status_q)
                capture_threads.add(ct)
                log.debug('thread %s starting...', ct.name)
                ct.start()
                log.debug('thread %s started', ct.name)
            try:
                log.debug('waiting for capture threads to exit...')
                while capture_threads:
                    try:
                        # Python doesn't notice a SIGINT (generated by
                        # Ctrl-C) until Queue.get() returns, so set a
                        # timeout to a relatively short duration so that
                        # the program is responsive to the user's Ctrl-C.
                        (thread, exc_info) = status_q.get(timeout=0.25)
                    except queue.Empty:
                        continue
                    log.debug('thread %s exited', thread.name)
                    capture_threads.remove(thread)
                    log.debug('still {:d} thread(s) remaining'.format(
                        len(capture_threads)))
                    if exc_info is not None:
                        raise CaptureThreadError(
                            'error in capture thread', exc_info)
            except:
                log.info('capture thread raised exception')
                raise
            finally:
                log.info('shutting down')
                shutdown_event.set()
        finally:
            log.debug('waiting for stats thread to exit')
            stats_thread.join()

def self_test():
    import unittest
    from .test import TAPTestRunner
    tests_dir = __name__
    loader = unittest.TestLoader()
    tests = loader.discover(tests_dir, pattern='*.py')
    runner = TAPTestRunner()
    results = runner.run(tests)
    return 0 if results.wasSuccessful() else 1
