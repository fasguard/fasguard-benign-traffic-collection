# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

import datetime
import itertools
import logging
import threading

log = logging.getLogger(__name__)

class Stats(object):
    packets = 0
    bytes = 0

    def __init__(self, name=None, parent=None):
        self._name = name
        self._parent = parent
        self._children = {}
        if parent is None:
            self._lock = threading.RLock()
        else:
            # sharing a single lock ensures that the parent always
            # equals the sum of the children, but it might be a
            # performance bottleneck
            self._lock = parent._lock

    def got_packet(self, length):
        with self._lock:
            if self._parent is not None:
                self._parent.got_packet(length)
            self.packets += 1
            self.bytes += length

    def get_child(self, name=None):
        if self._name is not None:
            name = self._name + '.' + name
        child = Stats(name, self)
        self._children[name] = child
        return child

    def log_lines(self, elapsed, prefix=""):
        if elapsed == 0.0:
            # avoid divide by zero
            elapsed = datetime.datetime.resolution.total_seconds()
        line = prefix
        if self._name is not None:
            line += self._name + ': '
        with self._lock:
            pps = self.packets / float(elapsed)
            Bps = self.bytes / float(elapsed)
            line += '%i packets (%i bytes) in %f seconds (%f pps, %f Bps)' % (
                self.packets, self.bytes, elapsed, pps, Bps)
            return itertools.chain(
                (line,),
                itertools.chain.from_iterable(
                    (self._children[n].log_lines(elapsed, prefix=(prefix+'  '))
                     for n in sorted(self._children))))

class StatsLoggerThread(threading.Thread):

    def __init__(self, stats, shutdown_event):
        super(StatsLoggerThread, self).__init__(name='stats')
        self._stats = stats
        self._shutdown = shutdown_event

    def run(self):
        start = datetime.datetime.utcnow()
        while not self._shutdown.is_set():
            self._shutdown.wait(5.0)
            elapsed = (datetime.datetime.utcnow() - start).total_seconds()
            for line in self._stats.log_lines(elapsed):
                log.info(line)
