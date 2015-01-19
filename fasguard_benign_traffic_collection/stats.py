# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

import logging
import threading

log = logging.getLogger(__name__)

class Stats(object):
    packets = 0
    bytes = 0
    def __init__(self):
        self._lock = threading.RLock()
    def got_packet(self, length):
        with self._lock:
            self.packets += 1
            self.bytes += length
