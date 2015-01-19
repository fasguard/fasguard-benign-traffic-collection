# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

import logging
import threading

log = logging.getLogger(__name__)

class CaptureParams(object):
    def __init__(self, linktype, snaplen):
        self._snaplen = snaplen
        self._linktype = linktype
        self.lock = threading.RLock()
    @property
    def linktype(self):
        with self.lock:
            return self._linktype
    @linktype.setter
    def linktype(self, value):
        with self.lock:
            self._linktype = value
    @property
    def snaplen(self):
        return self._snaplen
