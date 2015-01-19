# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

from .util import KeyDefaultDict

import fasguard_pcap as pcap
import logging
import threading

log = logging.getLogger(__name__)

class Dumpfiles(KeyDefaultDict):
    """maps service descriptions to Dumpfile objects

    If a service isn't in this (KeyError), the packet shouldn't be
    saved.
    """
    def __init__(self, config, capture_params, stats):
        super(Dumpfiles, self).__init__(self._factory)
        self._config = config
        self._capture_params = capture_params
        self._stats = stats
        self._dumpfiles_by_filename = {}
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_value, tb):
        self.close()
    def close(self):
        for df in self._dumpfiles_by_filename:
            self._dumpfiles_by_filename[df].close()
    def _factory(self, service):
        ethertype, proto, port = (list(service) + [None, None])[0:3]

        try:
            pattern = self._config['outputs'][ethertype]
            if proto is not None:
                pattern = pattern[proto]
            if port is not None:
                pattern = pattern[port]
        except KeyError:
            log.debug('no filename pattern in config for %s', service)
            raise

        if pattern is None:
            log.debug('filename pattern is None for %s', service)
            # pretend as if an entry wasn't found so that the packet
            # is dropped
            raise KeyError()

        filename = pattern.format(
            ethertype=ethertype,
            proto=proto,
            port=port,
        )

        try:
            return self._dumpfiles_by_filename[filename]
        except KeyError:
            pass

        dumpfile = Dumpfile(filename, self._capture_params,
                            self._stats)
        self._dumpfiles_by_filename[filename] = dumpfile
        return dumpfile

class Dumpfile(object):
    _pcap = None
    _dumper = None
    def __init__(self, filename, capture_params, stats):
        linktype = capture_params.linktype
        assert linktype is not None
        assert capture_params.snaplen is not None
        self._pcap = pcap.pcap.open_dead(linktype, capture_params.snaplen)
        self._dumper = pcap.dumper(self._pcap, filename)
        self._lock = threading.RLock()
        self._stats = stats
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_value, tb):
        self.close()
    def close(self):
        with self._lock:
            if self._dumper is not None:
                self._dumper.close()
                self._dumper = None
            if self._pcap is not None:
                self._pcap.close()
                self._pcap = None
    def save(self, packet, header):
        # record the original packet length, not the capture length
        self._stats.got_packet(header.len)
        with self._lock:
            self._dumper.dump(packet, header)
