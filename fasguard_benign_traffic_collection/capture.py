# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

from .util import close_when_done

import fasguard_pcap as pcap
import dpkt
import logging
import os
import stat
import sys
import threading
import traceback

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

class CaptureThreadError(Exception):
    cause = None
    def __init__(self, message, cause=None):
        tb = ''.join(traceback.format_exception(*cause)).rstrip()
        message = message + ', caused by:\n' + tb
        super(CaptureThreadError, self).__init__(message)
        self.cause = cause

class CaptureThread(threading.Thread):
    def __init__(self, iface_or_filename, shutdown_event,
                 dumpfiles, capture_params, status_q):
        name = iface_or_filename or '(default)'
        super(CaptureThread, self).__init__(name='capture.'+name)
        self._iface = iface_or_filename
        self._shutdown = shutdown_event
        self._dumpfiles = dumpfiles
        self._capture_params = capture_params
        self._status_q = status_q
        self._log = log.getChild(name)
        self._log.debug('created')
        self._pcap = None
    def run(self):
        status = [self, None]
        try:
            self._run()
        except:
            self._log.debug('exception')
            status[1] = sys.exc_info()
        finally:
            self._status_q.put(status)
    def _run(self):
        self._log.debug('running')
        if os.path.isfile(self._iface):
            self._pcap = pcap.pcap.open_offline(self._iface)
            # TODO: it is unclear what happens if self._pcap.snaplen
            # doesn't equal the output file's snaplen (which is the
            # same as self._capture_params.snaplen).  I believe the
            # output file's snaplen is effectively ignored by libpcap
            # everywhere (which makes me wonder why it exists), and
            # that it's only the per-packet snaplen that matters.
        else:
            self._pcap = pcap.pcap.open_live(
                self._iface,
                snaplen=self._capture_params.snaplen,
                to_ms=250)
        linktype = self._pcap.datalink()
        assert linktype is not None
        with self._capture_params.lock:
            if self._capture_params.linktype is None:
                self._capture_params.linktype = linktype
            if self._capture_params.linktype != linktype:
                raise RuntimeError('mixed link types not supported')
        with close_when_done(self._pcap):
            # we need to know whether this is a live capture or we are
            # reading from a file because the meaning of dispatch()'s
            # return value differs between the two cases
            live = self._pcap.type == 'live'

            while not self._shutdown.is_set():
                # the documentation of pcap.pcap.dispatch() is
                # wrong:
                #   * return value:  it returns the number of packets
                #     read, -1 on error, and -2 on breakloop().  if 0
                #     and a live capture, this means that the read
                #     timed out before any packets arrived and we
                #     should continue trying to get packets.  if 0 and
                #     reading from a saved file, there are no more
                #     packets in the file and we're done.
                #   * cnt argument:  -1 and 0 are the same, and mean
                #     "process all packets in the buffer (live
                #     capture) or in the file (offline)".  if cnt is
                #     greater than the number of packets in the buffer
                #     (live) or file (offline), it will process what
                #     is can and return.  for -1/0 with live captures,
                #     the function won't necessarily return until
                #     "enough" packets have filled the buffer (it
                #     doesn't return right away if there are no
                #     packets in the buffer yet).
                #
                # use dispatch() because:
                #   * loop() doesn't provide a way to check for
                #     shutdown when no packets have arrived within the
                #     timeout period (so shutdown can only be checked
                #     once a packet arrives, which may be never)
                #   * next() doesn't provide a way to distinguish live
                #     capture timeout from an error, so there's no way
                #     to know whether we should continue reading
                #     packets or raise an exception
                #
                # note that pcap.pcap.dispatch() will block in a
                # system call until the timeout (set in pcap's
                # constructor) is reached or the buffer is full,
                # whichever comes first.  there's no easy way to break
                # the system call when it's time to shut down, so the
                # timeout should be relatively short to ensure a
                # timely shutdown.
                n = self._pcap.dispatch(-1, self._handle_packet)

                if n == 0:
                    if live:
                        # timeout waiting for a packet; check for
                        # shutdown and try again
                        continue
                    else:
                        # no more packets in the pcap file
                        break
                elif n == -1:
                    raise IOError(self._pcap.geterr())
                elif n == -2:
                    # breakloop() was called and there was no
                    # exception; must be time to shut down
                    continue
                else:
                    # pcap doesn't document other negative values
                    assert n > 0
            self._log.debug('shutting down')

    def _handle_packet(self, header, packet):
        # WARNING:  packet is a pointer to static C memory and must be
        # copied before this function returns if the packet data is to
        # be dereferenced after returning

        if self._shutdown.is_set():
            self._pcap.breakloop()
            return

        timestamp = header.sec + header.nsec / 1e9

        self._log.debug('captured packet of caplen %i at time %f',
                        len(packet), timestamp)

        try:
            assert len(packet) == header.caplen
            service = self._extract_service(packet)
        except:
            self._log.critical('failed to decode packet')
            self._log.critical('raw packet data: ' \
                               + ':'.join('{:02x}'.format(ord(x))
                                          for x in packet))
            self._log.critical('packet data length: ' + str(len(packet)))
            self._log.critical('header:')
            self._log.critical('  sec = ' + str(header.sec))
            self._log.critical('  nsec = ' + str(header.nsec))
            self._log.critical('  caplen = ' + str(header.caplen))
            self._log.critical('  len = ' + str(header.len))
            raise
        try:
            dumpfile = self._dumpfiles[service]
        except KeyError:
            self._log.debug('discarding packet: %f len=%i %s',
                            timestamp, len(packet), service)
            return
        dumpfile.save(packet, header)

    def _extract_service(self, packet):
        eth = dpkt.ethernet.Ethernet(packet)
        ethertype = eth.type
        if ethertype <= 1500:
            # in this case the ethertype field is actually a length
            # and there is no ethertype, so combine these all into the
            # non-existant ethertype 0
            #
            # TODO: dpkt should really do this; fix in our dpkt and
            # send a patch upstream
            ethertype = 0
        if ethertype in (0x800, 0x86dd):
            ip = eth.data
            if ethertype == 0x800:
                assert isinstance(ip, dpkt.ip.IP)
                assert (4 == ip.v)
                # TODO: dpkt should split the .off property into
                # offset and flags.  fix in our dpkt and send a patch
                # upstream
                frag_offset = ip.off & (2**13 - 1)
                flags = ip.off >> 13
                dont_frag = bool(flags & 2)
                more_frag = bool(flags & 1)
                assert (not dont_frag) or (frag_offset == 0)
                assert (not dont_frag) or (not more_frag)
                is_frag = more_frag or (frag_offset != 0)
            else:
                assert isinstance(ip, dpkt.ip6.IP6)
                assert (6 == ip.v)
                # note: dpkt fills the extension_hdrs dict with Nones;
                # it should just omit an entry if the extension header
                # isn't present.  it'd be nice if we fixed this in our
                # dpkt and submitted a patch upstream.
                #
                # note: dpkt doesn't support more than one extension
                # header of the same type, but we don't care here
                #
                # note: dpkt doesn't preserve the extension header
                # order, but we don't care here
                frag_hdr = ip.extension_hdrs.get(dpkt.ip.IP_PROTO_FRAGMENT)
                frag_offset = 0
                is_frag = False
                if frag_hdr is not None:
                    frag_offset = frag_hdr.frag_off
                    is_frag = (frag_offset != 0) or (frag_hdr.m_flag)
            proto = ip.p
            if proto in (6, 17):
                if frag_offset != 0:
                    # TODO: dpkt doesn't bother checking the fragment
                    # offset before attempting to decode the payload,
                    # resulting in garbage values for large enough
                    # fragments.  fix in our dpkt and send a patch
                    # upstream
                    port = -1
                t = ip.data
                if not isinstance(t, dpkt.tcp.TCP) \
                   and not isinstance(t, dpkt.udp.UDP):
                    assert is_frag
                    port = -1
                else:
                    port = t.sport if t.sport < t.dport else t.dport
                return (ethertype, proto, port)
            return (ethertype, proto)
        return (ethertype,)
