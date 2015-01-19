# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

from .util import dummy_context_manager, ensure_tuple, iterable_not_string

import ast
import collections
import logging
import socket
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

@config_handler()
def config_handle_outputs(raw):
    """construct a nested dict matching packet properties to output filename

    The 'outputs' keyword is mapped to an object describing how packet
    properties are mapped to output files.

    If the 'outputs' keyword is not specified in the config this
    function won't be called and all read packets will be discarded.

    This function takes the raw config object and returns a nested
    dict structure mapping a packet's properties to the output
    filename template/pattern.

    Any of the dicts in the return value might be a defaultdict, so
    check for a KeyError exception instead of using .get().

    'raw' is an iterable of (filename pattern, protomatch iterable)
    tuples.  Each of these tuples specifies the output filename
    template/pattern for captured packets matching any of the
    protomatch objects in the protomatch iterable.  These tuples are
    processed in order, with latter tuples overriding previous tuples
    where the protomatches overlap.

    A protomatch iterable is an iterable of protomatch objects.  A
    protomatch object is a sequence resembling one of the following
    (see below for specifics):
      * ()
      * (ethertype(s),)
      * ('ip', IP protocol(s),)
      * ('ipv4', IP protocol(s),)
      * ('ipv6', IP protocol(s),)
      * ('ip', 'tcp', port(s),)
      * ('ipv4', 'tcp', port(s),)
      * ('ipv6', 'tcp', port(s),)
      * ('ip', 'udp', port(s),)
      * ('ipv4', 'udp', port(s),)
      * ('ipv6', 'udp', port(s),)

    PROTOMATCH OBJECTS

      ZERO-LENGTH:
        * a zero-length protomatch object matches all packets

      ETHERTYPES:

        NOTE: non-SNAP 802.3 Ethernet packets don't have an ethertype.
        These packets are all given the non-existent ethertype 0 for
        the purposes of protocol matching.

        * ethertype(s) is either:
            - a single ethertype value
            - a sequence containing single ethertype values and/or
              pairs of single ethertype values.  A pair of ethertype
              values represents a half-open range of all ethertype
              numbers between the first (inclusive) and last
              (exclusive).
        * an ethertype value is either an ethertype number, the number
          -1 (a special ethertype number representing both the IPv4 and
          IPv6 ethertypes), or one of the following strings:
            - 'ip': same as -1
            - 'ipv4': same as 0x800
            - 'arp': same as 0x806
            - 'ipv6': same as 0x86dd
        * IP protocol(s) and port(s) may only be specified if there is
          only one ethertype specified in the protomatch, and the
          ethertype is either the IPv4 ethertype, the IPv6 ethertype, or
          the special -1 ethertype
        * if ethertype(s) includes the IPv4 or IPv6 prototype and IP
          protocols(s) is not specified, all IPv4 or IPv6 packets will
          match regardless of the IP payload protocol number.  For
          example:
              ('foo.pcap', (
                  ('ip',),
              )),
          is equivalent to:
              ('foo.pcap', (
                  ('ipv4', ((0, 6), (7, 17), (18, 256))),
                  ('ipv4', 'tcp', ((0, 65536),)),
                  ('ipv4', 'udp', ((0, 65536),)),
                  ('ipv6', ((0, 6), (7, 17), (18, 256))),
                  ('ipv6', 'tcp', ((0, 65536),)),
                  ('ipv6', 'udp', ((0, 65536),)),
              )),

      IP PROTOCOLS:
        * IP protocol(s) is either:
            - a single IP protocol value
            - a sequence containing single IP protocol values and/or
              pairs of single IP protocol values.  A pair of IP
              protocol values represents a half-open range of all IP
              protocol numbers between the first (inclusive) and last
              (exclusive)
        * an IP protocol value is either an IP protocol number, a
          string that can be converted to an IP protocol number via
          socket.getprotobyname(), or one of the following strings:
            - 'tcp': same as 6
            - 'udp': same as 17
        * ports(s) may only be specified if there is only one IP
          protocol specified in the protomatch, and the protocol is
          either TCP or UDP
        * if IP protocol(s) includes TCP or UDP and port(s) is not
          specified, all TCP or UDP packets will match regardless of
          the packet's TCP or UDP port number.  For example:
              ('foo.pcap', (
                  ('ip', ('tcp', 'udp', 'gre')),
              )),
          is equivalent to:
              ('foo.pcap', (
                  ('ipv4', 'tcp', ((0, 65536),)),
                  ('ipv4', 'udp', ((0, 65536),)),
                  ('ipv4', 'gre'),
                  ('ipv6', 'tcp', ((0, 65536),)),
                  ('ipv6', 'udp', ((0, 65536),)),
                  ('ipv6', 'gre'),
              )),

      PORTS:
        * port(s) is either:
            - a single port value
            - a sequence containing single port values and/or pairs of
              single port values.  A pair of port values represents a
              half-open range of all port numbers between the first
              (inclusive) and last (exclusive)
        * a port value is one of:
            - the string 'fragment', which means that the port is
              unknown due to the packet being a fragment
            - an integer between -1 and 65535 (inclusive), where -1 is
              the same as 'fragment' and the other values are TCP or
              UDP port numbers
            - a string that can be converted to a number in the above
              range via int()
            - a string that can be converted to a TCP or UDP port
              number via socket.getservbyname()
        * only the lesser-valued port number in a TCP or UDP packet is
          considered when looking for a match

    FILENAME PATTERNS

    If the filename pattern associated with the protomatch is None,
    then any matching packets will be discarded as if there was no
    protomatch that matched the packet.  This is useful for overriding
    an earlier broad protomatch to exclude a narrow subset.  For
    example, the following configuration saves all IP packets to
    foo.pcap except for IPv4 TCP ssh packets:

        {
            'outputs':(
                ('foo.pcap', (('ip',),)),
                (None, (('ipv4', 'tcp', 'ssh'),)),
            ),
        }

    Otherwise, the filename pattern is a string.  A matching packet's
    properties are combined with the filename pattern to generate the
    output filename.

    Specifically, when a packet matches, the packet's ethertype, IP
    protocol number (if applicable), and port number (if applicable)
    are extracted and assigned to the variables ethertype, proto, and
    port, respectively.  The filename pattern is then processed as
    follows to produce the resulting output filename:
        filename = filename_pattern.format(ethertype=ethertype,
                                           proto=proto,
                                           port=port)
    """
    outputs = {}
    for filename_pattern, protomatches in raw:
        log.debug('processing filename_pattern=%s protomatches=%s',
                  filename_pattern, protomatches)
        for protomatch in protomatches:
            log.debug('  processing protomatch=%s', protomatch)
            outputs = handle_protomatch(outputs, filename_pattern, protomatch)
    log.debug('outputs = %s', repr(outputs))
    return outputs

def handle_protomatch(outputs, filename_pattern, protomatch):
    protomatch = list(protomatch)
    if len(protomatch):
        ethertypes = ensure_tuple(protomatch.pop(0))
        outputs = handle_ethertypes(
            outputs, filename_pattern, ethertypes, protomatch)
    else:
        outputs = collections.defaultdict(
            lambda: filename_pattern)
        for ethertype in ip_ethertypes:
            outputs[ethertype] = collections.defaultdict(
                lambda: filename_pattern)
            for proto in port_protos:
                outputs[ethertype][proto] = collections.defaultdict(
                    lambda: filename_pattern)
    return outputs

def handle_ethertypes(outputs, filename_pattern, ethertypes, protomatch):
    for ethertype_range in ethertypes:
        if iterable_not_string(ethertype_range):
            ethertype_range = tuple(
                (ethertype_to_num(x) for x in ethertype_range))
            if -1 in ethertype_range:
                raise ValueError('"ip" must not be used in a range')
        else:
            x = ethertype_to_num(ethertype_range)
            ethertype_range = (x, x + 1)
        for ethertype in range(*ethertype_range):
            outputs = handle_ethertype(
                outputs, filename_pattern, ethertype, protomatch)
    return outputs

def handle_ethertype(outputs, filename_pattern, ethertype, protomatch):
    protomatch = list(protomatch)
    if ethertype == -1:
        # special 'ip' ethertype means both IPv4 and IPv6
        for x in ip_ethertypes:
            outputs = handle_ethertype(
                outputs, filename_pattern, x, protomatch)
        return outputs

    if ethertype in ip_ethertypes:
        if len(protomatch):
            protos = ensure_tuple(protomatch.pop(0))
            outputs = handle_protos(
                outputs, filename_pattern, ethertype, protos, protomatch)
        else:
            outputs[ethertype] = collections.defaultdict(
                lambda: filename_pattern)
            for proto in port_protos:
                outputs[ethertype][proto] = collections.defaultdict(
                    lambda: filename_pattern)
        return outputs

    outputs[ethertype] = filename_pattern
    return outputs

def handle_protos(outputs, filename_pattern, ethertype, protos, protomatch):
    for proto_range in protos:
        if iterable_not_string(proto_range):
            proto_range = tuple(
                (proto_to_num(x) for x in proto_range))
        else:
            x = proto_to_num(proto_range)
            proto_range = (x, x + 1)
        for proto in range(*proto_range):
            outputs = handle_proto(
                outputs, filename_pattern, ethertype, proto, protomatch)
    return outputs

def handle_proto(outputs, filename_pattern, ethertype, proto, protomatch):
    protomatch = list(protomatch)
    ethertype_outputs = {}
    try:
        ethertype_outputs = outputs[ethertype]
    except KeyError:
        outputs[ethertype] = ethertype_outputs

    if proto in port_protos:
        if len(protomatch):
            ports = ensure_tuple(protomatch.pop(0))
            outputs = handle_ports(
                outputs, filename_pattern, ethertype, proto, ports, protomatch)
        else:
            ethertype_outputs[proto] = collections.defaultdict(
                lambda: filename_pattern)
    else:
        ethertype_outputs[proto] = filename_pattern
    return outputs

def handle_ports(outputs, filename_pattern, ethertype, proto, ports,
                 protomatch):
    for port_range in ports:
        if iterable_not_string(port_range):
            port_range = tuple(
                (port_to_num(x, proto) for x in port_range))
        else:
            x = port_to_num(port_range, proto)
            port_range = (x, x + 1)
        for port in range(*port_range):
            outputs = handle_port(
                outputs, filename_pattern, ethertype, proto, port, protomatch)
    return outputs

def handle_port(outputs, filename_pattern, ethertype, proto, port, protomatch):
    proto_outputs = {}
    try:
        proto_outputs = outputs[ethertype][proto]
    except KeyError:
        outputs[ethertype][proto] = proto_outputs

    proto_outputs[port] = filename_pattern
    return outputs

ip_ethertypes = (0x800, 0x86dd)
port_protos = (6, 17)

def ethertype_to_num(x):
    ret = {
        'ip':-1,
        'ipv4':0x800,
        'arp':0x806,
        'ipv6':0x86dd,
    }.get(x)
    if ret is None:
        # \todo do a lookup in /etc/ethertypes
        ret = int(x)
    return ret

def proto_to_num(x):
    try:
        return int(x)
    except ValueError:
        pass
    ret = {
        'tcp':6,
        'udp':17,
    }.get(x)
    if ret is None:
        return socket.getprotobyname(x)
    return ret

def port_to_num(x, proto):
    if x == 'fragment':
        return -1
    try:
        return int(x)
    except ValueError:
        proto = proto_to_num(proto)
        if proto not in port_protos:
            raise ValueError('proto must be tcp or udp')
        proto = 'tcp' if proto == 6 else 'udp'
        return socket.getservbyname(x, proto)
