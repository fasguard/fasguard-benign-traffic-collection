# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

import calendar
import datetime
import logging

class OffsetTimezone(datetime.tzinfo):
    def __init__(self, offset):
        self._offset = offset
    def utcoffset(self, dt):
        return self._offset
    def dst(self, dt):
        return datetime.timedelta(0)

def timestamp2datetime(timestamp):
    local = datetime.datetime.fromtimestamp(timestamp)
    utc = datetime.datetime.utcfromtimestamp(timestamp)
    local_s = calendar.timegm(local.timetuple())
    utc_s = calendar.timegm(utc.timetuple())
    offset = local_s - utc_s
    return datetime.datetime.fromtimestamp(
        timestamp, OffsetTimezone(datetime.timedelta(seconds=offset)))

class Formatter(logging.Formatter):
    converter = staticmethod(timestamp2datetime)
    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        if datefmt is not None:
            s = ct.strftime(datefmt)
        else:
            t = ct.strftime('%Y-%m-%d %H:%M:%S')
            s = '%s,%03d' % (t, record.msecs)
        return s

def config(log, verbose=False):
    handler = logging.StreamHandler()
    format = '%(asctime)s %(levelname)s %(name)s %(message)s'
    datefmt = '%Y-%m-%dT%H:%M:%S%z'
    formatter = Formatter(format, datefmt)
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
