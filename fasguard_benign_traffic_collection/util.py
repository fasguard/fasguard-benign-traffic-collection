# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

try:
    import collections.abc as abc
except ImportError:
    import collections as abc
import contextlib
import six
import threading

# intended to wrap stdin to prevent 'with' from closing it
@contextlib.contextmanager
def dummy_context_manager(obj):
    """wrapper to give an object a do-nothing context manager
    """
    yield obj

def ensure_tuple(obj):
    if iterable_not_string(obj):
        return tuple(obj)
    return (obj,)

def iterable_not_string(obj):
    if isinstance(obj, six.string_types):
        return False
    return isinstance(obj, abc.Iterable)

class KeyDefaultDict(abc.Mapping):
    """like collections.defaultdict but default can be function of key

    This class is like collections.defaultdict with two significant
    differences:
      * the factory function that constructs the default entries takes
        the key object as an argument, allowing default entries to be
        functions of the key
      * default entries are also constructed from .get()
    """
    def __init__(self, factory):
        self._data = {}
        self._factory = factory
        self._lock = threading.RLock()
    def __contains__(self, item):
        return item in self._data
    def __getitem__(self, key):
        with self._lock:
            try:
                return self._data[key]
            except KeyError:
                new = self._factory(key)
                self._data[key] = new
                return new
    def __iter__(self):
        return iter(self._data)
    def __len__(self):
        return len(self._data)
