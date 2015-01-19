# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

import contextlib
import six

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
