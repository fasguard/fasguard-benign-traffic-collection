# Copyright (c) 2015 Raytheon BBN Technologies Corp.  All rights reserved.

from __future__ import absolute_import

import contextlib

# intended to wrap stdin to prevent 'with' from closing it
@contextlib.contextmanager
def dummy_context_manager(obj):
    """wrapper to give an object a do-nothing context manager
    """
    yield obj
