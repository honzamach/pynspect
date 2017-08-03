#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# This file is part of Mentat system (https://mentat.cesnet.cz/).
#
# Copyright (C) since 2011 CESNET, z.s.p.o (http://www.ces.net/)
# Use of this source is governed by the MIT license, see LICENSE file.
#-------------------------------------------------------------------------------

import os
import sys
import shutil
import random
import string
import timeit
from pprint import pformat, pprint

# Generate the path to custom 'lib' directory
lib = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../lib'))
sys.path.insert(0, lib)

from pynspect.jpath import *

#-------------------------------------------------------------------------------
# HELPER FUNCTIONS
#-------------------------------------------------------------------------------

def random_jpath(depth = 3):
    """
    Generate random JPath with given node depth.
    """
    chunks = []
    while depth > 0:
        length = random.randint(5, 15)
        ident  = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(length))
        if random.choice((True, False)):
            index  = random.randint(0, 10)
            ident = "{:s}[{:d}]".format(ident, index)
        chunks.append(ident)
        depth -= 1
    return ".".join(chunks)

RANDOM_JPATHS = [random_jpath(random.randint(1,5)) for i in range(50)]
"""Pregenerated list of random JPaths."""

#-------------------------------------------------------------------------------
# BENCHMARK TESTS
#-------------------------------------------------------------------------------

b001 = jpath_parse
b002 = jpath_parse_c

def b003():
    jpath = random.choice(RANDOM_JPATHS)
    return jpath_parse(jpath)

def b004():
    jpath = random.choice(RANDOM_JPATHS)
    return jpath_parse_c(jpath)

#-------------------------------------------------------------------------------

if __name__ == "__main__":
    """
    Performance benchmarking of :py:mod:`pynspect.jpath` module.
    """

    print("\n BENCHMARKING MENTAT.FILTERING.JPATH MODULE\n")

    print("=" * 84)
    print(" {:22s} | {:16s} | {:20s} | {:20s}".format(
            "Name",
            "Iterations (#)",
            "Duration (s)",
            "Speed (#/s)"))
    print("=" * 84)
    format_ptrn = " {:22s} | {:16,d} | {:20.10f} | {:15,.3f}"

    #---------------------------------------------------------------------------

    iterations = 1000000

    """
    Parsing of single reasonably complex JPath without caching.
    """
    result = timeit.timeit('b001("Long[*].Test.Path[*]")', number = iterations, setup = "from __main__ import b001")
    speed = iterations / result
    print(
        format_ptrn.format(
            "jpath_parse",
            iterations,
            result,
            speed
        )
    )
    """
    Parsing of single reasonably complex JPath with caching.
    """
    result = timeit.timeit('b002("Long[*].Test.Path[*]")', number = iterations, setup = "from __main__ import b002")
    speed = iterations / result
    print(
        format_ptrn.format(
            "jpath_parse_c",
            iterations,
            result,
            speed
        )
    )

    #---------------------------------------------------------------------------

    iterations = 1000000

    """
    Parsing of random reasonably complex JPath without caching.
    """
    result = timeit.timeit('b003()', number = iterations, setup = "from __main__ import b003")
    speed = iterations / result
    print(
        format_ptrn.format(
            "jpath_parse (random)",
            iterations,
            result,
            speed
        )
    )
    """
    Parsing of random reasonably complex JPath with caching.
    """
    result = timeit.timeit('b004()', number = iterations, setup = "from __main__ import b004")
    speed = iterations / result
    print(
        format_ptrn.format(
            "jpath_parse_c (random)",
            iterations,
            result,
            speed
        )
    )

    #---------------------------------------------------------------------------

    print("=" * 84)
