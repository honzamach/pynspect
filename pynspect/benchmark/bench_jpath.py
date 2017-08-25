#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# This file is part of Pynspect project (https://pypi.python.org/pypi/pynspect).
# Originally part of Mentat system (https://mentat.cesnet.cz/).
#
# Copyright (C) since 2016 CESNET, z.s.p.o (http://www.ces.net/).
# Copyright (C) since 2016 Jan Mach <honza.mach.ml@gmail.com>
# Use of this source is governed by the MIT license, see LICENSE file.
#-------------------------------------------------------------------------------


"""
Benchmarking module for the :py:mod:`pynspect.jpath` module.
"""


__author__ = "Jan Mach <jan.mach@cesnet.cz>"
__credits__ = "Pavel Kácha <pavel.kacha@cesnet.cz>"


import random
import string
import timeit

from pynspect.jpath import jpath_parse, jpath_parse_c


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


#
# Performance benchmarking of :py:mod:`pynspect.jpath` module.
#
if __name__ == "__main__":

    print("\n BENCHMARKING MENTAT.FILTERING.JPATH MODULE\n")

    print("=" * 84)
    print(" {:22s} | {:16s} | {:20s} | {:20s}".format(
        "Name",
        "Iterations (#)",
        "Duration (s)",
        "Speed (#/s)"))
    print("=" * 84)
    FORMAT_PTRN = " {:22s} | {:16,d} | {:20.10f} | {:15,.3f}"

    #---------------------------------------------------------------------------

    ITERATIONS = 1000000

    #
    # Parsing of single reasonably complex JPath without caching.
    #
    RESULT = timeit.timeit('b001("Long[*].Test.Path[*]")', number = ITERATIONS, setup = "from __main__ import b001")
    SPEED = ITERATIONS / RESULT
    print(
        FORMAT_PTRN.format(
            "jpath_parse",
            ITERATIONS,
            RESULT,
            SPEED
        )
    )

    #
    # Parsing of single reasonably complex JPath with caching.
    #
    RESULT = timeit.timeit('b002("Long[*].Test.Path[*]")', number = ITERATIONS, setup = "from __main__ import b002")
    SPEED = ITERATIONS / RESULT
    print(
        FORMAT_PTRN.format(
            "jpath_parse_c",
            ITERATIONS,
            RESULT,
            SPEED
        )
    )

    #---------------------------------------------------------------------------

    ITERATIONS = 1000000

    #
    # Parsing of random reasonably complex JPath without caching.
    #
    RESULT = timeit.timeit('b003()', number = ITERATIONS, setup = "from __main__ import b003")
    SPEED = ITERATIONS / RESULT
    print(
        FORMAT_PTRN.format(
            "jpath_parse (random)",
            ITERATIONS,
            RESULT,
            SPEED
        )
    )

    #
    # Parsing of random reasonably complex JPath with caching.
    #
    RESULT = timeit.timeit('b004()', number = ITERATIONS, setup = "from __main__ import b004")
    SPEED = ITERATIONS / RESULT
    print(
        FORMAT_PTRN.format(
            "jpath_parse_c (random)",
            ITERATIONS,
            RESULT,
            SPEED
        )
    )

    #---------------------------------------------------------------------------

    print("=" * 84)
