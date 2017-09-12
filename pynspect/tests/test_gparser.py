#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# This file is part of Pynspect package (https://pypi.python.org/pypi/pynspect).
# Originally part of Mentat system (https://mentat.cesnet.cz/).
#
# Copyright (C) since 2016 CESNET, z.s.p.o (http://www.ces.net/).
# Copyright (C) since 2016 Jan Mach <honza.mach.ml@gmail.com>
# Use of this source is governed by the MIT license, see LICENSE file.
#-------------------------------------------------------------------------------


"""
Unit test module for testing the :py:mod:`pynspect.gparser` module.
"""


__author__ = "Jan Mach <jan.mach@cesnet.cz>"
__credits__ = "Pavel Kácha <pavel.kacha@cesnet.cz>"


import unittest

from pynspect.gparser import PynspectFilterParser


#-------------------------------------------------------------------------------
# NOTE: Sorry for the long lines in this file. They are deliberate, because the
# assertion permutations are (IMHO) more readable this way.
#-------------------------------------------------------------------------------


class TestPynspectFilterParser(unittest.TestCase):
    """
    Unit test class for testing the :py:mod:`pynspect.gparser` module.
    """

    def setUp(self):
        self.psr = PynspectFilterParser()
        self.psr.build()

    def test_01_operations_logical(self):
        """
        Test the parsing of basic logical operations.
        """
        self.maxDiff = None

        self.assertEqual(repr(self.psr.parse('1 and 1')),  'LOGBINOP(INTEGER(1) OP_AND INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('1 AND 1')),  'LOGBINOP(INTEGER(1) OP_AND INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('1 && 1')),   'LOGBINOP(INTEGER(1) OP_AND_P INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('1 or 1')),   'LOGBINOP(INTEGER(1) OP_OR INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('1 OR 1')),   'LOGBINOP(INTEGER(1) OP_OR INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('1 || 1')),   'LOGBINOP(INTEGER(1) OP_OR_P INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('1 xor 1')),  'LOGBINOP(INTEGER(1) OP_XOR INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('1 XOR 1')),  'LOGBINOP(INTEGER(1) OP_XOR INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('1 ^^ 1')),   'LOGBINOP(INTEGER(1) OP_XOR_P INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('not 1')),    'UNOP(OP_NOT INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('NOT 1')),    'UNOP(OP_NOT INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('! 1')),      'UNOP(OP_NOT INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('exists 1')), 'UNOP(OP_EXISTS INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('EXISTS 1')), 'UNOP(OP_EXISTS INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('? 1')),      'UNOP(OP_EXISTS INTEGER(1))')

        self.assertEqual(repr(self.psr.parse('(1 and 1)')),  'LOGBINOP(INTEGER(1) OP_AND INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(1 AND 1)')),  'LOGBINOP(INTEGER(1) OP_AND INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(1 && 1)')),   'LOGBINOP(INTEGER(1) OP_AND_P INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(1 or 1)')),   'LOGBINOP(INTEGER(1) OP_OR INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(1 OR 1)')),   'LOGBINOP(INTEGER(1) OP_OR INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(1 || 1)')),   'LOGBINOP(INTEGER(1) OP_OR_P INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(1 xor 1)')),  'LOGBINOP(INTEGER(1) OP_XOR INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(1 XOR 1)')),  'LOGBINOP(INTEGER(1) OP_XOR INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(1 ^^ 1)')),   'LOGBINOP(INTEGER(1) OP_XOR_P INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(not 1)')),    'UNOP(OP_NOT INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(NOT 1)')),    'UNOP(OP_NOT INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(! 1)')),      'UNOP(OP_NOT INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(exists 1)')), 'UNOP(OP_EXISTS INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(EXISTS 1)')), 'UNOP(OP_EXISTS INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('(? 1)')),      'UNOP(OP_EXISTS INTEGER(1))')

        self.assertEqual(repr(self.psr.parse('((1 and 1))')),  'LOGBINOP(INTEGER(1) OP_AND INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((1 AND 1))')),  'LOGBINOP(INTEGER(1) OP_AND INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((1 && 1))')),   'LOGBINOP(INTEGER(1) OP_AND_P INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((1 or 1))')),   'LOGBINOP(INTEGER(1) OP_OR INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((1 OR 1))')),   'LOGBINOP(INTEGER(1) OP_OR INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((1 || 1))')),   'LOGBINOP(INTEGER(1) OP_OR_P INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((1 xor 1))')),  'LOGBINOP(INTEGER(1) OP_XOR INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((1 XOR 1))')),  'LOGBINOP(INTEGER(1) OP_XOR INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((1 ^^ 1))')),   'LOGBINOP(INTEGER(1) OP_XOR_P INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((not 1))')),    'UNOP(OP_NOT INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((NOT 1))')),    'UNOP(OP_NOT INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((! 1))')),      'UNOP(OP_NOT INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((exists 1))')), 'UNOP(OP_EXISTS INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((EXISTS 1))')), 'UNOP(OP_EXISTS INTEGER(1))')
        self.assertEqual(repr(self.psr.parse('((? 1))')),      'UNOP(OP_EXISTS INTEGER(1))')

    def test_02_operations_comparison(self):
        """
        Test the parsing of basic comparison operations.
        """
        self.maxDiff = None

        self.assertEqual(repr(self.psr.parse('2 like 2')), 'COMPBINOP(INTEGER(2) OP_LIKE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 LIKE 2')), 'COMPBINOP(INTEGER(2) OP_LIKE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 =~ 2')),   'COMPBINOP(INTEGER(2) OP_LIKE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 in 2')),   'COMPBINOP(INTEGER(2) OP_IN INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 IN 2')),   'COMPBINOP(INTEGER(2) OP_IN INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 ~~ 2')),   'COMPBINOP(INTEGER(2) OP_IN INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 is 2')),   'COMPBINOP(INTEGER(2) OP_IS INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 IS 2')),   'COMPBINOP(INTEGER(2) OP_IS INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 eq 2')),   'COMPBINOP(INTEGER(2) OP_EQ INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 EQ 2')),   'COMPBINOP(INTEGER(2) OP_EQ INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 == 2')),   'COMPBINOP(INTEGER(2) OP_EQ INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 ne 2')),   'COMPBINOP(INTEGER(2) OP_NE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 NE 2')),   'COMPBINOP(INTEGER(2) OP_NE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 != 2')),   'COMPBINOP(INTEGER(2) OP_NE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 <> 2')),   'COMPBINOP(INTEGER(2) OP_NE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 ge 2')),   'COMPBINOP(INTEGER(2) OP_GE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 GE 2')),   'COMPBINOP(INTEGER(2) OP_GE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 >= 2')),   'COMPBINOP(INTEGER(2) OP_GE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 gt 2')),   'COMPBINOP(INTEGER(2) OP_GT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 GT 2')),   'COMPBINOP(INTEGER(2) OP_GT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 > 2')),    'COMPBINOP(INTEGER(2) OP_GT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 le 2')),   'COMPBINOP(INTEGER(2) OP_LE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 LE 2')),   'COMPBINOP(INTEGER(2) OP_LE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 <= 2')),   'COMPBINOP(INTEGER(2) OP_LE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 lt 2')),   'COMPBINOP(INTEGER(2) OP_LT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 LT 2')),   'COMPBINOP(INTEGER(2) OP_LT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('2 < 2')),    'COMPBINOP(INTEGER(2) OP_LT INTEGER(2))')

        self.assertEqual(repr(self.psr.parse('(2 like 2)')), 'COMPBINOP(INTEGER(2) OP_LIKE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 LIKE 2)')), 'COMPBINOP(INTEGER(2) OP_LIKE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 =~ 2)')),   'COMPBINOP(INTEGER(2) OP_LIKE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 in 2)')),   'COMPBINOP(INTEGER(2) OP_IN INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 IN 2)')),   'COMPBINOP(INTEGER(2) OP_IN INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 ~~ 2)')),   'COMPBINOP(INTEGER(2) OP_IN INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 is 2)')),   'COMPBINOP(INTEGER(2) OP_IS INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 IS 2)')),   'COMPBINOP(INTEGER(2) OP_IS INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 eq 2)')),   'COMPBINOP(INTEGER(2) OP_EQ INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 EQ 2)')),   'COMPBINOP(INTEGER(2) OP_EQ INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 == 2)')),   'COMPBINOP(INTEGER(2) OP_EQ INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 ne 2)')),   'COMPBINOP(INTEGER(2) OP_NE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 NE 2)')),   'COMPBINOP(INTEGER(2) OP_NE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 != 2)')),   'COMPBINOP(INTEGER(2) OP_NE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 <> 2)')),   'COMPBINOP(INTEGER(2) OP_NE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 ge 2)')),   'COMPBINOP(INTEGER(2) OP_GE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 GE 2)')),   'COMPBINOP(INTEGER(2) OP_GE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 >= 2)')),   'COMPBINOP(INTEGER(2) OP_GE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 gt 2)')),   'COMPBINOP(INTEGER(2) OP_GT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 GT 2)')),   'COMPBINOP(INTEGER(2) OP_GT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 > 2)')),    'COMPBINOP(INTEGER(2) OP_GT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 le 2)')),   'COMPBINOP(INTEGER(2) OP_LE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 LE 2)')),   'COMPBINOP(INTEGER(2) OP_LE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 <= 2)')),   'COMPBINOP(INTEGER(2) OP_LE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 lt 2)')),   'COMPBINOP(INTEGER(2) OP_LT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 LT 2)')),   'COMPBINOP(INTEGER(2) OP_LT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('(2 < 2)')),    'COMPBINOP(INTEGER(2) OP_LT INTEGER(2))')

        self.assertEqual(repr(self.psr.parse('((2 like 2))')), 'COMPBINOP(INTEGER(2) OP_LIKE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 LIKE 2))')), 'COMPBINOP(INTEGER(2) OP_LIKE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 =~ 2))')),   'COMPBINOP(INTEGER(2) OP_LIKE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 in 2))')),   'COMPBINOP(INTEGER(2) OP_IN INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 IN 2))')),   'COMPBINOP(INTEGER(2) OP_IN INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 ~~ 2))')),   'COMPBINOP(INTEGER(2) OP_IN INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 is 2))')),   'COMPBINOP(INTEGER(2) OP_IS INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 IS 2))')),   'COMPBINOP(INTEGER(2) OP_IS INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 eq 2))')),   'COMPBINOP(INTEGER(2) OP_EQ INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 EQ 2))')),   'COMPBINOP(INTEGER(2) OP_EQ INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 == 2))')),   'COMPBINOP(INTEGER(2) OP_EQ INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 ne 2))')),   'COMPBINOP(INTEGER(2) OP_NE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 NE 2))')),   'COMPBINOP(INTEGER(2) OP_NE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 != 2))')),   'COMPBINOP(INTEGER(2) OP_NE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 <> 2))')),   'COMPBINOP(INTEGER(2) OP_NE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 ge 2))')),   'COMPBINOP(INTEGER(2) OP_GE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 GE 2))')),   'COMPBINOP(INTEGER(2) OP_GE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 >= 2))')),   'COMPBINOP(INTEGER(2) OP_GE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 gt 2))')),   'COMPBINOP(INTEGER(2) OP_GT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 GT 2))')),   'COMPBINOP(INTEGER(2) OP_GT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 > 2))')),    'COMPBINOP(INTEGER(2) OP_GT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 le 2))')),   'COMPBINOP(INTEGER(2) OP_LE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 LE 2))')),   'COMPBINOP(INTEGER(2) OP_LE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 <= 2))')),   'COMPBINOP(INTEGER(2) OP_LE INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 lt 2))')),   'COMPBINOP(INTEGER(2) OP_LT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 LT 2))')),   'COMPBINOP(INTEGER(2) OP_LT INTEGER(2))')
        self.assertEqual(repr(self.psr.parse('((2 < 2))')),    'COMPBINOP(INTEGER(2) OP_LT INTEGER(2))')

    def test_03_operations_math(self):
        """
        Test the parsing of basic mathematical operations.
        """
        self.maxDiff = None

        self.assertEqual(repr(self.psr.parse('3 + 3')), 'MATHBINOP(INTEGER(3) OP_PLUS INTEGER(3))')
        self.assertEqual(repr(self.psr.parse('3 - 3')), 'MATHBINOP(INTEGER(3) OP_MINUS INTEGER(3))')
        self.assertEqual(repr(self.psr.parse('3 * 3')), 'MATHBINOP(INTEGER(3) OP_TIMES INTEGER(3))')
        self.assertEqual(repr(self.psr.parse('3 / 3')), 'MATHBINOP(INTEGER(3) OP_DIVIDE INTEGER(3))')
        self.assertEqual(repr(self.psr.parse('3 % 3')), 'MATHBINOP(INTEGER(3) OP_MODULO INTEGER(3))')

        self.assertEqual(repr(self.psr.parse('(3 + 3)')), 'MATHBINOP(INTEGER(3) OP_PLUS INTEGER(3))')
        self.assertEqual(repr(self.psr.parse('(3 - 3)')), 'MATHBINOP(INTEGER(3) OP_MINUS INTEGER(3))')
        self.assertEqual(repr(self.psr.parse('(3 * 3)')), 'MATHBINOP(INTEGER(3) OP_TIMES INTEGER(3))')
        self.assertEqual(repr(self.psr.parse('(3 / 3)')), 'MATHBINOP(INTEGER(3) OP_DIVIDE INTEGER(3))')
        self.assertEqual(repr(self.psr.parse('(3 % 3)')), 'MATHBINOP(INTEGER(3) OP_MODULO INTEGER(3))')

        self.assertEqual(repr(self.psr.parse('((3 + 3))')), 'MATHBINOP(INTEGER(3) OP_PLUS INTEGER(3))')
        self.assertEqual(repr(self.psr.parse('((3 - 3))')), 'MATHBINOP(INTEGER(3) OP_MINUS INTEGER(3))')
        self.assertEqual(repr(self.psr.parse('((3 * 3))')), 'MATHBINOP(INTEGER(3) OP_TIMES INTEGER(3))')
        self.assertEqual(repr(self.psr.parse('((3 / 3))')), 'MATHBINOP(INTEGER(3) OP_DIVIDE INTEGER(3))')
        self.assertEqual(repr(self.psr.parse('((3 % 3))')), 'MATHBINOP(INTEGER(3) OP_MODULO INTEGER(3))')

    def test_04_factors(self):
        """
        Test parsing of all available factors.
        """
        self.maxDiff = None

        self.assertEqual(repr(self.psr.parse("127.0.0.1")),   "IPV4('127.0.0.1')")
        self.assertEqual(repr(self.psr.parse("::1")),         "IPV6('::1')")
        self.assertEqual(repr(self.psr.parse("1")),           "INTEGER(1)")
        self.assertEqual(repr(self.psr.parse("1.1")),         "FLOAT(1.1)")
        self.assertEqual(repr(self.psr.parse("Test")),        "VARIABLE('Test')")
        self.assertEqual(repr(self.psr.parse('"constant1"')), "CONSTANT('constant1')")
        self.assertEqual(repr(self.psr.parse('func()')),      "FUNCTION(func())")

        self.assertEqual(repr(self.psr.parse("(127.0.0.1)")),   "IPV4('127.0.0.1')")
        self.assertEqual(repr(self.psr.parse("(::1)")),         "IPV6('::1')")
        self.assertEqual(repr(self.psr.parse("(1)")),           "INTEGER(1)")
        self.assertEqual(repr(self.psr.parse("(1.1)")),         "FLOAT(1.1)")
        self.assertEqual(repr(self.psr.parse("(Test)")),        "VARIABLE('Test')")
        self.assertEqual(repr(self.psr.parse('("constant1")')), "CONSTANT('constant1')")
        self.assertEqual(repr(self.psr.parse('(func())')),      "FUNCTION(func())")

        self.assertEqual(repr(self.psr.parse("((127.0.0.1))")),   "IPV4('127.0.0.1')")
        self.assertEqual(repr(self.psr.parse("((::1))")),         "IPV6('::1')")
        self.assertEqual(repr(self.psr.parse("((1))")),           "INTEGER(1)")
        self.assertEqual(repr(self.psr.parse("((1.1))")),         "FLOAT(1.1)")
        self.assertEqual(repr(self.psr.parse("((Test))")),        "VARIABLE('Test')")
        self.assertEqual(repr(self.psr.parse('(("constant1"))')), "CONSTANT('constant1')")
        self.assertEqual(repr(self.psr.parse('((func()))')),      "FUNCTION(func())")

        self.assertEqual(repr(self.psr.parse("[127.0.0.1]")),   "LIST(IPV4('127.0.0.1'))")
        self.assertEqual(repr(self.psr.parse("[::1]")),         "LIST(IPV6('::1'))")
        self.assertEqual(repr(self.psr.parse("[1]")),           "LIST(INTEGER(1))")
        self.assertEqual(repr(self.psr.parse("[1.1]")),         "LIST(FLOAT(1.1))")
        self.assertEqual(repr(self.psr.parse("[Test]")),        "LIST(VARIABLE('Test'))")
        self.assertEqual(repr(self.psr.parse('["constant1"]')), "LIST(CONSTANT('constant1'))")

        self.assertEqual(repr(self.psr.parse("[127.0.0.1 , 127.0.0.2]")),        "LIST(IPV4('127.0.0.1'), IPV4('127.0.0.2'))")
        self.assertEqual(repr(self.psr.parse("[::1 , ::2]")),                    "LIST(IPV6('::1'), IPV6('::2'))")
        self.assertEqual(repr(self.psr.parse("[1,2, 3,4 , 5]")),                 "LIST(INTEGER(1), INTEGER(2), INTEGER(3), INTEGER(4), INTEGER(5))")
        self.assertEqual(repr(self.psr.parse("[1.1,2.2, 3.3,4.4 , 5.5]")),       "LIST(FLOAT(1.1), FLOAT(2.2), FLOAT(3.3), FLOAT(4.4), FLOAT(5.5))")
        self.assertEqual(repr(self.psr.parse("[Var1,Var2, Var3,Var4 , Var5 ]")), "LIST(VARIABLE('Var1'), VARIABLE('Var2'), VARIABLE('Var3'), VARIABLE('Var4'), VARIABLE('Var5'))")
        self.assertEqual(repr(self.psr.parse('["c1","c2", "c3","c4" , "c5" ]')), "LIST(CONSTANT('c1'), CONSTANT('c2'), CONSTANT('c3'), CONSTANT('c4'), CONSTANT('c5'))")

    def test_05_functions(self):
        """
        Test parsing of all available functions.
        """
        self.maxDiff = None

        self.assertEqual(repr(self.psr.parse('func()')),           "FUNCTION(func())")
        self.assertEqual(repr(self.psr.parse('func(127.0.0.1)')),  "FUNCTION(func(IPV4('127.0.0.1'),))")
        self.assertEqual(repr(self.psr.parse('func(::1)')),        "FUNCTION(func(IPV6('::1'),))")
        self.assertEqual(repr(self.psr.parse('func(1)')),          "FUNCTION(func(INTEGER(1),))")
        self.assertEqual(repr(self.psr.parse('func(1.1)')),        "FUNCTION(func(FLOAT(1.1),))")
        self.assertEqual(repr(self.psr.parse('func(Test)')),       "FUNCTION(func(VARIABLE('Test'),))")
        self.assertEqual(repr(self.psr.parse('func("constant")')), "FUNCTION(func(CONSTANT('constant'),))")
        self.assertEqual(repr(self.psr.parse('func(sub())')),      "FUNCTION(func(FUNCTION(sub()),))")

        self.assertEqual(repr(self.psr.parse("func([127.0.0.1])")),   "FUNCTION(func(LIST(IPV4('127.0.0.1')),))")
        self.assertEqual(repr(self.psr.parse("func([::1])")),         "FUNCTION(func(LIST(IPV6('::1')),))")
        self.assertEqual(repr(self.psr.parse("func([1])")),           "FUNCTION(func(LIST(INTEGER(1)),))")
        self.assertEqual(repr(self.psr.parse("func([1.1])")),         "FUNCTION(func(LIST(FLOAT(1.1)),))")
        self.assertEqual(repr(self.psr.parse("func([Test])")),        "FUNCTION(func(LIST(VARIABLE('Test')),))")
        self.assertEqual(repr(self.psr.parse('func(["constant1"])')), "FUNCTION(func(LIST(CONSTANT('constant1')),))")

        self.assertEqual(repr(self.psr.parse("func([127.0.0.1 , 127.0.0.2])")),        "FUNCTION(func(LIST(IPV4('127.0.0.1'), IPV4('127.0.0.2')),))")
        self.assertEqual(repr(self.psr.parse("func([::1 , ::2])")),                    "FUNCTION(func(LIST(IPV6('::1'), IPV6('::2')),))")
        self.assertEqual(repr(self.psr.parse("func([1,2, 3,4 , 5])")),                 "FUNCTION(func(LIST(INTEGER(1), INTEGER(2), INTEGER(3), INTEGER(4), INTEGER(5)),))")
        self.assertEqual(repr(self.psr.parse("func([1.1,2.2, 3.3,4.4 , 5.5])")),       "FUNCTION(func(LIST(FLOAT(1.1), FLOAT(2.2), FLOAT(3.3), FLOAT(4.4), FLOAT(5.5)),))")
        self.assertEqual(repr(self.psr.parse("func([Var1,Var2, Var3,Var4 , Var5 ])")), "FUNCTION(func(LIST(VARIABLE('Var1'), VARIABLE('Var2'), VARIABLE('Var3'), VARIABLE('Var4'), VARIABLE('Var5')),))")
        self.assertEqual(repr(self.psr.parse('func(["c1","c2", "c3","c4" , "c5" ])')), "FUNCTION(func(LIST(CONSTANT('c1'), CONSTANT('c2'), CONSTANT('c3'), CONSTANT('c4'), CONSTANT('c5')),))")

    def test_06_advanced(self):
        """
        Test parsing of advanced filtering expressions.
        """
        self.maxDiff = None

        self.assertEqual(repr(self.psr.parse('Category in ["Abusive.Spam" , "Attempt.Exploit"]')), "COMPBINOP(VARIABLE('Category') OP_IN LIST(CONSTANT('Abusive.Spam'), CONSTANT('Attempt.Exploit')))")
        self.assertEqual(repr(self.psr.parse('Category is ["Abusive.Spam" , "Attempt.Exploit"]')), "COMPBINOP(VARIABLE('Category') OP_IS LIST(CONSTANT('Abusive.Spam'), CONSTANT('Attempt.Exploit')))")
        self.assertEqual(repr(self.psr.parse('Node.Name in ["cz.cesnet.labrea"]')), "COMPBINOP(VARIABLE('Node.Name') OP_IN LIST(CONSTANT('cz.cesnet.labrea')))")
        self.assertEqual(repr(self.psr.parse('Source.IP4 in [127.0.0.1 , 127.0.0.2]')), "COMPBINOP(VARIABLE('Source.IP4') OP_IN LIST(IPV4('127.0.0.1'), IPV4('127.0.0.2')))")
        self.assertEqual(repr(self.psr.parse('(Source.IP4 eq 127.0.0.1) or (Node[#].Name is "cz.cesnet.labrea")')), "LOGBINOP(COMPBINOP(VARIABLE('Source.IP4') OP_EQ IPV4('127.0.0.1')) OP_OR COMPBINOP(VARIABLE('Node[#].Name') OP_IS CONSTANT('cz.cesnet.labrea')))")


#-------------------------------------------------------------------------------


if __name__ == '__main__':
    unittest.main()
