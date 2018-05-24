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
Unit test module for testing the :py:mod:`pynspect.rules` module.
"""


__author__ = "Jan Mach <jan.mach@cesnet.cz>"
__credits__ = "Pavel Kácha <pavel.kacha@cesnet.cz>"


import unittest
from pprint import pformat

from pynspect.rules import IPV4Rule, IPV6Rule, DatetimeRule, TimedeltaRule,\
    IntegerRule, FloatRule, VariableRule, ConstantRule, LogicalBinOpRule,\
    UnaryOperationRule, ComparisonBinOpRule, MathBinOpRule, FunctionRule, ListRule


#-------------------------------------------------------------------------------
# NOTE: Sorry for the long lines in this file. They are deliberate, because the
# assertion permutations are (IMHO) more readable this way.
#-------------------------------------------------------------------------------


class TestPynspectRules(unittest.TestCase):
    """
    Unit test class for testing the rules from :py:mod:`pynspect.rules` module.
    """

    def test_01_values(self):
        """
        Perform basic rules tests: instantinate and check all rule objects.
        """
        self.maxDiff = None

        rule_var = VariableRule("Test")
        self.assertEqual(str(rule_var), "Test")
        self.assertEqual(repr(rule_var), "VARIABLE('Test')")
        rule_const = ConstantRule("constant")
        self.assertEqual(str(rule_const), '"constant"')
        self.assertEqual(repr(rule_const), "CONSTANT('constant')")
        rule_ipv4 = IPV4Rule("127.0.0.1")
        self.assertEqual(str(rule_ipv4), "127.0.0.1")
        self.assertEqual(repr(rule_ipv4), "IPV4('127.0.0.1')")
        rule_ipv6 = IPV6Rule("::1")
        self.assertEqual(str(rule_ipv6), "::1")
        self.assertEqual(repr(rule_ipv6), "IPV6('::1')")
        rule_datetime = DatetimeRule("2017-01-01T12:00:00Z")
        self.assertEqual(str(rule_datetime), "2017-01-01T12:00:00Z")
        self.assertEqual(repr(rule_datetime), "DATETIME('2017-01-01T12:00:00Z')")
        rule_timedelta = TimedeltaRule(3600)
        self.assertEqual(str(rule_timedelta), "3600")
        self.assertEqual(repr(rule_timedelta), "TIMEDELTA(3600)")
        rule_integer = IntegerRule(15)
        self.assertEqual(str(rule_integer), "15")
        self.assertEqual(repr(rule_integer), "INTEGER(15)")
        rule_float = FloatRule(15.5)
        self.assertEqual(str(rule_float), "15.5")
        self.assertEqual(repr(rule_float), "FLOAT(15.5)")
        rule_list = ListRule(VariableRule("Test"), ListRule(ConstantRule("constant"), ListRule(IPV4Rule("127.0.0.1"))))
        self.assertEqual(str(rule_list), '[Test, "constant", 127.0.0.1]')
        self.assertEqual(repr(rule_list), "LIST(VARIABLE('Test'), CONSTANT('constant'), IPV4('127.0.0.1'))")
        self.assertEqual(str(rule_list.value), "[VARIABLE('Test'), CONSTANT('constant'), IPV4('127.0.0.1')]")
        self.assertEqual(pformat(rule_list.value), "[VARIABLE('Test'), CONSTANT('constant'), IPV4('127.0.0.1')]")

    def test_02_operations(self):
        """
        Perform basic rules tests: instantinate and check all rule objects.
        """
        self.maxDiff = None

        rule_var = VariableRule("Test")
        rule_integer = IntegerRule(15)
        rule_binop_l = LogicalBinOpRule("OP_OR", rule_var, rule_integer)
        self.assertEqual(str(rule_binop_l), "(Test OP_OR 15)")
        self.assertEqual(repr(rule_binop_l), "LOGBINOP(VARIABLE('Test') OP_OR INTEGER(15))")
        rule_binop_c = ComparisonBinOpRule("OP_GT", rule_var, rule_integer)
        self.assertEqual(str(rule_binop_c), "(Test OP_GT 15)")
        self.assertEqual(repr(rule_binop_c), "COMPBINOP(VARIABLE('Test') OP_GT INTEGER(15))")
        rule_binop_m = MathBinOpRule("OP_PLUS", rule_var, rule_integer)
        self.assertEqual(str(rule_binop_m), "(Test OP_PLUS 15)")
        self.assertEqual(repr(rule_binop_m), "MATHBINOP(VARIABLE('Test') OP_PLUS INTEGER(15))")
        rule_binop = LogicalBinOpRule("OP_OR", ComparisonBinOpRule("OP_GT", MathBinOpRule("OP_PLUS", VariableRule("Test"), IntegerRule(10)), IntegerRule(20)), ComparisonBinOpRule("OP_LT", VariableRule("Test"), IntegerRule(5)))
        self.assertEqual(str(rule_binop), "(((Test OP_PLUS 10) OP_GT 20) OP_OR (Test OP_LT 5))")
        self.assertEqual(repr(rule_binop), "LOGBINOP(COMPBINOP(MATHBINOP(VARIABLE('Test') OP_PLUS INTEGER(10)) OP_GT INTEGER(20)) OP_OR COMPBINOP(VARIABLE('Test') OP_LT INTEGER(5)))")
        rule_unop = UnaryOperationRule("OP_NOT", rule_var)
        self.assertEqual(str(rule_unop), "(OP_NOT Test)")
        self.assertEqual(repr(rule_unop), "UNOP(OP_NOT VARIABLE('Test'))")

    def test_03_functions(self):
        """
        Perform basic rules tests: instantinate and check all rule objects.
        """
        self.maxDiff = None

        rule_integer = IntegerRule(15)
        rule_func1 = FunctionRule('utcnow')
        self.assertEqual(str(rule_func1), "utcnow()")
        self.assertEqual(repr(rule_func1), "FUNCTION(utcnow())")
        rule_func2 = FunctionRule('resolve', rule_integer)
        self.assertEqual(str(rule_func2), "resolve(INTEGER(15),)")
        self.assertEqual(repr(rule_func2), "FUNCTION(resolve(INTEGER(15),))")


#-------------------------------------------------------------------------------


if __name__ == '__main__':
    unittest.main()
