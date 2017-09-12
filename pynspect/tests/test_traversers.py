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
Unit test module for testing the :py:mod:`pynspect.traversers` module.
"""


__author__ = "Jan Mach <jan.mach@cesnet.cz>"
__credits__ = "Pavel Kácha <pavel.kacha@cesnet.cz>"


import unittest

from pynspect.rules import IntegerRule, VariableRule, LogicalBinOpRule, UnaryOperationRule,\
    ComparisonBinOpRule, MathBinOpRule, FunctionRule
from pynspect.traversers import PrintingTreeTraverser


#-------------------------------------------------------------------------------
# NOTE: Sorry for the long lines in this file. They are deliberate, because the
# assertion permutations are (IMHO) more readable this way.
#-------------------------------------------------------------------------------


class TestPynspectPrintingTreeTraverser(unittest.TestCase):
    """
    Unit test class for testing the PrintingTreeTraverser from :py:mod:`pynspect.rules` module.
    """

    def setUp(self):
        self.tvs = PrintingTreeTraverser()

    def test_01_basic(self):
        """
        Demonstrate and test the PrintingTreeTraverser object.
        """
        self.maxDiff = None

        rule_binop_l = LogicalBinOpRule('OP_OR', VariableRule("Test"), IntegerRule(10))
        self.assertEqual(rule_binop_l.traverse(self.tvs), 'LOGBINOP(OP_OR;VARIABLE(Test);INTEGER(10))')

        rule_binop_c = ComparisonBinOpRule('OP_GT', VariableRule("Test"), IntegerRule(15))
        self.assertEqual(rule_binop_c.traverse(self.tvs), 'COMPBINOP(OP_GT;VARIABLE(Test);INTEGER(15))')

        rule_binop_m = MathBinOpRule('OP_PLUS', VariableRule("Test"), IntegerRule(10))
        self.assertEqual(rule_binop_m.traverse(self.tvs), 'MATHBINOP(OP_PLUS;VARIABLE(Test);INTEGER(10))')

        rule_binop = LogicalBinOpRule('OP_OR', ComparisonBinOpRule('OP_GT', MathBinOpRule('OP_PLUS', VariableRule("Test"), IntegerRule(10)), IntegerRule(20)), ComparisonBinOpRule('OP_LT', VariableRule("Test"), IntegerRule(5)))
        self.assertEqual(rule_binop.traverse(self.tvs), 'LOGBINOP(OP_OR;COMPBINOP(OP_GT;MATHBINOP(OP_PLUS;VARIABLE(Test);INTEGER(10));INTEGER(20));COMPBINOP(OP_LT;VARIABLE(Test);INTEGER(5)))')

        rule_unop = UnaryOperationRule('OP_NOT', VariableRule("Test"))
        self.assertEqual(rule_unop.traverse(self.tvs), 'UNOP(OP_NOT;VARIABLE(Test))')

        rule_function = FunctionRule('test', VariableRule("Test"))
        self.assertEqual(rule_function.traverse(self.tvs), "FUNCTION(test;['VARIABLE(Test)'])")


#-------------------------------------------------------------------------------


if __name__ == '__main__':
    unittest.main()
