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
from pynspect.traversers import PrintingTreeTraverser, HTMLTreeTraverser, BaseFilteringTreeTraverser


#-------------------------------------------------------------------------------
# NOTE: Sorry for the long lines in this file. They are deliberate, because the
# assertion permutations are (IMHO) more readable this way.
#-------------------------------------------------------------------------------


class TestPynspectPrintingTreeTraverser(unittest.TestCase):
    """
    Unit test class for testing the :py:class:`pynspect.traversers.PrintingTreeTraverser`
    from :py:mod:`pynspect.traversers` module.
    """

    def setUp(self):
        self.tvs = PrintingTreeTraverser()

    def test_01_basic(self):
        """
        Demonstrate and test the :py:class:`pynspect.traversers.PrintingTreeTraverser` object.
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
        self.assertEqual(rule_function.traverse(self.tvs), "FUNCTION(test;VARIABLE(Test))")


class TestPynspectHTMLTreeTraverser(unittest.TestCase):
    """
    Unit test class for testing the :py:class:`pynspect.traversers.HTMLTreeTraverser`
    from :py:mod:`pynspect.traversers` module.
    """

    def setUp(self):
        self.tvs = HTMLTreeTraverser()

    def test_01_basic(self):
        """
        Demonstrate and test the :py:class:`pynspect.traversers.HTMLTreeTraverser` object.
        """
        self.maxDiff = None

        rule_binop_l = LogicalBinOpRule('OP_OR', VariableRule('Test'), IntegerRule(10))
        self.assertEqual(rule_binop_l.traverse(self.tvs), '<div class="pynspect-rule-operation pynspect-rule-operation-logical"><h3 class="pynspect-rule-operation-name">OP_OR</h3><ul class="pynspect-rule-operation-arguments"><li class="pynspect-rule-operation-argument-left"><div class="pynspect-rule-constant pynspect-rule-constant-string"><kbd>Test</kbd></div></li><li class="pynspect-rule-operation-argument-right"><div class="pynspect-rule-constant pynspect-rule-constant-integer"><code>10</code></div></li></ul></div>')

        rule_binop_c = ComparisonBinOpRule('OP_GT', VariableRule('Test'), IntegerRule(15))
        self.assertEqual(rule_binop_c.traverse(self.tvs), '<div class="pynspect-rule-operation pynspect-rule-operation-comparison"><h3 class="pynspect-rule-operation-name">OP_GT</h3><ul class="pynspect-rule-operation-arguments"><li class="pynspect-rule-operation-argument-left"><div class="pynspect-rule-constant pynspect-rule-constant-string"><kbd>Test</kbd></div></li><li class="pynspect-rule-operation-argument-right"><div class="pynspect-rule-constant pynspect-rule-constant-integer"><code>15</code></div></li></ul></div>')

        rule_binop_m = MathBinOpRule('OP_PLUS', VariableRule('Test'), IntegerRule(10))
        self.assertEqual(rule_binop_m.traverse(self.tvs), '<div class="pynspect-rule-operation pynspect-rule-operation-math"><h3 class="pynspect-rule-operation-name">OP_PLUS</h3><ul class="pynspect-rule-operation-arguments"><li class="pynspect-rule-operation-argument-left"><div class="pynspect-rule-constant pynspect-rule-constant-string"><kbd>Test</kbd></div></li><li class="pynspect-rule-operation-argument-right"><div class="pynspect-rule-constant pynspect-rule-constant-integer"><code>10</code></div></li></ul></div>')

        rule_binop = LogicalBinOpRule('OP_OR', ComparisonBinOpRule('OP_GT', MathBinOpRule('OP_PLUS', VariableRule('Test'), IntegerRule(10)), IntegerRule(20)), ComparisonBinOpRule('OP_LT', VariableRule('Test'), IntegerRule(5)))
        self.assertEqual(rule_binop.traverse(self.tvs), '<div class="pynspect-rule-operation pynspect-rule-operation-logical"><h3 class="pynspect-rule-operation-name">OP_OR</h3><ul class="pynspect-rule-operation-arguments"><li class="pynspect-rule-operation-argument-left"><div class="pynspect-rule-operation pynspect-rule-operation-comparison"><h3 class="pynspect-rule-operation-name">OP_GT</h3><ul class="pynspect-rule-operation-arguments"><li class="pynspect-rule-operation-argument-left"><div class="pynspect-rule-operation pynspect-rule-operation-math"><h3 class="pynspect-rule-operation-name">OP_PLUS</h3><ul class="pynspect-rule-operation-arguments"><li class="pynspect-rule-operation-argument-left"><div class="pynspect-rule-constant pynspect-rule-constant-string"><kbd>Test</kbd></div></li><li class="pynspect-rule-operation-argument-right"><div class="pynspect-rule-constant pynspect-rule-constant-integer"><code>10</code></div></li></ul></div></li><li class="pynspect-rule-operation-argument-right"><div class="pynspect-rule-constant pynspect-rule-constant-integer"><code>20</code></div></li></ul></div></li><li class="pynspect-rule-operation-argument-right"><div class="pynspect-rule-operation pynspect-rule-operation-comparison"><h3 class="pynspect-rule-operation-name">OP_LT</h3><ul class="pynspect-rule-operation-arguments"><li class="pynspect-rule-operation-argument-left"><div class="pynspect-rule-constant pynspect-rule-constant-string"><kbd>Test</kbd></div></li><li class="pynspect-rule-operation-argument-right"><div class="pynspect-rule-constant pynspect-rule-constant-integer"><code>5</code></div></li></ul></div></li></ul></div>')

        rule_unop = UnaryOperationRule('OP_NOT', VariableRule('Test'))
        self.assertEqual(rule_unop.traverse(self.tvs), '<div class="pynspect-rule-operation pynspect-rule-operation-unary"><h3 class="pynspect-rule-operation-name">OP_NOT</h3><ul class="pynspect-rule-operation-arguments"><li class="pynspect-rule-operation-argument-right"><div class="pynspect-rule-constant pynspect-rule-constant-string"><kbd>Test</kbd></div></li></ul></div>')

        rule_function = FunctionRule('test', VariableRule('Test'))
        self.assertEqual(rule_function.traverse(self.tvs), '<div class="pynspect-rule-function"><h3 class="pynspect-rule-function-name">test</h3><ul class="pynspect-rule-function-arguments><li class="pynspect-rule-function-argument"><div class="pynspect-rule-constant pynspect-rule-constant-string"><kbd>Test</kbd></div></li></ul></div>')


class TestPynspectBaseFilteringTreeTraverser(unittest.TestCase):
    """
    Unit test class for testing the :py:class:`pynspect.traversers.BaseFilteringTreeTraverser`
    from :py:mod:`pynspect.traversers` module.
    """

    def setUp(self):
        self.tvs = BaseFilteringTreeTraverser()

    def test_01_eval_binops_logical(self):
        """
        Test the logical binary operations evaluations.
        """
        self.maxDiff = None

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', 1,    1),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', 0,    1),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', 1,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', 0,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', None, None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', 0,    None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', None, 0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', 0,    0),    False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', 1,    1),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', 0,    1),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', 1,    0),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', 0,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', None, None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', 0,    None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', None, 0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', 0,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', 1,    None), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', None, 1),    True)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', 1,    1),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', 0,    1),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', 1,    0),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', 0,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', None, None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', 0,    None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', None, 0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', 0,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', 1,    None), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', None, 1),    True)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', "True", "True"), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', "",     "True"), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', "True", ""),     False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', "",     ""),     False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', "True", "True"), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', "",     "True"), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', "True", ""),     True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', "",     ""),     False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', "True", "True"), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', "",     "True"), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', "True", ""),     True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', "",     ""),     False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', [1,2], [1,2]), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', [],    [1,2]), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', [1,2], []),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', [],    []),    False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', [1,2], [1,2]), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', [],    [1,2]), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', [1,2], []),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', [],    []),    False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', [1,2], [1,2]), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', [],    [1,2]), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', [1,2], []),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', [],    []),    False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', {"x":1}, {"x":1}), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', {},      {"x":1}), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', {"x":1}, {}),      False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND', {},      {}),      False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', {"x":1}, {"x":1}), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', {},      {"x":1}), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', {"x":1}, {}),      True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR', {},      {}),      False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', {"x":1}, {"x":1}), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', {},      {"x":1}), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', {"x":1}, {}),      True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR', {},      {}),      False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', 1,    1),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', 0,    1),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', 1,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', 0,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', None, None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', 0,    None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', None, 0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', 0,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', 1,    None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', None, 1),    False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', 1,    1),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', 0,    1),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', 1,    0),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', 0,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', None, None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', 0,    None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', None, 0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', 0,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', 1,    None), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', None, 1),    True)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', 1,    1),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', 0,    1),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', 1,    0),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', 0,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', None, None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', 0,    None), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', None, 0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', 0,    0),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', 1,    None), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', None, 1),    True)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', "True", "True"), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', "",     "True"), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', "True", ""),     False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', "",     ""),     False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', "True", "True"), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', "",     "True"), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', "True", ""),     True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', "",     ""),     False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', "True", "True"), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', "",     "True"), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', "True", ""),     True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', "",     ""),     False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', [1,2], [1,2]), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', [],    [1,2]), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', [1,2], []),    False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', [],    []),    False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', [1,2], [1,2]), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', [],    [1,2]), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', [1,2], []),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', [],    []),    False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', [1,2], [1,2]), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', [],    [1,2]), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', [1,2], []),    True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', [],    []),    False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', {"x":1}, {"x":1}), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', {},      {"x":1}), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', {"x":1}, {}),      False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_AND_P', {},      {}),      False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', {"x":1}, {"x":1}), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', {},      {"x":1}), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', {"x":1}, {}),      True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_OR_P', {},      {}),      False)

        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', {"x":1}, {"x":1}), False)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', {},      {"x":1}), True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', {"x":1}, {}),      True)
        self.assertEqual(self.tvs.evaluate_binop_logical('OP_XOR_P', {},      {}),      False)

    def test_02_eval_binops_comparison(self):
        """
        Test the comparison binary operations evaluations.
        """
        self.maxDiff = None

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_LIKE', 'abcd', 'a'), True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_LIKE', 'abcd', 'e'), False)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_IN', 'a', ['a','b','c','d']), True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_IN', 'e', ['a','b','c','d']), False)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_IS', ['a','b','c','d'], ['a','b','c','d']), True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_IS', ['a','b','c','e'], ['a','b','c','d']), False)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_EQ', 'a', 'a'), True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_EQ', 'e', 'a'), False)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_NE', 'e', 'a'), True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_NE', 'a', 'a'), False)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_GT', 'ab', 'ab'), False)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_GT', 'eb', 'ab'), True)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_GE', 'eb', 'ab'), True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_GE', 'ab', 'ab'), True)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_LT', 'ab', 'ab'), False)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_LT', 'eb', 'ab'), False)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_LE', 'eb', 'ab'), False)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_LE', 'ab', 'ab'), True)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_IN', 1, [1,2,3,4]), True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_IN', 5, [1,2,3,4]), False)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_IS', 1, 1), True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_IS', 1, 5), False)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_IS', "Test", "Test"),     True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_IS', "Test", ["Test"]),   True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_IS', ["Test"], ["Test"]), True)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_EQ', 1, 1), True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_EQ', 2, 1), False)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_NE', 2, 1), True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_NE', 1, 1), False)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_GT', 1, 1), False)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_GT', 2, 1), True)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_GE', 1, 1), True)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_GE', 1, 2), False)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_LT', 1, 1), False)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_LT', 1, 2), True)

        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_LE', 2, 1), False)
        self.assertEqual(self.tvs.evaluate_binop_comparison('OP_LE', 1, 2), True)

    def test_03_eval_binops_math(self):
        """
        Test the mathematical binary operations evaluations.
        """
        self.maxDiff = None

        self.assertEqual(self.tvs.evaluate_binop_math('OP_PLUS',   10, 10), 20)
        self.assertEqual(self.tvs.evaluate_binop_math('OP_MINUS',  10, 10), 0)
        self.assertEqual(self.tvs.evaluate_binop_math('OP_TIMES',  10, 10), 100)
        self.assertEqual(self.tvs.evaluate_binop_math('OP_MODULO', 10,  3), 1)

        self.assertEqual(self.tvs.evaluate_binop_math('OP_PLUS',   [10], [10]), 20)
        self.assertEqual(self.tvs.evaluate_binop_math('OP_MINUS',  [10], [10]), 0)
        self.assertEqual(self.tvs.evaluate_binop_math('OP_TIMES',  [10], [10]), 100)
        self.assertEqual(self.tvs.evaluate_binop_math('OP_MODULO', [10],  [3]), 1)

        self.assertEqual(self.tvs.evaluate_binop_math('OP_PLUS',   [10,20], [10]), [20,30])
        self.assertEqual(self.tvs.evaluate_binop_math('OP_MINUS',  [10,20], [10]), [0,10])
        self.assertEqual(self.tvs.evaluate_binop_math('OP_TIMES',  [10,20], [10]), [100,200])
        self.assertEqual(self.tvs.evaluate_binop_math('OP_MODULO', [10,20],  [3]), [1,2])

        self.assertEqual(self.tvs.evaluate_binop_math('OP_PLUS',   [10], [10,20]), [20,30])
        self.assertEqual(self.tvs.evaluate_binop_math('OP_MINUS',  [10], [10,20]), [0,-10])
        self.assertEqual(self.tvs.evaluate_binop_math('OP_TIMES',  [10], [10,20]), [100,200])
        self.assertEqual(self.tvs.evaluate_binop_math('OP_MODULO', [10],   [3,4]), [1,2])


#-------------------------------------------------------------------------------


if __name__ == '__main__':
    unittest.main()
