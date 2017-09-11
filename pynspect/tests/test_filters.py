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
Unit test module for testing the :py:mod:`pynspect.filters` module.
"""


__author__ = "Jan Mach <jan.mach@cesnet.cz>"
__credits__ = "Pavel Kácha <pavel.kacha@cesnet.cz>"


import unittest

from pynspect.rules import IntegerRule, VariableRule, ConstantRule, ListRule,\
    LogicalBinOpRule, UnaryOperationRule, ComparisonBinOpRule, MathBinOpRule
from pynspect.gparser import PynspectFilterParser
from pynspect.filters import FilteringTreeTraverser, DataObjectFilter


#-------------------------------------------------------------------------------
# NOTE: Sorry for the long lines in this file. They are deliberate, because the
# assertion permutations are (IMHO) more readable this way.
#-------------------------------------------------------------------------------


class TestPynspectFilteringTreeTraverser(unittest.TestCase):
    """
    Unit test class for testing the RuleTreeTraverser from :py:mod:`pynspect.rules` module.
    """

    def setUp(self):
        self.tvs = FilteringTreeTraverser()

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


class TestDataObjectFilter(unittest.TestCase):
    """
    Unit test class for testing the :py:mod:`pynspect.filters` module.
    """

    test_msg1 = {
        "ID" : "e214d2d9-359b-443d-993d-3cc5637107a0",
        "WinEndTime" : "2016-06-21 11:25:01Z",
        "ConnCount" : 2,
        "Source" : [
            {
                "IP4" : [
                    "188.14.166.39"
                ]
            }
        ],
        "Format" : "IDEA0",
        "WinStartTime" : "2016-06-21 11:20:01Z",
        "_CESNET" : {
            "StorageTime" : 1466508305
        },
        "Target" : [
            {
                "IP4" : [
                    "195.113.165.128/25"
                ],
                "Port" : [
                    "22"
                ],
                "Proto" : [
                    "tcp",
                    "ssh"
                ],
                "Anonymised" : True
            }
        ],
        "Note" : "SSH login attempt",
        "DetectTime" : "2016-06-21 13:08:27Z",
        "Node" : [
            {
                "Name" : "cz.cesnet.mentat.warden_filer",
                "Type" : [
                    "Relay"
                ]
            },
            {
                "AggrWin" : "00:05:00",
                "Type" : [
                    "Connection",
                    "Honeypot",
                    "Recon"
                ],
                "SW" : [
                    "Kippo"
                ],
                "Name" : "cz.uhk.apate.cowrie"
            }
        ],
        "Category" : [
            "Attempt.Login"
        ]
    }

    def setUp(self):
        self.flt = DataObjectFilter()
        self.psr = PynspectFilterParser()
        self.psr.build()

    def test_01_basic_logical(self):
        """
        Perform basic filtering tests.
        """
        self.maxDiff = None

        rule = LogicalBinOpRule('OP_AND', ConstantRule(True), ConstantRule(True))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = LogicalBinOpRule('OP_AND', ConstantRule(True), ConstantRule(False))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = LogicalBinOpRule('OP_AND', ConstantRule(False), ConstantRule(True))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = LogicalBinOpRule('OP_AND', ConstantRule(False), ConstantRule(False))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)

        rule = LogicalBinOpRule('OP_OR', ConstantRule(True), ConstantRule(True))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = LogicalBinOpRule('OP_OR', ConstantRule(True), ConstantRule(False))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = LogicalBinOpRule('OP_OR', ConstantRule(False), ConstantRule(True))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = LogicalBinOpRule('OP_OR', ConstantRule(False), ConstantRule(False))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)

        rule = LogicalBinOpRule('OP_XOR', ConstantRule(True), ConstantRule(True))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = LogicalBinOpRule('OP_XOR', ConstantRule(True), ConstantRule(False))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = LogicalBinOpRule('OP_XOR', ConstantRule(False), ConstantRule(True))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = LogicalBinOpRule('OP_XOR', ConstantRule(False), ConstantRule(False))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)

        rule = UnaryOperationRule('OP_NOT', ConstantRule(True))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = UnaryOperationRule('OP_NOT', ConstantRule(False))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = UnaryOperationRule('OP_NOT', VariableRule("Target.Anonymised"))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)

    def test_02_basic_comparison(self):
        """
        Perform basic filtering tests.
        """
        self.maxDiff = None

        rule = ComparisonBinOpRule('OP_EQ', VariableRule("ID"), ConstantRule("e214d2d9-359b-443d-993d-3cc5637107a0"))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = ComparisonBinOpRule('OP_EQ', VariableRule("ID"), ConstantRule("e214d2d9-359b-443d-993d-3cc5637107"))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = ComparisonBinOpRule('OP_NE', VariableRule("ID"), ConstantRule("e214d2d9-359b-443d-993d-3cc5637107a0"))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = ComparisonBinOpRule('OP_NE', VariableRule("ID"), ConstantRule("e214d2d9-359b-443d-993d-3cc5637107"))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)

        rule = ComparisonBinOpRule('OP_LIKE', VariableRule("ID"), ConstantRule("e214d2d9"))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = ComparisonBinOpRule('OP_LIKE', VariableRule("ID"), ConstantRule("xxxxxxxx"))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = ComparisonBinOpRule('OP_IN', VariableRule("Category"), ListRule(ConstantRule("Phishing"), ListRule(ConstantRule("Attempt.Login"))))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = ComparisonBinOpRule('OP_IN', VariableRule("Category"), ListRule(ConstantRule("Phishing"), ListRule(ConstantRule("Spam"))))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = ComparisonBinOpRule('OP_IS', VariableRule("Category"), ListRule(ConstantRule("Attempt.Login")))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = ComparisonBinOpRule('OP_IS', VariableRule("Category"), ListRule(ConstantRule("Phishing"), ListRule(ConstantRule("Attempt.Login"))))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = ComparisonBinOpRule('OP_EQ', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = ComparisonBinOpRule('OP_EQ', VariableRule("ConnCount"), IntegerRule(4))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = ComparisonBinOpRule('OP_NE', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = ComparisonBinOpRule('OP_NE', VariableRule("ConnCount"), IntegerRule(4))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = ComparisonBinOpRule('OP_GT', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = ComparisonBinOpRule('OP_GT', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = ComparisonBinOpRule('OP_GE', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = ComparisonBinOpRule('OP_GE', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = ComparisonBinOpRule('OP_GE', VariableRule("ConnCount"), IntegerRule(3))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = ComparisonBinOpRule('OP_LT', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = ComparisonBinOpRule('OP_LT', VariableRule("ConnCount"), IntegerRule(3))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = ComparisonBinOpRule('OP_LE', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = ComparisonBinOpRule('OP_LE', VariableRule("ConnCount"), IntegerRule(3))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = ComparisonBinOpRule('OP_LE', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)

        rule = self.psr.parse('ID == "e214d2d9-359b-443d-993d-3cc5637107a0"')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('ID eq "e214d2d9-359b-443d-993d-3cc5637107"')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = self.psr.parse('ID != "e214d2d9-359b-443d-993d-3cc5637107a0"')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = self.psr.parse('ID ne "e214d2d9-359b-443d-993d-3cc5637107"')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)

        rule = self.psr.parse('ID like "e214d2d9"')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('ID LIKE "xxxxxxxx"')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = self.psr.parse('Category in ["Phishing" , "Attempt.Login"]')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('Category IN ["Phishing" , "Spam"]')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = self.psr.parse('Category is ["Attempt.Login"]')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('Category IS ["Phishing" , "Attempt.Login"]')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = self.psr.parse('ConnCount == 2')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('ConnCount eq 4')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = self.psr.parse('ConnCount != 2')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = self.psr.parse('ConnCount ne 4')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('ConnCount > 2')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = self.psr.parse('ConnCount gt 1')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('ConnCount >= 2')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('ConnCount ge 1')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('ConnCount GE 3')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = self.psr.parse('ConnCount < 2')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = self.psr.parse('ConnCount lt 3')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('ConnCount <= 2')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('ConnCount le 3')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('ConnCount LE 1')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)
        rule = self.psr.parse('ConnCounts LE 1')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), None)

    def test_03_basic_math(self):
        """
        Perform basic math tests.
        """
        self.maxDiff = None

        rule = MathBinOpRule('OP_PLUS', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), 3)
        rule = MathBinOpRule('OP_MINUS', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), 1)
        rule = MathBinOpRule('OP_TIMES', VariableRule("ConnCount"), IntegerRule(5))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), 10)
        rule = MathBinOpRule('OP_DIVIDE', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), 1)
        rule = MathBinOpRule('OP_MODULO', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.flt.filter(rule, self.test_msg1), 0)

        rule = self.psr.parse('ConnCount + 1')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), 3)
        rule = self.psr.parse('ConnCount - 1')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), 1)
        rule = self.psr.parse('ConnCount * 5')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), 10)
        rule = self.psr.parse('ConnCount / 2')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), 1)
        rule = self.psr.parse('ConnCount % 2')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), 0)

    def test_04_advanced_filters(self):
        """
        Perform advanced filtering tests.
        """
        self.maxDiff = None

        rule = self.psr.parse('(ConnCount + 10) > 11')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('((ConnCount + 3) < 5) or ((ConnCount + 10) > 11)')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('1')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)

    def test_05_non_existent_nodes(self):
        """
        Perform advanced filtering tests.
        """
        self.maxDiff = None

        rule = self.psr.parse('(ConnCounts + 10) > 11')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), None)
        rule = self.psr.parse('ConnCount > ConnCounts')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), None)
        rule = self.psr.parse('DetectTime < InspectionTime')
        self.assertEqual(self.flt.filter(rule, self.test_msg1), None)


#-------------------------------------------------------------------------------


if __name__ == '__main__':
    unittest.main()
