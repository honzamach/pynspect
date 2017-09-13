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
from pynspect.filters import DataObjectFilter


#-------------------------------------------------------------------------------
# NOTE: Sorry for the long lines in this file. They are deliberate, because the
# assertion permutations are (IMHO) more readable this way.
#-------------------------------------------------------------------------------


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
        self.assertEqual(repr(rule), "COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(10)) OP_GT INTEGER(11))")
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('((ConnCount + 3) < 5) or ((ConnCount + 10) > 11)')
        self.assertEqual(repr(rule), "LOGBINOP(COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(3)) OP_LT INTEGER(5)) OP_OR COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(10)) OP_GT INTEGER(11)))")
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('1')
        self.assertEqual(repr(rule), "INTEGER(1)")
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('(size(Node.Type) > 2)')
        self.assertEqual(repr(rule), "COMPBINOP(FUNCTION(size(VARIABLE('Node.Type'),)) OP_GT INTEGER(2))")
        self.assertEqual(self.flt.filter(rule, self.test_msg1), True)
        rule = self.psr.parse('(size(Source.IP4) > 4)')
        self.assertEqual(repr(rule), "COMPBINOP(FUNCTION(size(VARIABLE('Source.IP4'),)) OP_GT INTEGER(4))")
        self.assertEqual(self.flt.filter(rule, self.test_msg1), False)

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
