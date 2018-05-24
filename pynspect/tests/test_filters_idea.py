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
Unit test module for testing the :py:mod:`pynspect.filters` module with
`IDEA <https://idea.cesnet.cz/en/index>`__ messages.
"""


__author__ = "Jan Mach <jan.mach@cesnet.cz>"
__credits__ = "Pavel Kácha <pavel.kacha@cesnet.cz>"


import unittest
import datetime

from idea import lite
from pynspect.rules import IntegerRule, VariableRule, ConstantRule,\
    LogicalBinOpRule, UnaryOperationRule, ComparisonBinOpRule, MathBinOpRule, ListRule
from pynspect.gparser import PynspectFilterParser
from pynspect.filters import DataObjectFilter
from pynspect.compilers import IDEAFilterCompiler


#-------------------------------------------------------------------------------
# NOTE: Sorry for the long lines in this file. They are deliberate, because the
# assertion permutations are (IMHO) more readable this way.
#-------------------------------------------------------------------------------


class TestDataObjectFilterIDEA(unittest.TestCase):
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
        self.cpl = IDEAFilterCompiler()

        self.msg_idea = lite.Idea(self.test_msg1)

    def build_rule(self, rule_str):
        """
        Build and compile rule tree from given rule string.
        """
        rule = self.psr.parse(rule_str)
        rule = self.cpl.compile(rule)
        return rule

    def check_rule(self, rule):
        """
        Check given rule against internal test message and filter.
        """
        return self.flt.filter(rule, self.msg_idea)

    def test_01_basic_logical(self):
        """
        Perform filtering tests with basic logical expressions.
        """
        self.maxDiff = None

        rule = LogicalBinOpRule('OP_AND', ConstantRule(True), ConstantRule(True))
        self.assertEqual(self.check_rule(rule), True)
        rule = LogicalBinOpRule('OP_AND', ConstantRule(True), ConstantRule(False))
        self.assertEqual(self.check_rule(rule), False)
        rule = LogicalBinOpRule('OP_AND', ConstantRule(False), ConstantRule(True))
        self.assertEqual(self.check_rule(rule), False)
        rule = LogicalBinOpRule('OP_AND', ConstantRule(False), ConstantRule(False))
        self.assertEqual(self.check_rule(rule), False)

        rule = LogicalBinOpRule('OP_OR', ConstantRule(True), ConstantRule(True))
        self.assertEqual(self.check_rule(rule), True)
        rule = LogicalBinOpRule('OP_OR', ConstantRule(True), ConstantRule(False))
        self.assertEqual(self.check_rule(rule), True)
        rule = LogicalBinOpRule('OP_OR', ConstantRule(False), ConstantRule(True))
        self.assertEqual(self.check_rule(rule), True)
        rule = LogicalBinOpRule('OP_OR', ConstantRule(False), ConstantRule(False))
        self.assertEqual(self.check_rule(rule), False)

        rule = LogicalBinOpRule('OP_XOR', ConstantRule(True), ConstantRule(True))
        self.assertEqual(self.check_rule(rule), False)
        rule = LogicalBinOpRule('OP_XOR', ConstantRule(True), ConstantRule(False))
        self.assertEqual(self.check_rule(rule), True)
        rule = LogicalBinOpRule('OP_XOR', ConstantRule(False), ConstantRule(True))
        self.assertEqual(self.check_rule(rule), True)
        rule = LogicalBinOpRule('OP_XOR', ConstantRule(False), ConstantRule(False))
        self.assertEqual(self.check_rule(rule), False)

        rule = UnaryOperationRule('OP_NOT', ConstantRule(True))
        self.assertEqual(self.check_rule(rule), False)
        rule = UnaryOperationRule('OP_NOT', ConstantRule(False))
        self.assertEqual(self.check_rule(rule), True)
        rule = UnaryOperationRule('OP_NOT', VariableRule("Target.Anonymised"))
        self.assertEqual(self.check_rule(rule), False)

    def test_02_basic_comparison(self):
        """
        Perform filtering tests with basic comparison operations.
        """
        self.maxDiff = None

        rule = ComparisonBinOpRule('OP_EQ', VariableRule("ID"), ConstantRule("e214d2d9-359b-443d-993d-3cc5637107a0"))
        self.assertEqual(self.check_rule(rule), True)
        rule = ComparisonBinOpRule('OP_EQ', VariableRule("ID"), ConstantRule("e214d2d9-359b-443d-993d-3cc5637107"))
        self.assertEqual(self.check_rule(rule), False)
        rule = ComparisonBinOpRule('OP_NE', VariableRule("ID"), ConstantRule("e214d2d9-359b-443d-993d-3cc5637107a0"))
        self.assertEqual(self.check_rule(rule), False)
        rule = ComparisonBinOpRule('OP_NE', VariableRule("ID"), ConstantRule("e214d2d9-359b-443d-993d-3cc5637107"))
        self.assertEqual(self.check_rule(rule), True)

        rule = ComparisonBinOpRule('OP_LIKE', VariableRule("ID"), ConstantRule("e214d2d9"))
        self.assertEqual(self.check_rule(rule), True)
        rule = ComparisonBinOpRule('OP_LIKE', VariableRule("ID"), ConstantRule("xxxxxxxx"))
        self.assertEqual(self.check_rule(rule), False)
        rule = ComparisonBinOpRule('OP_IN', VariableRule("Category"), ListRule(ConstantRule("Phishing"), ListRule(ConstantRule("Attempt.Login"))))
        self.assertEqual(self.check_rule(rule), True)
        rule = ComparisonBinOpRule('OP_IN', VariableRule("Category"), ListRule(ConstantRule("Phishing"), ListRule(ConstantRule("Spam"))))
        self.assertEqual(self.check_rule(rule), False)
        rule = ComparisonBinOpRule('OP_IS', VariableRule("Category"), ListRule(ConstantRule("Attempt.Login")))
        self.assertEqual(self.check_rule(rule), True)
        rule = ComparisonBinOpRule('OP_IS', VariableRule("Category"), ListRule(ConstantRule("Phishing"), ListRule(ConstantRule("Attempt.Login"))))
        self.assertEqual(self.check_rule(rule), False)
        rule = ComparisonBinOpRule('OP_EQ', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.check_rule(rule), True)
        rule = ComparisonBinOpRule('OP_EQ', VariableRule("ConnCount"), IntegerRule(4))
        self.assertEqual(self.check_rule(rule), False)
        rule = ComparisonBinOpRule('OP_NE', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.check_rule(rule), False)
        rule = ComparisonBinOpRule('OP_NE', VariableRule("ConnCount"), IntegerRule(4))
        self.assertEqual(self.check_rule(rule), True)
        rule = ComparisonBinOpRule('OP_GT', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.check_rule(rule), False)
        rule = ComparisonBinOpRule('OP_GT', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(self.check_rule(rule), True)
        rule = ComparisonBinOpRule('OP_GE', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.check_rule(rule), True)
        rule = ComparisonBinOpRule('OP_GE', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(self.check_rule(rule), True)
        rule = ComparisonBinOpRule('OP_GE', VariableRule("ConnCount"), IntegerRule(3))
        self.assertEqual(self.check_rule(rule), False)
        rule = ComparisonBinOpRule('OP_LT', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.check_rule(rule), False)
        rule = ComparisonBinOpRule('OP_LT', VariableRule("ConnCount"), IntegerRule(3))
        self.assertEqual(self.check_rule(rule), True)
        rule = ComparisonBinOpRule('OP_LE', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.check_rule(rule), True)
        rule = ComparisonBinOpRule('OP_LE', VariableRule("ConnCount"), IntegerRule(3))
        self.assertEqual(self.check_rule(rule), True)
        rule = ComparisonBinOpRule('OP_LE', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(self.check_rule(rule), False)

    def test_03_parsed_comparison(self):
        """
        Perform filtering tests with basic parsed comparison operations.
        """
        self.maxDiff = None

        rule = self.build_rule('ID == "e214d2d9-359b-443d-993d-3cc5637107a0"')
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('ID eq "e214d2d9-359b-443d-993d-3cc5637107"')
        self.assertEqual(self.check_rule(rule), False)
        rule = self.build_rule('ID != "e214d2d9-359b-443d-993d-3cc5637107a0"')
        self.assertEqual(self.check_rule(rule), False)
        rule = self.build_rule('ID ne "e214d2d9-359b-443d-993d-3cc5637107"')
        self.assertEqual(self.check_rule(rule), True)

        rule = self.build_rule('ID like "e214d2d9"')
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('ID LIKE "xxxxxxxx"')
        self.assertEqual(self.check_rule(rule), False)
        rule = self.build_rule('Category in ["Phishing" , "Attempt.Login"]')
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('Category IN ["Phishing" , "Spam"]')
        self.assertEqual(self.check_rule(rule), False)
        rule = self.build_rule('Category is ["Attempt.Login"]')
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('Category IS ["Phishing" , "Attempt.Login"]')
        self.assertEqual(self.check_rule(rule), False)
        rule = self.build_rule('ConnCount == 2')
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('ConnCount eq 4')
        self.assertEqual(self.check_rule(rule), False)
        rule = self.build_rule('ConnCount != 2')
        self.assertEqual(self.check_rule(rule), False)
        rule = self.build_rule('ConnCount ne 4')
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('ConnCount > 2')
        self.assertEqual(self.check_rule(rule), False)
        rule = self.build_rule('ConnCount gt 1')
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('ConnCount >= 2')
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('ConnCount ge 1')
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('ConnCount GE 3')
        self.assertEqual(self.check_rule(rule), False)
        rule = self.build_rule('ConnCount < 2')
        self.assertEqual(self.check_rule(rule), False)
        rule = self.build_rule('ConnCount lt 3')
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('ConnCount <= 2')
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('ConnCount le 3')
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('ConnCount LE 1')
        self.assertEqual(self.check_rule(rule), False)

    def test_04_basic_math(self):
        """
        Perform filtering tests with basic math operations.
        """
        self.maxDiff = None

        rule = MathBinOpRule('OP_PLUS', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(self.check_rule(rule), 3)
        rule = MathBinOpRule('OP_MINUS', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(self.check_rule(rule), 1)
        rule = MathBinOpRule('OP_TIMES', VariableRule("ConnCount"), IntegerRule(5))
        self.assertEqual(self.check_rule(rule), 10)
        rule = MathBinOpRule('OP_DIVIDE', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.check_rule(rule), 1)
        rule = MathBinOpRule('OP_MODULO', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(self.check_rule(rule), 0)

    def test_05_parsed_math(self):
        """
        Perform filtering tests with parsed math operations.
        """
        self.maxDiff = None

        rule = self.build_rule('ConnCount + 1')
        self.assertEqual(self.check_rule(rule), 3)
        rule = self.build_rule('ConnCount - 1')
        self.assertEqual(self.check_rule(rule), 1)
        rule = self.build_rule('ConnCount * 5')
        self.assertEqual(self.check_rule(rule), 10)
        rule = self.build_rule('ConnCount / 2')
        self.assertEqual(self.check_rule(rule), 1)
        rule = self.build_rule('ConnCount % 2')
        self.assertEqual(self.check_rule(rule), 0)

    def test_06_advanced_filters(self):
        """
        Perform advanced filtering tests.
        """
        self.maxDiff = None

        rule = self.build_rule('DetectTime + 3600')
        self.assertEqual(repr(rule), "MATHBINOP(VARIABLE('DetectTime') OP_PLUS TIMEDELTA(datetime.timedelta(0, 3600)))")
        expected_res = (datetime.datetime(2016, 6, 21, 13, 8, 27) + datetime.timedelta(seconds = 3600))
        self.assertEqual(self.check_rule(rule), expected_res)

        rule = self.build_rule('(ConnCount + 10) > 11')
        self.assertEqual(repr(rule), "COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(10)) OP_GT INTEGER(11))")
        self.assertEqual(self.check_rule(rule), True)

        rule = self.build_rule('(ConnCount + 3) < 5')
        self.assertEqual(repr(rule), "COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(3)) OP_LT INTEGER(5))")
        self.assertEqual(self.check_rule(rule), False)

        rule = self.build_rule('((ConnCount + 3) < 5) or ((ConnCount + 10) > 11)')
        self.assertEqual(repr(rule), "LOGBINOP(COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(3)) OP_LT INTEGER(5)) OP_OR COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(10)) OP_GT INTEGER(11)))")
        self.assertEqual(self.check_rule(rule), True)

        rule = self.build_rule('(DetectTime == 2016-06-21T13:08:27Z)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_EQ DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27)))")
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('(DetectTime != 2016-06-21T13:08:27Z)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_NE DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27)))")
        self.assertEqual(self.check_rule(rule), False)
        rule = self.build_rule('(DetectTime >= 2016-06-21T14:08:27Z)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_GE DATETIME(datetime.datetime(2016, 6, 21, 14, 8, 27)))")
        self.assertEqual(self.check_rule(rule), False)
        rule = self.build_rule('(DetectTime <= 2016-06-21T14:08:27Z)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_LE DATETIME(datetime.datetime(2016, 6, 21, 14, 8, 27)))")
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('DetectTime < (utcnow() + 05:00:00)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_LT MATHBINOP(FUNCTION(utcnow()) OP_PLUS TIMEDELTA(datetime.timedelta(0, 18000))))")
        self.assertEqual(self.check_rule(rule), True)
        rule = self.build_rule('DetectTime > (utcnow() - 05:00:00)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_GT MATHBINOP(FUNCTION(utcnow()) OP_MINUS TIMEDELTA(datetime.timedelta(0, 18000))))")
        self.assertEqual(self.check_rule(rule), False)

        rule = self.build_rule('(Source.IP4 == 188.14.166.39)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_EQ IPV4(IP4('188.14.166.39')))")
        self.assertEqual(self.check_rule(rule), True)

        rule = self.build_rule('(Source.IP4 in ["188.14.166.39","188.14.166.40","188.14.166.41"])')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_IN IPLIST(IPV4(IP4('188.14.166.39')), IPV4(IP4('188.14.166.40')), IPV4(IP4('188.14.166.41'))))")
        self.assertEqual(self.check_rule(rule), True)

        # list with CIDR addresses
        rule = self.build_rule('(Source.IP4 in ["188.14.166.0/24","10.0.0.0/8","189.14.166.41"])')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_IN IPLIST(IPV4(IP4Net('188.14.166.0/24')), IPV4(IP4Net('10.0.0.0/8')), IPV4(IP4('189.14.166.41'))))")
        self.assertEqual(self.check_rule(rule), True)

    def test_06_shortcuts(self):
        """
        Perform tests of shortcut methods.
        """
        self.maxDiff = None

        # Let the shortcut method initialize everything.
        flt = DataObjectFilter(
            parser   = PynspectFilterParser,
            compiler = IDEAFilterCompiler
        )
        rule = flt.prepare('(Source.IP4 == 188.14.166.39)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_EQ IPV4(IP4('188.14.166.39')))")
        self.assertEqual(self.check_rule(rule), True)

        # Create parser and compiler instances by hand, but register them into filter.
        cpl = IDEAFilterCompiler()
        psr = PynspectFilterParser()
        psr.build()
        flt = DataObjectFilter(
            parser   = psr,
            compiler = cpl
        )
        rule = flt.prepare('(Source.IP4 == 188.14.166.39)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_EQ IPV4(IP4('188.14.166.39')))")
        self.assertEqual(self.check_rule(rule), True)


#-------------------------------------------------------------------------------


if __name__ == '__main__':
    unittest.main()
