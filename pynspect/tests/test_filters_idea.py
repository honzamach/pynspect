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


import datetime
import unittest

from idea import lite
from pynspect.rules import IntegerRule, VariableRule, ConstantRule,\
    LogicalBinOpRule, UnaryOperationRule, ComparisonBinOpRule, MathBinOpRule, ListRule
from pynspect.gparser import PynspectFilterParser
from pynspect.filters import py2_timestamp, DataObjectFilter, IDEAFilterCompiler, clean_variable


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

    def test_01_basic_logical(self):
        """
        Perform basic filtering tests.
        """
        self.maxDiff = None

        msg_idea = lite.Idea(self.test_msg1)
        flt = DataObjectFilter()

        rule = LogicalBinOpRule('OP_AND', ConstantRule(True), ConstantRule(True))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = LogicalBinOpRule('OP_AND', ConstantRule(True), ConstantRule(False))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = LogicalBinOpRule('OP_AND', ConstantRule(False), ConstantRule(True))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = LogicalBinOpRule('OP_AND', ConstantRule(False), ConstantRule(False))
        self.assertEqual(flt.filter(rule, msg_idea), False)

        rule = LogicalBinOpRule('OP_OR', ConstantRule(True), ConstantRule(True))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = LogicalBinOpRule('OP_OR', ConstantRule(True), ConstantRule(False))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = LogicalBinOpRule('OP_OR', ConstantRule(False), ConstantRule(True))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = LogicalBinOpRule('OP_OR', ConstantRule(False), ConstantRule(False))
        self.assertEqual(flt.filter(rule, msg_idea), False)

        rule = LogicalBinOpRule('OP_XOR', ConstantRule(True), ConstantRule(True))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = LogicalBinOpRule('OP_XOR', ConstantRule(True), ConstantRule(False))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = LogicalBinOpRule('OP_XOR', ConstantRule(False), ConstantRule(True))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = LogicalBinOpRule('OP_XOR', ConstantRule(False), ConstantRule(False))
        self.assertEqual(flt.filter(rule, msg_idea), False)

        rule = UnaryOperationRule('OP_NOT', ConstantRule(True))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = UnaryOperationRule('OP_NOT', ConstantRule(False))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = UnaryOperationRule('OP_NOT', VariableRule("Target.Anonymised"))
        self.assertEqual(flt.filter(rule, msg_idea), False)

    def test_02_basic_comparison(self):
        """
        Perform basic filtering tests.
        """
        self.maxDiff = None

        msg_idea = lite.Idea(self.test_msg1)
        flt = DataObjectFilter()
        psr = PynspectFilterParser()
        psr.build()

        rule = ComparisonBinOpRule('OP_EQ', VariableRule("ID"), ConstantRule("e214d2d9-359b-443d-993d-3cc5637107a0"))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = ComparisonBinOpRule('OP_EQ', VariableRule("ID"), ConstantRule("e214d2d9-359b-443d-993d-3cc5637107"))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = ComparisonBinOpRule('OP_NE', VariableRule("ID"), ConstantRule("e214d2d9-359b-443d-993d-3cc5637107a0"))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = ComparisonBinOpRule('OP_NE', VariableRule("ID"), ConstantRule("e214d2d9-359b-443d-993d-3cc5637107"))
        self.assertEqual(flt.filter(rule, msg_idea), True)

        rule = ComparisonBinOpRule('OP_LIKE', VariableRule("ID"), ConstantRule("e214d2d9"))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = ComparisonBinOpRule('OP_LIKE', VariableRule("ID"), ConstantRule("xxxxxxxx"))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = ComparisonBinOpRule('OP_IN', VariableRule("Category"), ListRule(ConstantRule("Phishing"), ListRule(ConstantRule("Attempt.Login"))))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = ComparisonBinOpRule('OP_IN', VariableRule("Category"), ListRule(ConstantRule("Phishing"), ListRule(ConstantRule("Spam"))))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = ComparisonBinOpRule('OP_IS', VariableRule("Category"), ListRule(ConstantRule("Attempt.Login")))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = ComparisonBinOpRule('OP_IS', VariableRule("Category"), ListRule(ConstantRule("Phishing"), ListRule(ConstantRule("Attempt.Login"))))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = ComparisonBinOpRule('OP_EQ', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = ComparisonBinOpRule('OP_EQ', VariableRule("ConnCount"), IntegerRule(4))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = ComparisonBinOpRule('OP_NE', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = ComparisonBinOpRule('OP_NE', VariableRule("ConnCount"), IntegerRule(4))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = ComparisonBinOpRule('OP_GT', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = ComparisonBinOpRule('OP_GT', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = ComparisonBinOpRule('OP_GE', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = ComparisonBinOpRule('OP_GE', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = ComparisonBinOpRule('OP_GE', VariableRule("ConnCount"), IntegerRule(3))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = ComparisonBinOpRule('OP_LT', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = ComparisonBinOpRule('OP_LT', VariableRule("ConnCount"), IntegerRule(3))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = ComparisonBinOpRule('OP_LE', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = ComparisonBinOpRule('OP_LE', VariableRule("ConnCount"), IntegerRule(3))
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = ComparisonBinOpRule('OP_LE', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(flt.filter(rule, msg_idea), False)

        rule = psr.parse('ID == "e214d2d9-359b-443d-993d-3cc5637107a0"')
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('ID eq "e214d2d9-359b-443d-993d-3cc5637107"')
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = psr.parse('ID != "e214d2d9-359b-443d-993d-3cc5637107a0"')
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = psr.parse('ID ne "e214d2d9-359b-443d-993d-3cc5637107"')
        self.assertEqual(flt.filter(rule, msg_idea), True)

        rule = psr.parse('ID like "e214d2d9"')
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('ID LIKE "xxxxxxxx"')
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = psr.parse('Category in ["Phishing" , "Attempt.Login"]')
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('Category IN ["Phishing" , "Spam"]')
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = psr.parse('Category is ["Attempt.Login"]')
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('Category IS ["Phishing" , "Attempt.Login"]')
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = psr.parse('ConnCount == 2')
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('ConnCount eq 4')
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = psr.parse('ConnCount != 2')
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = psr.parse('ConnCount ne 4')
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('ConnCount > 2')
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = psr.parse('ConnCount gt 1')
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('ConnCount >= 2')
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('ConnCount ge 1')
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('ConnCount GE 3')
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = psr.parse('ConnCount < 2')
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = psr.parse('ConnCount lt 3')
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('ConnCount <= 2')
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('ConnCount le 3')
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('ConnCount LE 1')
        self.assertEqual(flt.filter(rule, msg_idea), False)

    def test_03_basic_math(self):
        """
        Perform basic math tests.
        """
        self.maxDiff = None

        msg_idea = lite.Idea(self.test_msg1)
        flt = DataObjectFilter()
        psr = PynspectFilterParser()
        psr.build()

        rule = MathBinOpRule('OP_PLUS', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(flt.filter(rule, msg_idea), 3)
        rule = MathBinOpRule('OP_MINUS', VariableRule("ConnCount"), IntegerRule(1))
        self.assertEqual(flt.filter(rule, msg_idea), 1)
        rule = MathBinOpRule('OP_TIMES', VariableRule("ConnCount"), IntegerRule(5))
        self.assertEqual(flt.filter(rule, msg_idea), 10)
        rule = MathBinOpRule('OP_DIVIDE', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(flt.filter(rule, msg_idea), 1)
        rule = MathBinOpRule('OP_MODULO', VariableRule("ConnCount"), IntegerRule(2))
        self.assertEqual(flt.filter(rule, msg_idea), 0)

        rule = psr.parse('ConnCount + 1')
        self.assertEqual(flt.filter(rule, msg_idea), 3)
        rule = psr.parse('ConnCount - 1')
        self.assertEqual(flt.filter(rule, msg_idea), 1)
        rule = psr.parse('ConnCount * 5')
        self.assertEqual(flt.filter(rule, msg_idea), 10)
        rule = psr.parse('ConnCount / 2')
        self.assertEqual(flt.filter(rule, msg_idea), 1)
        rule = psr.parse('ConnCount % 2')
        self.assertEqual(flt.filter(rule, msg_idea), 0)

    def test_04_basic_compilations(self):
        """
        Perform advanced filtering tests.
        """
        self.maxDiff = None

        self.assertEqual(clean_variable('Target.IP4'), 'Target.IP4')
        self.assertEqual(clean_variable('Target[1].IP4'), 'Target.IP4')
        self.assertEqual(clean_variable('Target[1].IP4[22]'), 'Target.IP4')

        cpl = IDEAFilterCompiler()
        psr = PynspectFilterParser()
        psr.build()

        rule = psr.parse('(DetectTime == "2016-06-21T13:08:27Z")')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_EQ CONSTANT('2016-06-21T13:08:27Z'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('DetectTime') OP_EQ DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27)))")

        rule = psr.parse('(DetectTime == 2016-06-21T13:08:27Z)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_EQ DATETIME('2016-06-21T13:08:27Z'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('DetectTime') OP_EQ DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27)))")

        rule = psr.parse('(Source.IP4 == "188.14.166.39")')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_EQ CONSTANT('188.14.166.39'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('Source.IP4') OP_EQ IPV4(IP4('188.14.166.39')))")

        rule = psr.parse('(Source.IP4 == 188.14.166.39)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_EQ IPV4('188.14.166.39'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('Source.IP4') OP_EQ IPV4(IP4('188.14.166.39')))")

        rule = psr.parse('5 + 6 - 9')
        self.assertEqual(repr(rule), "MATHBINOP(INTEGER(5) OP_PLUS MATHBINOP(INTEGER(6) OP_MINUS INTEGER(9)))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "INTEGER(2)")

        rule = psr.parse('Test + 10 - 9')
        self.assertEqual(repr(rule), "MATHBINOP(VARIABLE('Test') OP_PLUS MATHBINOP(INTEGER(10) OP_MINUS INTEGER(9)))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "MATHBINOP(VARIABLE('Test') OP_PLUS INTEGER(1))")

        rule = psr.parse('Test + (10 - 9)')
        self.assertEqual(repr(rule), "MATHBINOP(VARIABLE('Test') OP_PLUS MATHBINOP(INTEGER(10) OP_MINUS INTEGER(9)))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "MATHBINOP(VARIABLE('Test') OP_PLUS INTEGER(1))")

        rule = psr.parse('(Test + 10) - 9')
        self.assertEqual(repr(rule), "MATHBINOP(MATHBINOP(VARIABLE('Test') OP_PLUS INTEGER(10)) OP_MINUS INTEGER(9))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "MATHBINOP(MATHBINOP(VARIABLE('Test') OP_PLUS INTEGER(10)) OP_MINUS INTEGER(9))")

        rule = psr.parse('9 - 6 + Test')
        self.assertEqual(repr(rule), "MATHBINOP(INTEGER(9) OP_MINUS MATHBINOP(INTEGER(6) OP_PLUS VARIABLE('Test')))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "MATHBINOP(INTEGER(9) OP_MINUS MATHBINOP(INTEGER(6) OP_PLUS VARIABLE('Test')))")

        rule = psr.parse('9 - (6 + Test)')
        self.assertEqual(repr(rule), "MATHBINOP(INTEGER(9) OP_MINUS MATHBINOP(INTEGER(6) OP_PLUS VARIABLE('Test')))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "MATHBINOP(INTEGER(9) OP_MINUS MATHBINOP(INTEGER(6) OP_PLUS VARIABLE('Test')))")

        rule = psr.parse('(9 - 6) + Test')
        self.assertEqual(repr(rule), "MATHBINOP(MATHBINOP(INTEGER(9) OP_MINUS INTEGER(6)) OP_PLUS VARIABLE('Test'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "MATHBINOP(INTEGER(3) OP_PLUS VARIABLE('Test'))")

    def test_05_advanced_filters(self):
        """
        Perform advanced filtering tests.
        """
        self.maxDiff = None

        msg_idea = lite.Idea(self.test_msg1)
        flt = DataObjectFilter()
        cpl = IDEAFilterCompiler()
        psr = PynspectFilterParser()
        psr.build()

        #rule = psr.parse('DetectTime + 3600')
        #self.assertEqual(repr(rule), "MATHBINOP(VARIABLE('DetectTime') OP_PLUS INTEGER(3600))")
        #res = cpl.compile(rule)
        #self.assertEqual(repr(res), "MATHBINOP(VARIABLE('DetectTime') OP_PLUS INTEGER(3600))")

        # Be careful about timezones - comparison must not be performed using absolute number:
        #tsd = (datetime.datetime(2016, 6, 21, 13, 8, 27) + datetime.timedelta(seconds = 3600))
        #try:
        #    tsd_sec = tsd.timestamp()
        #except NameError:
        #    tsd_sec = py2_timestamp(tsd)
        #self.assertEqual(flt.filter(rule, msg_idea), tsd_sec)

        rule = psr.parse('(ConnCount + 10) > 11')
        self.assertEqual(repr(rule), "COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(10)) OP_GT INTEGER(11))")
        rule = cpl.compile(rule)
        self.assertEqual(repr(rule), "COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(10)) OP_GT INTEGER(11))")
        self.assertEqual(flt.filter(rule, msg_idea), True)

        rule = psr.parse('(ConnCount + 3) < 5')
        self.assertEqual(repr(rule), "COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(3)) OP_LT INTEGER(5))")
        rule = cpl.compile(rule)
        self.assertEqual(repr(rule), "COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(3)) OP_LT INTEGER(5))")
        self.assertEqual(flt.filter(rule, msg_idea), False)

        rule = psr.parse('((ConnCount + 3) < 5) or ((ConnCount + 10) > 11)')
        self.assertEqual(repr(rule), "LOGBINOP(COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(3)) OP_LT INTEGER(5)) OP_OR COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(10)) OP_GT INTEGER(11)))")
        rule = cpl.compile(rule)
        self.assertEqual(repr(rule), "LOGBINOP(COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(3)) OP_LT INTEGER(5)) OP_OR COMPBINOP(MATHBINOP(VARIABLE('ConnCount') OP_PLUS INTEGER(10)) OP_GT INTEGER(11)))")
        self.assertEqual(flt.filter(rule, msg_idea), True)

        rule = psr.parse('(DetectTime == 2016-06-21T13:08:27Z)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_EQ DATETIME('2016-06-21T13:08:27Z'))")
        rule = cpl.compile(rule)
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_EQ DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27)))")
        self.assertEqual(flt.filter(rule, msg_idea), True)
        rule = psr.parse('(DetectTime != 2016-06-21T13:08:27Z)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_NE DATETIME('2016-06-21T13:08:27Z'))")
        rule = cpl.compile(rule)
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_NE DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27)))")
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = psr.parse('(DetectTime >= 2016-06-21T14:08:27Z)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_GE DATETIME('2016-06-21T14:08:27Z'))")
        rule = cpl.compile(rule)
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_GE DATETIME(datetime.datetime(2016, 6, 21, 14, 8, 27)))")
        self.assertEqual(flt.filter(rule, msg_idea), False)
        rule = psr.parse('(DetectTime <= 2016-06-21T14:08:27Z)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_LE DATETIME('2016-06-21T14:08:27Z'))")
        rule = cpl.compile(rule)
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_LE DATETIME(datetime.datetime(2016, 6, 21, 14, 8, 27)))")
        self.assertEqual(flt.filter(rule, msg_idea), True)

        rule = psr.parse('(Source.IP4 == 188.14.166.39)')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_EQ IPV4('188.14.166.39'))")
        rule = cpl.compile(rule)
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_EQ IPV4(IP4('188.14.166.39')))")
        self.assertEqual(flt.filter(rule, msg_idea), True)

        rule = psr.parse('(Source.IP4 in ["188.14.166.39","188.14.166.40","188.14.166.41"])')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_IN LIST(CONSTANT('188.14.166.39'), CONSTANT('188.14.166.40'), CONSTANT('188.14.166.41')))")
        rule = cpl.compile(rule)
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_IN IPLIST(IPV4(IP4('188.14.166.39')), IPV4(IP4('188.14.166.40')), IPV4(IP4('188.14.166.41'))))")
        self.assertEqual(flt.filter(rule, msg_idea), True)

        # list with CIDR addresses
        rule = psr.parse('(Source.IP4 in ["188.14.166.0/24","10.0.0.0/8","189.14.166.41"])')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_IN LIST(CONSTANT('188.14.166.0/24'), CONSTANT('10.0.0.0/8'), CONSTANT('189.14.166.41')))")
        rule = cpl.compile(rule)
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_IN IPLIST(IPV4(IP4Net('188.14.166.0/24')), IPV4(IP4Net('10.0.0.0/8')), IPV4(IP4('189.14.166.41'))))")
        self.assertEqual(flt.filter(rule, msg_idea), True)


#-------------------------------------------------------------------------------


if __name__ == '__main__':
    unittest.main()
