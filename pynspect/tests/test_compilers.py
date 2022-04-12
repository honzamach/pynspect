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
Unit test module for testing the :py:mod:`pynspect.compilers` module.
"""


__author__ = "Jan Mach <jan.mach@cesnet.cz>"
__credits__ = "Pavel Kácha <pavel.kacha@cesnet.cz>"


import unittest
from datetime import datetime

from pynspect.rules import ConstantRule, NumberRule
from pynspect.gparser import PynspectFilterParser
from pynspect.compilers import IDEAFilterCompiler, clean_variable, compile_ip_v4,\
    compile_ip_v6, compile_timedelta, compile_datetime, compile_timeoper

#-------------------------------------------------------------------------------
# NOTE: Sorry for the long lines in this file. They are deliberate, because the
# assertion permutations are (IMHO) more readable this way.
#-------------------------------------------------------------------------------


class TestIDEAFilterCompiler(unittest.TestCase):
    """
    Unit test class for testing the :py:mod:`pynspect.compilers` module.
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

    def test_01_utilities(self):
        """
        Perform basic compilation tests.
        """
        self.maxDiff = None

        self.assertEqual(clean_variable('Target.IP4'), 'Target.IP4')
        self.assertEqual(clean_variable('Target[1].IP4'), 'Target.IP4')
        self.assertEqual(clean_variable('Target[1].IP4[22]'), 'Target.IP4')

    def test_02_compilation_callbacks(self):
        """
        Perform basic compilation callback tests.
        """
        self.maxDiff = None

        self.assertEqual(
            repr(compile_ip_v4(ConstantRule('192.168.1.1'))),
            "IPV4(IP4('192.168.1.1'))"
        )
        self.assertEqual(
            repr(compile_ip_v6(ConstantRule('::1'))),
            "IPV6(IP6('::1'))"
        )
        self.assertEqual(
            repr(compile_datetime(ConstantRule('2016-06-21T13:08:27Z'))),
            "DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27))"
        )
        self.assertEqual(
            repr(compile_datetime(ConstantRule('1527155786'))),
            "DATETIME({0!r})".format(datetime.fromtimestamp(1527155786))
        )
        self.assertEqual(
            repr(compile_timedelta(NumberRule('3600'))),
            "TIMEDELTA(datetime.timedelta(0, 3600))"
        )
        self.assertEqual(
            repr(compile_timedelta(ConstantRule('3600'))),
            "TIMEDELTA(datetime.timedelta(0, 3600))"
        )
        self.assertEqual(
            repr(compile_timedelta(ConstantRule('15:15:15'))),
            "TIMEDELTA(datetime.timedelta(0, 54915))"
        )
        self.assertEqual(
            repr(compile_timedelta(ConstantRule('15D15:15:15'))),
            "TIMEDELTA(datetime.timedelta(15, 54915))"
        )
        self.assertEqual(
            repr(compile_timedelta(ConstantRule('15d15:15:15'))),
            "TIMEDELTA(datetime.timedelta(15, 54915))"
        )
        self.assertEqual(
            repr(compile_timeoper(ConstantRule('2016-06-21T13:08:27Z'))),
            "DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27))"
        )
        self.assertEqual(
            repr(compile_timeoper(ConstantRule('1527155786'))),
            "DATETIME({0!r})".format(datetime.fromtimestamp(1527155786))
        )
        self.assertEqual(
            repr(compile_timeoper(NumberRule('3600'))),
            "TIMEDELTA(datetime.timedelta(0, 3600))"
        )
        self.assertEqual(
            repr(compile_timeoper(ConstantRule('15:15:15'))),
            "TIMEDELTA(datetime.timedelta(0, 54915))"
        )
        self.assertEqual(
            repr(compile_timeoper(ConstantRule('15D15:15:15'))),
            "TIMEDELTA(datetime.timedelta(15, 54915))"
        )
        self.assertEqual(
            repr(compile_timeoper(ConstantRule('15d15:15:15'))),
            "TIMEDELTA(datetime.timedelta(15, 54915))"
        )


    def test_03_basic_compilations(self):
        """
        Perform basic compilation tests.
        """
        self.maxDiff = None

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
        self.assertEqual(repr(res), "MATHBINOP(INTEGER(9) OP_MINUS MATHBINOP(VARIABLE('Test') OP_PLUS INTEGER(6)))")

        rule = psr.parse('9 - (6 + Test)')
        self.assertEqual(repr(rule), "MATHBINOP(INTEGER(9) OP_MINUS MATHBINOP(INTEGER(6) OP_PLUS VARIABLE('Test')))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "MATHBINOP(INTEGER(9) OP_MINUS MATHBINOP(VARIABLE('Test') OP_PLUS INTEGER(6)))")

        rule = psr.parse('(9 - 6) + Test')
        self.assertEqual(repr(rule), "MATHBINOP(MATHBINOP(INTEGER(9) OP_MINUS INTEGER(6)) OP_PLUS VARIABLE('Test'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "MATHBINOP(VARIABLE('Test') OP_PLUS INTEGER(3))")

    def test_03_idea_time_compilations(self):
        """
        Perform IDEA datetime compilation tests.
        """
        self.maxDiff = None

        cpl = IDEAFilterCompiler()
        psr = PynspectFilterParser()
        psr.build()

        rule = psr.parse('(DetectTime == "2016-06-21T13:08:27Z")')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_EQ CONSTANT('2016-06-21T13:08:27Z'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('DetectTime') OP_EQ DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27)))")

        rule = psr.parse('(CreateTime == "2016-06-21T13:08:27Z")')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('CreateTime') OP_EQ CONSTANT('2016-06-21T13:08:27Z'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('CreateTime') OP_EQ DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27)))")

        rule = psr.parse('(EventTime == "2016-06-21T13:08:27Z")')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('EventTime') OP_EQ CONSTANT('2016-06-21T13:08:27Z'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('EventTime') OP_EQ DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27)))")

        rule = psr.parse('(CeaseTime == "2016-06-21T13:08:27Z")')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('CeaseTime') OP_EQ CONSTANT('2016-06-21T13:08:27Z'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('CeaseTime') OP_EQ DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27)))")

        rule = psr.parse('(WinStartTime == "2016-06-21T13:08:27Z")')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('WinStartTime') OP_EQ CONSTANT('2016-06-21T13:08:27Z'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('WinStartTime') OP_EQ DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27)))")

        rule = psr.parse('(WinEndTime == "2016-06-21T13:08:27Z")')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('WinEndTime') OP_EQ CONSTANT('2016-06-21T13:08:27Z'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('WinEndTime') OP_EQ DATETIME(datetime.datetime(2016, 6, 21, 13, 8, 27)))")

    def test_04_idea_ip_compilations(self):
        """
        Perform IDEA IP address compilation tests.
        """
        self.maxDiff = None

        cpl = IDEAFilterCompiler()
        psr = PynspectFilterParser()
        psr.build()

        rule = psr.parse('(Source.IP4 == "192.168.1.1")')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_EQ CONSTANT('192.168.1.1'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('Source.IP4') OP_EQ IPV4(IP4('192.168.1.1')))")

        rule = psr.parse('(Target.IP4 == "192.168.1.1")')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Target.IP4') OP_EQ CONSTANT('192.168.1.1'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('Target.IP4') OP_EQ IPV4(IP4('192.168.1.1')))")

        rule = psr.parse('(Source.IP6 == "::1")')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP6') OP_EQ CONSTANT('::1'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('Source.IP6') OP_EQ IPV6(IP6('::1')))")

        rule = psr.parse('(Target.IP6 == "::1")')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Target.IP6') OP_EQ CONSTANT('::1'))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('Target.IP6') OP_EQ IPV6(IP6('::1')))")

        rule = psr.parse('(Source.IP4 IN ["192.168.1.1","192.168.1.2"])')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP4') OP_IN LIST(CONSTANT('192.168.1.1'), CONSTANT('192.168.1.2')))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('Source.IP4') OP_IN IPLIST(IPV4(IP4('192.168.1.1')), IPV4(IP4('192.168.1.2'))))")

        rule = psr.parse('(Target.IP4 IN ["192.168.1.1","192.168.1.2"])')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Target.IP4') OP_IN LIST(CONSTANT('192.168.1.1'), CONSTANT('192.168.1.2')))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('Target.IP4') OP_IN IPLIST(IPV4(IP4('192.168.1.1')), IPV4(IP4('192.168.1.2'))))")

        rule = psr.parse('(Source.IP6 IN ["::1","::2"])')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Source.IP6') OP_IN LIST(CONSTANT('::1'), CONSTANT('::2')))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('Source.IP6') OP_IN IPLIST(IPV6(IP6('::1')), IPV6(IP6('::2'))))")

        rule = psr.parse('(Target.IP6 IN ["::1","::2"])')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('Target.IP6') OP_IN LIST(CONSTANT('::1'), CONSTANT('::2')))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('Target.IP6') OP_IN IPLIST(IPV6(IP6('::1')), IPV6(IP6('::2'))))")

    def test_05_idea_func_compilations(self):
        """
        Perform IDEA function compilation tests.
        """
        self.maxDiff = None

        cpl = IDEAFilterCompiler()
        psr = PynspectFilterParser()
        psr.build()

        rule = psr.parse('(DetectTime < utcnow())')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_LT FUNCTION(utcnow()))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('DetectTime') OP_LT FUNCTION(utcnow()))")

        rule = psr.parse('(DetectTime < (utcnow() - 3600))')
        self.assertEqual(repr(rule), "COMPBINOP(VARIABLE('DetectTime') OP_LT MATHBINOP(FUNCTION(utcnow()) OP_MINUS INTEGER(3600)))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(VARIABLE('DetectTime') OP_LT MATHBINOP(FUNCTION(utcnow()) OP_MINUS TIMEDELTA(datetime.timedelta(0, 3600))))")

        rule = psr.parse('(DetectTime + 3600) > utcnow()')
        self.assertEqual(repr(rule), "COMPBINOP(MATHBINOP(VARIABLE('DetectTime') OP_PLUS INTEGER(3600)) OP_GT FUNCTION(utcnow()))")
        res = cpl.compile(rule)
        self.assertEqual(repr(res), "COMPBINOP(MATHBINOP(VARIABLE('DetectTime') OP_PLUS TIMEDELTA(datetime.timedelta(0, 3600))) OP_GT FUNCTION(utcnow()))")


#-------------------------------------------------------------------------------


if __name__ == '__main__':
    unittest.main()
