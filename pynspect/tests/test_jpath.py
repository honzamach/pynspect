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
Unit test module for testing the :py:mod:`pynspect.jpath` module.
"""


__author__ = "Jan Mach <jan.mach@cesnet.cz>"
__credits__ = "Pavel Kácha <pavel.kacha@cesnet.cz>"


import unittest

from idea import lite
from pynspect.jpath import JPathException, cache_size, cache_clear,\
    jpath_parse, jpath_parse_c, jpath_exists, jpath_set, jpath_value, jpath_values,\
    RC_VALUE_DUPLICATE, RC_VALUE_EXISTS, RC_VALUE_SET


# Monkeypatching for Py 2 & 3 compatibility, taken from typedcols package.
if not hasattr(unittest.TestCase, "assertRaisesRegex"):
    unittest.TestCase.assertRaisesRegex = unittest.TestCase.assertRaisesRegexp


#-------------------------------------------------------------------------------
# NOTE: Sorry for the long lines in this file. They are deliberate, because the
# assertion permutations are (IMHO) more readable this way.
#-------------------------------------------------------------------------------


class TestJPath(unittest.TestCase):
    """
    Unit test class for testing the :py:mod:`pynspect.jpath` module.
    """

    msg_dict = {
        "Format": "IDEA0",
        "ID": "MESSAGE_ID",
        "DetectTime": "2016-06-21 13:08:27Z",
        "Category": ["CATEGORY"],
        "ConnCount": 633,
        "Description": "Ping scan",
        "Source": [
            {
                "IP4": ["192.168.1.1", "192.168.1.2"],
                "Proto": ["icmp"]
            },
            {
                "IP4": ["192.168.2.1", "192.168.2.2"],
                "Proto": ["tcp"]
            }
        ],
        "Target": [
            {
                "Proto": ["udp"],
                "IP4": ["192.168.3.1", "192.168.3.2"],
                "Anonymised": True
            }
        ],
        "Node": [
            {
                "SW" : ["KIPPO","FAIL_TO_BAN"],
                "Name" : "node.name"
            }
        ]
    }

    msg_idea = lite.Idea(msg_dict)

    def test_01_jpath_parse(self):
        """
        Perform the basic JPath parsing tests.

        Make sure all possible JPath forms parse correctly.
        """
        self.maxDiff = None

        cache_clear()
        self.assertEqual(cache_size(), 0)

        self.assertEqual(jpath_parse("Test"),           [{'m': 'Test', 'n': 'Test', 'p': 'Test'}])
        self.assertEqual(jpath_parse("Test.Path"),      [{'m': 'Test', 'n': 'Test', 'p': 'Test'}, {'m': 'Path', 'n': 'Path', 'p': 'Test.Path'}])
        self.assertEqual(jpath_parse("Long.Test.Path"), [{'m': 'Long', 'n': 'Long', 'p': 'Long'}, {'m': 'Test', 'n': 'Test', 'p': 'Long.Test'}, {'m': 'Path', 'n': 'Path', 'p': 'Long.Test.Path'}])

        self.assertEqual(jpath_parse("Long[1].Test.Path"),    [{'i': 0, 'm': 'Long[1]', 'n': 'Long', 'p': 'Long[1]'}, {        'm': 'Test',    'n': 'Test', 'p': 'Long[1].Test'},    {        'm': 'Path',    'n': 'Path', 'p': 'Long[1].Test.Path'}])
        self.assertEqual(jpath_parse("Long.Test[2].Path"),    [{        'm': 'Long',    'n': 'Long', 'p': 'Long'},    {'i': 1, 'm': 'Test[2]', 'n': 'Test', 'p': 'Long.Test[2]'},    {        'm': 'Path',    'n': 'Path', 'p': 'Long.Test[2].Path'}])
        self.assertEqual(jpath_parse("Long.Test.Path[3]"),    [{        'm': 'Long',    'n': 'Long', 'p': 'Long'},    {        'm': 'Test',    'n': 'Test', 'p': 'Long.Test'},       {'i': 2, 'm': 'Path[3]', 'n': 'Path', 'p': 'Long.Test.Path[3]'}])
        self.assertEqual(jpath_parse("Long[1].Test[1].Path"), [{'i': 0, 'm': 'Long[1]', 'n': 'Long', 'p': 'Long[1]'}, {'i': 0, 'm': 'Test[1]', 'n': 'Test', 'p': 'Long[1].Test[1]'}, {        'm': 'Path',    'n': 'Path', 'p': 'Long[1].Test[1].Path'}])
        self.assertEqual(jpath_parse("Long.Test[2].Path[2]"), [{        'm': 'Long',    'n': 'Long', 'p': 'Long'},    {'i': 1, 'm': 'Test[2]', 'n': 'Test', 'p': 'Long.Test[2]'},    {'i': 1, 'm': 'Path[2]', 'n': 'Path', 'p': 'Long.Test[2].Path[2]'}])
        self.assertEqual(jpath_parse("Long[3].Test.Path[3]"), [{'i': 2, 'm': 'Long[3]', 'n': 'Long', 'p': 'Long[3]'}, {        'm': 'Test',    'n': 'Test', 'p': 'Long[3].Test'},    {'i': 2, 'm': 'Path[3]', 'n': 'Path', 'p': 'Long[3].Test.Path[3]'}])

        self.assertEqual(jpath_parse("Long[#].Test.Path"),    [{'i': -1, 'm': 'Long[#]', 'n': 'Long', 'p': 'Long[#]'}, {         'm': 'Test',    'n': 'Test', 'p': 'Long[#].Test'},    {         'm': 'Path',    'n': 'Path', 'p': 'Long[#].Test.Path'}])
        self.assertEqual(jpath_parse("Long.Test[#].Path"),    [{         'm': 'Long',    'n': 'Long', 'p': 'Long'},    {'i': -1, 'm': 'Test[#]', 'n': 'Test', 'p': 'Long.Test[#]'},    {         'm': 'Path',    'n': 'Path', 'p': 'Long.Test[#].Path'}])
        self.assertEqual(jpath_parse("Long.Test.Path[#]"),    [{         'm': 'Long',    'n': 'Long', 'p': 'Long'},    {         'm': 'Test',    'n': 'Test', 'p': 'Long.Test'},       {'i': -1, 'm': 'Path[#]', 'n': 'Path', 'p': 'Long.Test.Path[#]'}])
        self.assertEqual(jpath_parse("Long[#].Test[#].Path"), [{'i': -1, 'm': 'Long[#]', 'n': 'Long', 'p': 'Long[#]'}, {'i': -1, 'm': 'Test[#]', 'n': 'Test', 'p': 'Long[#].Test[#]'}, {         'm': 'Path',    'n': 'Path', 'p': 'Long[#].Test[#].Path'}])
        self.assertEqual(jpath_parse("Long.Test[#].Path[#]"), [{         'm': 'Long',    'n': 'Long', 'p': 'Long'},    {'i': -1, 'm': 'Test[#]', 'n': 'Test', 'p': 'Long.Test[#]'},    {'i': -1, 'm': 'Path[#]', 'n': 'Path', 'p': 'Long.Test[#].Path[#]'}])
        self.assertEqual(jpath_parse("Long[#].Test.Path[#]"), [{'i': -1, 'm': 'Long[#]', 'n': 'Long', 'p': 'Long[#]'}, {         'm': 'Test',    'n': 'Test', 'p': 'Long[#].Test'},    {'i': -1, 'm': 'Path[#]', 'n': 'Path', 'p': 'Long[#].Test.Path[#]'}])

        self.assertEqual(jpath_parse("Long[*].Test.Path"),    [{'i': '*', 'm': 'Long[*]', 'n': 'Long', 'p': 'Long[*]'}, {          'm': 'Test',    'n': 'Test', 'p': 'Long[*].Test'},    {          'm': 'Path',    'n': 'Path', 'p': 'Long[*].Test.Path'}])
        self.assertEqual(jpath_parse("Long.Test[*].Path"),    [{          'm': 'Long',    'n': 'Long', 'p': 'Long'},    {'i': '*', 'm': 'Test[*]', 'n': 'Test', 'p': 'Long.Test[*]'},    {          'm': 'Path',    'n': 'Path', 'p': 'Long.Test[*].Path'}])
        self.assertEqual(jpath_parse("Long.Test.Path[*]"),    [{          'm': 'Long',    'n': 'Long', 'p': 'Long'},    {          'm': 'Test',    'n': 'Test', 'p': 'Long.Test'},       {'i': '*', 'm': 'Path[*]', 'n': 'Path', 'p': 'Long.Test.Path[*]'}])
        self.assertEqual(jpath_parse("Long[*].Test[*].Path"), [{'i': '*', 'm': 'Long[*]', 'n': 'Long', 'p': 'Long[*]'}, {'i': '*', 'm': 'Test[*]', 'n': 'Test', 'p': 'Long[*].Test[*]'}, {          'm': 'Path',    'n': 'Path', 'p': 'Long[*].Test[*].Path'}])
        self.assertEqual(jpath_parse("Long.Test[*].Path[*]"), [{          'm': 'Long',    'n': 'Long', 'p': 'Long'},    {'i': '*', 'm': 'Test[*]', 'n': 'Test', 'p': 'Long.Test[*]'},    {'i': '*', 'm': 'Path[*]', 'n': 'Path', 'p': 'Long.Test[*].Path[*]'}])
        self.assertEqual(jpath_parse("Long[*].Test.Path[*]"), [{'i': '*', 'm': 'Long[*]', 'n': 'Long', 'p': 'Long[*]'}, {          'm': 'Test',    'n': 'Test', 'p': 'Long[*].Test'},    {'i': '*', 'm': 'Path[*]', 'n': 'Path', 'p': 'Long[*].Test.Path[*]'}])

        self.assertEqual(jpath_parse("Test"),  [{'m': 'Test',  'n': 'Test',  'p': 'Test'}])
        self.assertEqual(jpath_parse("test"),  [{'m': 'test',  'n': 'test',  'p': 'test'}])
        self.assertEqual(jpath_parse("TEST"),  [{'m': 'TEST',  'n': 'TEST',  'p': 'TEST'}])
        self.assertEqual(jpath_parse("_test"), [{'m': '_test', 'n': '_test', 'p': '_test'}])

        self.assertRaisesRegex(JPathException, "Invalid JPath chunk", jpath_parse, 'Test/Value')
        self.assertRaisesRegex(JPathException, "Invalid JPath chunk", jpath_parse, 'Test|Value')
        self.assertRaisesRegex(JPathException, "Invalid JPath chunk", jpath_parse, 'Test-Value')
        self.assertRaisesRegex(JPathException, "Invalid JPath chunk", jpath_parse, 'Test-.Value')
        self.assertRaisesRegex(JPathException, "Invalid JPath chunk", jpath_parse, 'Test[]Value')
        self.assertRaisesRegex(JPathException, "Invalid JPath chunk", jpath_parse, 'TestValue[]')
        self.assertRaisesRegex(JPathException, "Invalid JPath chunk", jpath_parse, 'Test[1]Value')
        self.assertRaisesRegex(JPathException, "Invalid JPath chunk", jpath_parse, 'Test[].Value')
        self.assertRaisesRegex(JPathException, "Invalid JPath chunk", jpath_parse, 'Test.Value[]')
        self.assertRaisesRegex(JPathException, "Invalid JPath chunk", jpath_parse, 'Test[-1].Value')
        self.assertRaisesRegex(JPathException, "Invalid JPath chunk", jpath_parse, 'Test.[1].Value')
        self.assertRaisesRegex(JPathException, "Invalid JPath chunk", jpath_parse, 'Test.Value.[1]')

        self.assertEqual(jpath_parse_c("Test"),           [{'m': 'Test', 'n': 'Test', 'p': 'Test'}])
        self.assertEqual(jpath_parse_c("Test.Path"),      [{'m': 'Test', 'n': 'Test', 'p': 'Test'}, {'m': 'Path', 'n': 'Path', 'p': 'Test.Path'}])
        self.assertEqual(jpath_parse_c("Long.Test.Path"), [{'m': 'Long', 'n': 'Long', 'p': 'Long'}, {'m': 'Test', 'n': 'Test', 'p': 'Long.Test'}, {'m': 'Path', 'n': 'Path', 'p': 'Long.Test.Path'}])
        self.assertEqual(jpath_parse_c("Test"),           [{'m': 'Test', 'n': 'Test', 'p': 'Test'}])
        self.assertEqual(jpath_parse_c("Test.Path"),      [{'m': 'Test', 'n': 'Test', 'p': 'Test'}, {'m': 'Path', 'n': 'Path', 'p': 'Test.Path'}])
        self.assertEqual(jpath_parse_c("Long.Test.Path"), [{'m': 'Long', 'n': 'Long', 'p': 'Long'}, {'m': 'Test', 'n': 'Test', 'p': 'Long.Test'}, {'m': 'Path', 'n': 'Path', 'p': 'Long.Test.Path'}])

        self.assertEqual(cache_size(), 3)
        cache_clear()
        self.assertEqual(cache_size(), 0)

    def test_02_jpath_values_dict(self):
        """
        Perform the basic JPath values retrieval tests on regular Python dict.

        Make sure all possible JPath forms return expected results.
        """
        self.maxDiff = None

        self.assertEqual(jpath_values(self.msg_dict, 'Format'),    ['IDEA0'])
        self.assertEqual(jpath_values(self.msg_dict, 'Format[1]'), [])
        self.assertEqual(jpath_values(self.msg_dict, 'Format[#]'), [])
        self.assertEqual(jpath_values(self.msg_dict, 'Format[*]'), [])

        self.assertEqual(jpath_values(self.msg_dict, 'Category'),    ['CATEGORY'])
        self.assertEqual(jpath_values(self.msg_dict, 'Category[1]'), ['CATEGORY'])
        self.assertEqual(jpath_values(self.msg_dict, 'Category[2]'), [])
        self.assertEqual(jpath_values(self.msg_dict, 'Category[#]'), ['CATEGORY'])
        self.assertEqual(jpath_values(self.msg_dict, 'Category[*]'), ['CATEGORY'])

        self.assertEqual(jpath_values(self.msg_dict, 'Node.SW'),       ['KIPPO','FAIL_TO_BAN'])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[1].SW'),    ['KIPPO','FAIL_TO_BAN'])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[#].SW'),    ['KIPPO','FAIL_TO_BAN'])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[*].SW'),    ['KIPPO','FAIL_TO_BAN'])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[#].SW[1]'), ['KIPPO'])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[#].SW[2]'), ['FAIL_TO_BAN'])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[#].SW[#]'), ['FAIL_TO_BAN'])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[#].SW[*]'), ['KIPPO','FAIL_TO_BAN'])

        self.assertEqual(jpath_values(self.msg_dict, 'Node.Name'),       ['node.name'])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[1].Name'),    ['node.name'])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[#].Name'),    ['node.name'])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[*].Name'),    ['node.name'])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[1].Name[1]'), [])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[#].Name[#]'), [])
        self.assertEqual(jpath_values(self.msg_dict, 'Node[*].Name[*]'), [])

        self.assertEqual(jpath_values(self.msg_dict, 'Source.IP4'),       ['192.168.1.1','192.168.1.2','192.168.2.1','192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[1].IP4'),    ['192.168.1.1','192.168.1.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[2].IP4'),    ['192.168.2.1','192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[#].IP4'),    ['192.168.2.1','192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[*].IP4'),    ['192.168.1.1','192.168.1.2','192.168.2.1','192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source.IP4[1]'),    ['192.168.1.1','192.168.2.1'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source.IP4[2]'),    ['192.168.1.2','192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source.IP4[#]'),    ['192.168.1.2','192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source.IP4[*]'),    ['192.168.1.1','192.168.1.2','192.168.2.1','192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[1].IP4[1]'), ['192.168.1.1'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[1].IP4[2]'), ['192.168.1.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[1].IP4[#]'), ['192.168.1.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[1].IP4[*]'), ['192.168.1.1','192.168.1.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[2].IP4[1]'), ['192.168.2.1'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[2].IP4[2]'), ['192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[2].IP4[#]'), ['192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[2].IP4[*]'), ['192.168.2.1','192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[#].IP4[1]'), ['192.168.2.1'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[#].IP4[2]'), ['192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[#].IP4[#]'), ['192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[#].IP4[*]'), ['192.168.2.1','192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[*].IP4[1]'), ['192.168.1.1','192.168.2.1'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[*].IP4[2]'), ['192.168.1.2','192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[*].IP4[#]'), ['192.168.1.2','192.168.2.2'])
        self.assertEqual(jpath_values(self.msg_dict, 'Source[*].IP4[*]'), ['192.168.1.1','192.168.1.2','192.168.2.1','192.168.2.2'])

    def test_03_jpath_values_idea(self):
        """
        Perform the basic JPath values retrieval tests on :py:mod:`idea.lite` object.

        Make sure all possible JPath forms return expected results.
        """
        self.maxDiff = None

        self.assertEqual(jpath_values(self.msg_idea, 'Format'),    ['IDEA0'])
        self.assertEqual(jpath_values(self.msg_idea, 'Format[1]'), [])
        self.assertEqual(jpath_values(self.msg_idea, 'Format[#]'), [])
        self.assertEqual(jpath_values(self.msg_idea, 'Format[*]'), [])

        self.assertEqual(jpath_values(self.msg_idea, 'Category'),    ['CATEGORY'])
        self.assertEqual(jpath_values(self.msg_idea, 'Category[1]'), ['CATEGORY'])
        self.assertEqual(jpath_values(self.msg_idea, 'Category[2]'), [])
        self.assertEqual(jpath_values(self.msg_idea, 'Category[#]'), ['CATEGORY'])
        self.assertEqual(jpath_values(self.msg_idea, 'Category[*]'), ['CATEGORY'])

        self.assertEqual(jpath_values(self.msg_idea, 'Node.SW'),       ['KIPPO','FAIL_TO_BAN'])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[1].SW'),    ['KIPPO','FAIL_TO_BAN'])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[#].SW'),    ['KIPPO','FAIL_TO_BAN'])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[*].SW'),    ['KIPPO','FAIL_TO_BAN'])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[#].SW[1]'), ['KIPPO'])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[#].SW[2]'), ['FAIL_TO_BAN'])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[#].SW[#]'), ['FAIL_TO_BAN'])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[#].SW[*]'), ['KIPPO','FAIL_TO_BAN'])

        self.assertEqual(jpath_values(self.msg_idea, 'Node.Name'),       ['node.name'])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[1].Name'),    ['node.name'])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[#].Name'),    ['node.name'])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[*].Name'),    ['node.name'])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[1].Name[1]'), [])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[#].Name[#]'), [])
        self.assertEqual(jpath_values(self.msg_idea, 'Node[*].Name[*]'), [])


    def test_04_jpath_value_dict(self):
        """
        Perform the basic JPath value retrieval tests on regular Python dict.

        Make sure all possible JPath forms return expected results.
        """
        self.maxDiff = None

        self.assertEqual(jpath_value(self.msg_dict, 'Format'),    'IDEA0')
        self.assertEqual(jpath_value(self.msg_dict, 'Format[1]'), None)
        self.assertEqual(jpath_value(self.msg_dict, 'Format[#]'), None)
        self.assertEqual(jpath_value(self.msg_dict, 'Format[*]'), None)

        self.assertEqual(jpath_value(self.msg_dict, 'Category'),    'CATEGORY')
        self.assertEqual(jpath_value(self.msg_dict, 'Category[1]'), 'CATEGORY')
        self.assertEqual(jpath_value(self.msg_dict, 'Category[2]'), None)
        self.assertEqual(jpath_value(self.msg_dict, 'Category[#]'), 'CATEGORY')
        self.assertEqual(jpath_value(self.msg_dict, 'Category[*]'), 'CATEGORY')

        self.assertEqual(jpath_value(self.msg_dict, 'Node.SW'),       'KIPPO')
        self.assertEqual(jpath_value(self.msg_dict, 'Node[1].SW'),    'KIPPO')
        self.assertEqual(jpath_value(self.msg_dict, 'Node[#].SW'),    'KIPPO')
        self.assertEqual(jpath_value(self.msg_dict, 'Node[*].SW'),    'KIPPO')
        self.assertEqual(jpath_value(self.msg_dict, 'Node[#].SW[1]'), 'KIPPO')
        self.assertEqual(jpath_value(self.msg_dict, 'Node[#].SW[2]'), 'FAIL_TO_BAN')
        self.assertEqual(jpath_value(self.msg_dict, 'Node[#].SW[#]'), 'FAIL_TO_BAN')
        self.assertEqual(jpath_value(self.msg_dict, 'Node[#].SW[*]'), 'KIPPO')

        self.assertEqual(jpath_value(self.msg_dict, 'Node.Name'),       'node.name')
        self.assertEqual(jpath_value(self.msg_dict, 'Node[1].Name'),    'node.name')
        self.assertEqual(jpath_value(self.msg_dict, 'Node[#].Name'),    'node.name')
        self.assertEqual(jpath_value(self.msg_dict, 'Node[*].Name'),    'node.name')
        self.assertEqual(jpath_value(self.msg_dict, 'Node[1].Name[1]'), None)
        self.assertEqual(jpath_value(self.msg_dict, 'Node[#].Name[#]'), None)
        self.assertEqual(jpath_value(self.msg_dict, 'Node[*].Name[*]'), None)

        self.assertEqual(jpath_value(self.msg_dict, 'Source.IP4'),       '192.168.1.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[1].IP4'),    '192.168.1.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[2].IP4'),    '192.168.2.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[#].IP4'),    '192.168.2.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[*].IP4'),    '192.168.1.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source.IP4[1]'),    '192.168.1.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source.IP4[2]'),    '192.168.1.2')
        self.assertEqual(jpath_value(self.msg_dict, 'Source.IP4[#]'),    '192.168.1.2')
        self.assertEqual(jpath_value(self.msg_dict, 'Source.IP4[*]'),    '192.168.1.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[1].IP4[1]'), '192.168.1.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[1].IP4[2]'), '192.168.1.2')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[1].IP4[#]'), '192.168.1.2')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[1].IP4[*]'), '192.168.1.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[2].IP4[1]'), '192.168.2.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[2].IP4[2]'), '192.168.2.2')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[2].IP4[#]'), '192.168.2.2')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[2].IP4[*]'), '192.168.2.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[#].IP4[1]'), '192.168.2.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[#].IP4[2]'), '192.168.2.2')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[#].IP4[#]'), '192.168.2.2')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[#].IP4[*]'), '192.168.2.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[*].IP4[1]'), '192.168.1.1')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[*].IP4[2]'), '192.168.1.2')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[*].IP4[#]'), '192.168.1.2')
        self.assertEqual(jpath_value(self.msg_dict, 'Source[*].IP4[*]'), '192.168.1.1')


    def test_05_jpath_value_idea(self):
        """
        Perform the basic JPath value retrieval tests on :py:mod:`idea.lite` object.

        Make sure all possible JPath forms return expected results.
        """
        self.maxDiff = None

        self.assertEqual(jpath_value(self.msg_idea, 'Format'),    'IDEA0')
        self.assertEqual(jpath_value(self.msg_idea, 'Format[1]'), None)
        self.assertEqual(jpath_value(self.msg_idea, 'Format[#]'), None)
        self.assertEqual(jpath_value(self.msg_idea, 'Format[*]'), None)

        self.assertEqual(jpath_value(self.msg_idea, 'Category'),    'CATEGORY')
        self.assertEqual(jpath_value(self.msg_idea, 'Category[1]'), 'CATEGORY')
        self.assertEqual(jpath_value(self.msg_idea, 'Category[2]'), None)
        self.assertEqual(jpath_value(self.msg_idea, 'Category[#]'), 'CATEGORY')
        self.assertEqual(jpath_value(self.msg_idea, 'Category[*]'), 'CATEGORY')

        self.assertEqual(jpath_value(self.msg_idea, 'Node.SW'),       'KIPPO')
        self.assertEqual(jpath_value(self.msg_idea, 'Node[1].SW'),    'KIPPO')
        self.assertEqual(jpath_value(self.msg_idea, 'Node[#].SW'),    'KIPPO')
        self.assertEqual(jpath_value(self.msg_idea, 'Node[*].SW'),    'KIPPO')
        self.assertEqual(jpath_value(self.msg_idea, 'Node[#].SW[1]'), 'KIPPO')
        self.assertEqual(jpath_value(self.msg_idea, 'Node[#].SW[2]'), 'FAIL_TO_BAN')
        self.assertEqual(jpath_value(self.msg_idea, 'Node[#].SW[#]'), 'FAIL_TO_BAN')
        self.assertEqual(jpath_value(self.msg_idea, 'Node[#].SW[*]'), 'KIPPO')

        self.assertEqual(jpath_value(self.msg_idea, 'Node.Name'),       'node.name')
        self.assertEqual(jpath_value(self.msg_idea, 'Node[1].Name'),    'node.name')
        self.assertEqual(jpath_value(self.msg_idea, 'Node[#].Name'),    'node.name')
        self.assertEqual(jpath_value(self.msg_idea, 'Node[*].Name'),    'node.name')
        self.assertEqual(jpath_value(self.msg_idea, 'Node[1].Name[1]'), None)
        self.assertEqual(jpath_value(self.msg_idea, 'Node[#].Name[#]'), None)
        self.assertEqual(jpath_value(self.msg_idea, 'Node[*].Name[*]'), None)


    def test_06_jpath_exists_dict(self):
        """
        Perform the basic JPath elements existence tests on regular Python dict.

        Make sure all possible JPath forms return expected results.
        """
        self.maxDiff = None

        self.assertEqual(jpath_exists(self.msg_dict, 'Format'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Format[1]'), False)
        self.assertEqual(jpath_exists(self.msg_dict, 'Format[#]'), False)
        self.assertEqual(jpath_exists(self.msg_dict, 'Format[*]'), False)

        self.assertEqual(jpath_exists(self.msg_dict, 'Category'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Category[1]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Category[2]'), False)
        self.assertEqual(jpath_exists(self.msg_dict, 'Category[#]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Category[*]'), True)

        self.assertEqual(jpath_exists(self.msg_dict, 'Node.SW'),       True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[1].SW'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[#].SW'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[*].SW'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[#].SW[1]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[#].SW[2]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[#].SW[#]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[#].SW[*]'), True)

        self.assertEqual(jpath_exists(self.msg_dict, 'Node.Name'),       True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[1].Name'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[#].Name'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[*].Name'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[1].Name[1]'), False)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[#].Name[#]'), False)
        self.assertEqual(jpath_exists(self.msg_dict, 'Node[*].Name[*]'), False)

        self.assertEqual(jpath_exists(self.msg_dict, 'Source.IP4'),       True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[1].IP4'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[2].IP4'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[#].IP4'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[*].IP4'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source.IP4[1]'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source.IP4[2]'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source.IP4[#]'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source.IP4[*]'),    True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[1].IP4[1]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[1].IP4[2]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[1].IP4[#]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[1].IP4[*]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[2].IP4[1]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[2].IP4[2]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[2].IP4[#]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[2].IP4[*]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[#].IP4[1]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[#].IP4[2]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[#].IP4[#]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[#].IP4[*]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[*].IP4[1]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[*].IP4[2]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[*].IP4[#]'), True)
        self.assertEqual(jpath_exists(self.msg_dict, 'Source[*].IP4[*]'), True)


    def test_07_jpath_exists_idea(self):
        """
        Perform the basic JPath elements existence tests on :py:mod:`idea.lite` object.

        Make sure all possible JPath forms return expected results.
        """
        self.maxDiff = None

        self.assertEqual(jpath_exists(self.msg_idea, 'Format'),    True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Format[1]'), False)
        self.assertEqual(jpath_exists(self.msg_idea, 'Format[#]'), False)
        self.assertEqual(jpath_exists(self.msg_idea, 'Format[*]'), False)

        self.assertEqual(jpath_exists(self.msg_idea, 'Category'),    True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Category[1]'), True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Category[2]'), False)
        self.assertEqual(jpath_exists(self.msg_idea, 'Category[#]'), True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Category[*]'), True)

        self.assertEqual(jpath_exists(self.msg_idea, 'Node.SW'),       True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[1].SW'),    True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[#].SW'),    True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[*].SW'),    True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[#].SW[1]'), True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[#].SW[2]'), True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[#].SW[#]'), True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[#].SW[*]'), True)

        self.assertEqual(jpath_exists(self.msg_idea, 'Node.Name'),       True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[1].Name'),    True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[#].Name'),    True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[*].Name'),    True)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[1].Name[1]'), False)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[#].Name[#]'), False)
        self.assertEqual(jpath_exists(self.msg_idea, 'Node[*].Name[*]'), False)


    def test_08_jpath_set(self):
        """
        Perform the basic JPath value setting tests.
        """
        self.maxDiff = None

        msg = {}
        self.assertEqual(jpath_set(msg, 'TestA.ValueA1', 'A1'), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestA': { 'ValueA1': 'A1'}
            }
        )
        self.assertEqual(jpath_set(msg, 'TestA.ValueA2', 'A2'), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestA': { 'ValueA1': 'A1', 'ValueA2': 'A2' }
            }
        )
        self.assertEqual(jpath_set(msg, 'TestB[1].ValueB1', 'B1'), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestA': { 'ValueA1': 'A1', 'ValueA2': 'A2' },
                'TestB': [{ 'ValueB1': 'B1' }]
            }
        )
        self.assertEqual(jpath_set(msg, 'TestB[#].ValueB2', 'B2'), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestA': { 'ValueA1': 'A1', 'ValueA2': 'A2' },
                'TestB': [{ 'ValueB1': 'B1', 'ValueB2': 'B2' }]
            }
        )
        self.assertEqual(jpath_set(msg, 'TestB[*].ValueB3', 'B3'), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestA': { 'ValueA1': 'A1', 'ValueA2': 'A2' },
                'TestB': [{ 'ValueB1': 'B1', 'ValueB2': 'B2' }, { 'ValueB3': 'B3' }]
            }
        )
        self.assertEqual(jpath_set(msg, 'TestB[#].ValueB4', 'B4'), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestA': { 'ValueA1': 'A1', 'ValueA2': 'A2' },
                'TestB': [{ 'ValueB1': 'B1', 'ValueB2': 'B2' }, { 'ValueB3': 'B3', 'ValueB4': 'B4' }]
            }
        )
        self.assertEqual(jpath_set(msg, 'TestB[#]', 'DROP'), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestA': { 'ValueA1': 'A1', 'ValueA2': 'A2' },
                'TestB': [{ 'ValueB1': 'B1', 'ValueB2': 'B2' }, "DROP"]
            }
        )

        # This will fail, because "TestA" node is not a list
        self.assertRaisesRegex(JPathException, "Expected list-like object under structure key", jpath_set, msg, 'TestA[#].ValueC1', 'C1')

        # This will fail, because "TestA.ValueA1" node is not a dict
        self.assertRaisesRegex(JPathException, "Expected dict-like object under structure key", jpath_set, msg, 'TestA.ValueA1.ValueC1', 'C1')

        # This will fail, because we try to attach a node to scalar "TestB[#]"
        self.assertRaisesRegex(JPathException, "Expected dict-like structure to attach node", jpath_set, msg, 'TestB[#].ValueB5', 'RAISE EXCEPTION')


    def test_09_jpath_set_unique(self):
        """
        Perform JPath value setting tests with unique flag.
        """
        self.maxDiff = None

        msg = {}
        self.assertEqual(jpath_set(msg, 'TestC[#].ListVals1[*]', 'LV1', unique = True), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestC': [{ 'ListVals1': ['LV1']}]
            }
        )
        self.assertEqual(jpath_set(msg, 'TestC[#].ListVals1[*]', 'LV2', unique = True), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestC': [{ 'ListVals1': ['LV1','LV2']}]
            }
        )
        self.assertEqual(jpath_set(msg, 'TestC[#].ListVals1[*]', 'LV1', unique = True), RC_VALUE_DUPLICATE)
        self.assertEqual(
            msg,
            {
                'TestC': [{ 'ListVals1': ['LV1','LV2']}]
            }
        )


    def test_10_jpath_set_overwrite(self):
        """
        Perform JPath value setting tests with overwrite flag.
        """
        self.maxDiff = None

        msg = {}

        #
        # Overwriting in lists.
        #
        self.assertEqual(jpath_set(msg, 'TestD[#].ListVals1[*]', 'LV1', overwrite = False), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestD': [{ 'ListVals1': ['LV1']}]
            }
        )
        self.assertEqual(jpath_set(msg, 'TestD[#].ListVals1[*]', 'LV2', overwrite = False), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestD': [{ 'ListVals1': ['LV1','LV2']}]
            }
        )
        self.assertEqual(jpath_set(msg, 'TestD[#].ListVals1[2]', 'LV3', overwrite = False), RC_VALUE_EXISTS)
        self.assertEqual(
            msg,
            {
                'TestD': [{ 'ListVals1': ['LV1','LV2']}]
            }
        )
        self.assertEqual(jpath_set(msg, 'TestD[#].ListVals1[3]', 'LV3', overwrite = False), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestD': [{ 'ListVals1': ['LV1','LV2','LV3']}]
            }
        )

        #
        # Overwriting in dicts.
        #
        self.assertEqual(jpath_set(msg, 'TestD[#].DictVal', 'DV1', overwrite = False), RC_VALUE_SET)
        self.assertEqual(
            msg,
            {
                'TestD': [{ 'ListVals1': ['LV1','LV2','LV3'], 'DictVal': 'DV1' }]
            }
        )
        self.assertEqual(jpath_set(msg, 'TestD[#].DictVal', 'DV2', overwrite = False), RC_VALUE_EXISTS)
        self.assertEqual(
            msg,
            {
                'TestD': [{ 'ListVals1': ['LV1','LV2','LV3'], 'DictVal': 'DV1' }]
            }
        )


#-------------------------------------------------------------------------------


if __name__ == "__main__":
    unittest.main()
