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
Unit test module for testing the :py:mod:`pynspect.lexer` module.
"""


__author__ = "Jan Mach <jan.mach@cesnet.cz>"
__credits__ = "Pavel Kácha <pavel.kacha@cesnet.cz>"


import unittest

from pynspect.lexer import PynspectFilterLexer


#-------------------------------------------------------------------------------
# NOTE: Sorry for the long lines in this file. They are deliberate, because the
# assertion permutations are (IMHO) more readable this way.
#-------------------------------------------------------------------------------


class TestPynspectFilterLexer(unittest.TestCase):
    """
    Unit test class for testing the :py:mod:`pynspect.lexer` module.
    """

    def setUp(self):
        self.lex = PynspectFilterLexer()
        self.lex.build()

    def test_01_symbols(self):
        """
        Check, that all lexical tokens for symbols are correctly recognized.
        """
        self.maxDiff = None

        self.assertEqual(self.lex.test('+-*/%'), "LexToken(OP_PLUS,'OP_PLUS',1,0)LexToken(OP_MINUS,'OP_MINUS',1,1)LexToken(OP_TIMES,'OP_TIMES',1,2)LexToken(OP_DIVIDE,'OP_DIVIDE',1,3)LexToken(OP_MODULO,'OP_MODULO',1,4)")

        self.assertEqual(self.lex.test(','),     "LexToken(COMMA,',',1,0)")
        self.assertEqual(self.lex.test(', '),    "LexToken(COMMA,', ',1,0)")
        self.assertEqual(self.lex.test(' , '),   "LexToken(COMMA,', ',1,1)")
        self.assertEqual(self.lex.test('  ,  '), "LexToken(COMMA,',  ',1,2)")
        self.assertEqual(self.lex.test(';'),     "LexToken(COMMA,';',1,0)")
        self.assertEqual(self.lex.test('; '),    "LexToken(COMMA,'; ',1,0)")
        self.assertEqual(self.lex.test(' ; '),   "LexToken(COMMA,'; ',1,1)")
        self.assertEqual(self.lex.test('  ;  '), "LexToken(COMMA,';  ',1,2)")

        self.assertEqual(self.lex.test('()'), "LexToken(LPAREN,'(',1,0)LexToken(RPAREN,')',1,1)")
        self.assertEqual(self.lex.test('[]'), "LexToken(LBRACK,'[',1,0)LexToken(RBRACK,']',1,1)")


    def test_02_operations(self):
        """
        Check, that all lexical tokens for operations are correctly recognized.
        """
        self.maxDiff = None

        self.assertEqual(self.lex.test('OR or ||'),        "LexToken(OP_OR,'OP_OR',1,0)LexToken(OP_OR,'OP_OR',1,3)LexToken(OP_OR_P,'OP_OR_P',1,6)")
        self.assertEqual(self.lex.test('XOR xor ^^'),      "LexToken(OP_XOR,'OP_XOR',1,0)LexToken(OP_XOR,'OP_XOR',1,4)LexToken(OP_XOR_P,'OP_XOR_P',1,8)")
        self.assertEqual(self.lex.test('AND and &&'),      "LexToken(OP_AND,'OP_AND',1,0)LexToken(OP_AND,'OP_AND',1,4)LexToken(OP_AND_P,'OP_AND_P',1,8)")
        self.assertEqual(self.lex.test('NOT not !'),       "LexToken(OP_NOT,'OP_NOT',1,0)LexToken(OP_NOT,'OP_NOT',1,4)LexToken(OP_NOT,'OP_NOT',1,8)")
        self.assertEqual(self.lex.test('EXISTS exists ?'), "LexToken(OP_EXISTS,'OP_EXISTS',1,0)LexToken(OP_EXISTS,'OP_EXISTS',1,7)LexToken(OP_EXISTS,'OP_EXISTS',1,14)")

        self.assertEqual(self.lex.test('LIKE like =~'), "LexToken(OP_LIKE,'OP_LIKE',1,0)LexToken(OP_LIKE,'OP_LIKE',1,5)LexToken(OP_LIKE,'OP_LIKE',1,10)")
        self.assertEqual(self.lex.test('IN in ~~'),     "LexToken(OP_IN,'OP_IN',1,0)LexToken(OP_IN,'OP_IN',1,3)LexToken(OP_IN,'OP_IN',1,6)")
        self.assertEqual(self.lex.test('IS is'),        "LexToken(OP_IS,'OP_IS',1,0)LexToken(OP_IS,'OP_IS',1,3)")
        self.assertEqual(self.lex.test('EQ eq =='),     "LexToken(OP_EQ,'OP_EQ',1,0)LexToken(OP_EQ,'OP_EQ',1,3)LexToken(OP_EQ,'OP_EQ',1,6)")
        self.assertEqual(self.lex.test('NE ne <> !='),  "LexToken(OP_NE,'OP_NE',1,0)LexToken(OP_NE,'OP_NE',1,3)LexToken(OP_NE,'OP_NE',1,6)LexToken(OP_NE,'OP_NE',1,9)")
        self.assertEqual(self.lex.test('GT gt >'),      "LexToken(OP_GT,'OP_GT',1,0)LexToken(OP_GT,'OP_GT',1,3)LexToken(OP_GT,'OP_GT',1,6)")
        self.assertEqual(self.lex.test('GE ge >='),     "LexToken(OP_GE,'OP_GE',1,0)LexToken(OP_GE,'OP_GE',1,3)LexToken(OP_GE,'OP_GE',1,6)")
        self.assertEqual(self.lex.test('LT lt <'),      "LexToken(OP_LT,'OP_LT',1,0)LexToken(OP_LT,'OP_LT',1,3)LexToken(OP_LT,'OP_LT',1,6)")
        self.assertEqual(self.lex.test('LE le <='),     "LexToken(OP_LE,'OP_LE',1,0)LexToken(OP_LE,'OP_LE',1,3)LexToken(OP_LE,'OP_LE',1,6)")

    def test_03_constants(self):
        """
        Check, that all lexical tokens for constants are correctly recognized.
        """
        self.maxDiff = None

        self.assertEqual(self.lex.test('127.0.0.1'),            "LexToken(IPV4,('IPV4', '127.0.0.1'),1,0)")
        self.assertEqual(self.lex.test('127.0.0.1/32'),         "LexToken(IPV4,('IPV4', '127.0.0.1/32'),1,0)")
        self.assertEqual(self.lex.test('127.0.0.1-127.0.0.5'),  "LexToken(IPV4,('IPV4', '127.0.0.1-127.0.0.5'),1,0)")
        self.assertEqual(self.lex.test('127.0.0.1..127.0.0.5'), "LexToken(IPV4,('IPV4', '127.0.0.1..127.0.0.5'),1,0)")

        self.assertEqual(self.lex.test('::1'),      "LexToken(IPV6,('IPV6', '::1'),1,0)")
        self.assertEqual(self.lex.test('::1/64'),   "LexToken(IPV6,('IPV6', '::1/64'),1,0)")
        self.assertEqual(self.lex.test('::1-::5'),  "LexToken(IPV6,('IPV6', '::1-::5'),1,0)")
        self.assertEqual(self.lex.test('::1..::5'), "LexToken(IPV6,('IPV6', '::1..::5'),1,0)")

        self.assertEqual(self.lex.test('15'),   "LexToken(INTEGER,('INTEGER', 15),1,0)")
        self.assertEqual(self.lex.test('15.5'), "LexToken(FLOAT,('FLOAT', 15.5),1,0)")

        self.assertEqual(self.lex.test('2017-01-01T12:00:00Z'),     "LexToken(DATETIME,('DATETIME', '2017-01-01T12:00:00Z'),1,0)")
        self.assertEqual(self.lex.test('2017-01-01t12:00:00z'),     "LexToken(DATETIME,('DATETIME', '2017-01-01t12:00:00z'),1,0)")
        self.assertEqual(self.lex.test('2017-01-01T12:00:00.123Z'), "LexToken(DATETIME,('DATETIME', '2017-01-01T12:00:00.123Z'),1,0)")
        self.assertEqual(self.lex.test('2017-01-01t12:00:00.123z'), "LexToken(DATETIME,('DATETIME', '2017-01-01t12:00:00.123z'),1,0)")

        self.assertEqual(self.lex.test('2017-01-01T12:00:00+02:00'),     "LexToken(DATETIME,('DATETIME', '2017-01-01T12:00:00+02:00'),1,0)")
        self.assertEqual(self.lex.test('2017-01-01t12:00:00-02:00'),     "LexToken(DATETIME,('DATETIME', '2017-01-01t12:00:00-02:00'),1,0)")
        self.assertEqual(self.lex.test('2017-01-01T12:00:00.123+02:00'), "LexToken(DATETIME,('DATETIME', '2017-01-01T12:00:00.123+02:00'),1,0)")
        self.assertEqual(self.lex.test('2017-01-01t12:00:00.123-02:00'), "LexToken(DATETIME,('DATETIME', '2017-01-01t12:00:00.123-02:00'),1,0)")

    def test_04_variables(self):
        """
        Check, that all lexical tokens for variables are correctly recognized.
        """
        self.maxDiff = None

        self.assertEqual(self.lex.test('S'),                   "LexToken(VARIABLE,('VARIABLE', 'S'),1,0)")
        self.assertEqual(self.lex.test('S.N'),                 "LexToken(VARIABLE,('VARIABLE', 'S.N'),1,0)")
        self.assertEqual(self.lex.test('Source.Node'),         "LexToken(VARIABLE,('VARIABLE', 'Source.Node'),1,0)")
        self.assertEqual(self.lex.test('Source[1].Node[2]'),   "LexToken(VARIABLE,('VARIABLE', 'Source[1].Node[2]'),1,0)")
        self.assertEqual(self.lex.test('Source[-1].Node[-2]'), "LexToken(VARIABLE,('VARIABLE', 'Source[-1].Node[-2]'),1,0)")
        self.assertEqual(self.lex.test('Source[#].Node[#]'),   "LexToken(VARIABLE,('VARIABLE', 'Source[#].Node[#]'),1,0)")
        self.assertEqual(self.lex.test('"Value 525.89:X><"'),  "LexToken(CONSTANT,('CONSTANT', 'Value 525.89:X><'),1,0)")
        self.assertEqual(self.lex.test("'Value 525.89:X><'"),  "LexToken(CONSTANT,('CONSTANT', 'Value 525.89:X><'),1,0)")

    def test_05_lists(self):
        """
        Check, that all lexical tokens for constant lists are correctly recognized.
        """
        self.maxDiff = None

        self.assertEqual(self.lex.test('[127.0.0.1 , 127.0.0.2]'), "LexToken(LBRACK,'[',1,0)LexToken(IPV4,('IPV4', '127.0.0.1'),1,1)LexToken(COMMA,', ',1,11)LexToken(IPV4,('IPV4', '127.0.0.2'),1,13)LexToken(RBRACK,']',1,22)")
        self.assertEqual(self.lex.test('[::1 , ::2]'), "LexToken(LBRACK,'[',1,0)LexToken(IPV6,('IPV6', '::1'),1,1)LexToken(COMMA,', ',1,5)LexToken(IPV6,('IPV6', '::2'),1,7)LexToken(RBRACK,']',1,10)")
        self.assertEqual(self.lex.test('[1,2, 3,4 , 5 ]'), "LexToken(LBRACK,'[',1,0)LexToken(INTEGER,('INTEGER', 1),1,1)LexToken(COMMA,',',1,2)LexToken(INTEGER,('INTEGER', 2),1,3)LexToken(COMMA,', ',1,4)LexToken(INTEGER,('INTEGER', 3),1,6)LexToken(COMMA,',',1,7)LexToken(INTEGER,('INTEGER', 4),1,8)LexToken(COMMA,', ',1,10)LexToken(INTEGER,('INTEGER', 5),1,12)LexToken(RBRACK,']',1,14)")
        self.assertEqual(self.lex.test('[15.5,16.6, 17.7,18.8 , 19.9 ]'), "LexToken(LBRACK,'[',1,0)LexToken(FLOAT,('FLOAT', 15.5),1,1)LexToken(COMMA,',',1,5)LexToken(FLOAT,('FLOAT', 16.6),1,6)LexToken(COMMA,', ',1,10)LexToken(FLOAT,('FLOAT', 17.7),1,12)LexToken(COMMA,',',1,16)LexToken(FLOAT,('FLOAT', 18.8),1,17)LexToken(COMMA,', ',1,22)LexToken(FLOAT,('FLOAT', 19.9),1,24)LexToken(RBRACK,']',1,29)")
        self.assertEqual(self.lex.test('[Test.Node1,Test.Node2, Test.Node3,Test.Node4 , Test.Node5 ]'), "LexToken(LBRACK,'[',1,0)LexToken(VARIABLE,('VARIABLE', 'Test.Node1'),1,1)LexToken(COMMA,',',1,11)LexToken(VARIABLE,('VARIABLE', 'Test.Node2'),1,12)LexToken(COMMA,', ',1,22)LexToken(VARIABLE,('VARIABLE', 'Test.Node3'),1,24)LexToken(COMMA,',',1,34)LexToken(VARIABLE,('VARIABLE', 'Test.Node4'),1,35)LexToken(COMMA,', ',1,46)LexToken(VARIABLE,('VARIABLE', 'Test.Node5'),1,48)LexToken(RBRACK,']',1,59)")
        self.assertEqual(self.lex.test('["constant1","constant2", "constant3","constant4" , "constant5" ]'), "LexToken(LBRACK,'[',1,0)LexToken(CONSTANT,('CONSTANT', 'constant1'),1,1)LexToken(COMMA,',',1,12)LexToken(CONSTANT,('CONSTANT', 'constant2'),1,13)LexToken(COMMA,', ',1,24)LexToken(CONSTANT,('CONSTANT', 'constant3'),1,26)LexToken(COMMA,',',1,37)LexToken(CONSTANT,('CONSTANT', 'constant4'),1,38)LexToken(COMMA,', ',1,50)LexToken(CONSTANT,('CONSTANT', 'constant5'),1,52)LexToken(RBRACK,']',1,64)")
        self.assertEqual(self.lex.test('[127.0.0.1 ; 127.0.0.2]'), "LexToken(LBRACK,'[',1,0)LexToken(IPV4,('IPV4', '127.0.0.1'),1,1)LexToken(COMMA,'; ',1,11)LexToken(IPV4,('IPV4', '127.0.0.2'),1,13)LexToken(RBRACK,']',1,22)")
        self.assertEqual(self.lex.test('[::1 ; ::2]'), "LexToken(LBRACK,'[',1,0)LexToken(IPV6,('IPV6', '::1'),1,1)LexToken(COMMA,'; ',1,5)LexToken(IPV6,('IPV6', '::2'),1,7)LexToken(RBRACK,']',1,10)")
        self.assertEqual(self.lex.test('[1;2; 3;4 ; 5 ]'), "LexToken(LBRACK,'[',1,0)LexToken(INTEGER,('INTEGER', 1),1,1)LexToken(COMMA,';',1,2)LexToken(INTEGER,('INTEGER', 2),1,3)LexToken(COMMA,'; ',1,4)LexToken(INTEGER,('INTEGER', 3),1,6)LexToken(COMMA,';',1,7)LexToken(INTEGER,('INTEGER', 4),1,8)LexToken(COMMA,'; ',1,10)LexToken(INTEGER,('INTEGER', 5),1,12)LexToken(RBRACK,']',1,14)")
        self.assertEqual(self.lex.test('[15.5;16.6; 17.7;18.8 ; 19.9 ]'), "LexToken(LBRACK,'[',1,0)LexToken(FLOAT,('FLOAT', 15.5),1,1)LexToken(COMMA,';',1,5)LexToken(FLOAT,('FLOAT', 16.6),1,6)LexToken(COMMA,'; ',1,10)LexToken(FLOAT,('FLOAT', 17.7),1,12)LexToken(COMMA,';',1,16)LexToken(FLOAT,('FLOAT', 18.8),1,17)LexToken(COMMA,'; ',1,22)LexToken(FLOAT,('FLOAT', 19.9),1,24)LexToken(RBRACK,']',1,29)")
        self.assertEqual(self.lex.test('[Test.Node1;Test.Node2; Test.Node3;Test.Node4 ; Test.Node5 ]'), "LexToken(LBRACK,'[',1,0)LexToken(VARIABLE,('VARIABLE', 'Test.Node1'),1,1)LexToken(COMMA,';',1,11)LexToken(VARIABLE,('VARIABLE', 'Test.Node2'),1,12)LexToken(COMMA,'; ',1,22)LexToken(VARIABLE,('VARIABLE', 'Test.Node3'),1,24)LexToken(COMMA,';',1,34)LexToken(VARIABLE,('VARIABLE', 'Test.Node4'),1,35)LexToken(COMMA,'; ',1,46)LexToken(VARIABLE,('VARIABLE', 'Test.Node5'),1,48)LexToken(RBRACK,']',1,59)")
        self.assertEqual(self.lex.test('["constant1";"constant2"; "constant3";"constant4" ; "constant5" ]'), "LexToken(LBRACK,'[',1,0)LexToken(CONSTANT,('CONSTANT', 'constant1'),1,1)LexToken(COMMA,';',1,12)LexToken(CONSTANT,('CONSTANT', 'constant2'),1,13)LexToken(COMMA,'; ',1,24)LexToken(CONSTANT,('CONSTANT', 'constant3'),1,26)LexToken(COMMA,';',1,37)LexToken(CONSTANT,('CONSTANT', 'constant4'),1,38)LexToken(COMMA,'; ',1,50)LexToken(CONSTANT,('CONSTANT', 'constant5'),1,52)LexToken(RBRACK,']',1,64)")
        self.assertEqual(self.lex.test(''), "")

    def test_06_functions(self):
        """
        Check, that all lexical tokens for functions are correctly recognized.
        """
        self.maxDiff = None

        self.assertEqual(self.lex.test('___('), "LexToken(FUNCTION,('FUNCTION', '___'),1,0)")
        self.assertEqual(self.lex.test('_ab('), "LexToken(FUNCTION,('FUNCTION', '_ab'),1,0)")
        self.assertEqual(self.lex.test('_AB('), "LexToken(FUNCTION,('FUNCTION', '_AB'),1,0)")


#-------------------------------------------------------------------------------


if __name__ == '__main__':
    unittest.main()
