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
This module provides tools for data filtering based on filtering and query
grammar.

The filtering grammar is thoroughly described in following module:

* :py:mod:`pynspect.lexer`

  Lexical analyzer, descriptions of valid grammar tokens.

* :py:mod:`pynspect.gparser`

  Grammar parser, language grammar description

* :py:mod:`pynspect.rules`

  Object representation of grammar rules, interface definition

* :py:mod:`pynspect.jpath`

  The addressing language JPath.

Please refer to appropriate module for more in-depth information.

There are following main tools in this package:

* :py:class:`DataObjectFilter`

  Tool capable of filtering data structures according to given filtering rules.

.. todo::

    There is quite a lot of code that needs to be written before actual filtering
    can take place. In the future, there should be some kind of object, that will
    be tailored for immediate processing and will take care of initializing
    uderlying parser, compiler and filter. This object will be designed later.

"""


__author__ = "Jan Mach <jan.mach@cesnet.cz>"
__credits__ = "Pavel Kácha <pavel.kacha@cesnet.cz>"


from pynspect.traversers import BaseFilteringTreeTraverser
from pynspect.jpath import jpath_values


class DataObjectFilter(BaseFilteringTreeTraverser):
    """
    Rule tree traverser implementing  default object filtering logic.

    Following example demonstrates DataObjectFilter usage in conjuction with
    PynspectFilterParser::

    >>> flt = DataObjectFilter()
    >>> psr = PynspectFilterParser()
    >>> psr.build()
    >>> rule = psr.parse('ID like "e214d2d9"')
    >>> result = flt.filter(rule, test_msg)

    Alternativelly rule tree can be created by hand/programatically:

    >>> rule = ComparisonBinOpRule('OP_GT', VariableRule("ConnCount"), IntegerRule(1))
    >>> result = flt.filter(rule, test_msg1)
    """
    def filter(self, rule, data):
        """
        Apply given filtering rule to given data structure.

        :param pynspect.rules.Rule rule: filtering rule to be checked
        :param any data: data structure to check against rule, ussually dict
        :return: True or False or expression result
        :rtype: bool or any
        """
        return rule.traverse(self, obj = data)

    #---------------------------------------------------------------------------

    def ipv4(self, rule, **kwargs):
        """
        Implementation of :py:func:`pynspect.traversers.RuleTreeTraverser.ipv4` interface.
        """
        return rule.value

    def ipv6(self, rule, **kwargs):
        """
        Implementation of :py:func:`pynspect.traversers.RuleTreeTraverser.ipv6` interface.
        """
        return rule.value

    def datetime(self, rule, **kwargs):
        """
        Implementation of :py:func:`pynspect.traversers.RuleTreeTraverser.datetime` interface.
        """
        return rule.value

    def integer(self, rule, **kwargs):
        """
        Implementation of :py:func:`pynspect.traversers.RuleTreeTraverser.integer` interface.
        """
        return rule.value

    def constant(self, rule, **kwargs):
        """
        Implementation of :py:func:`pynspect.traversers.RuleTreeTraverser.constant` interface.
        """
        return rule.value

    def variable(self, rule, **kwargs):
        """
        Implementation of :py:func:`pynspect.traversers.RuleTreeTraverser.variable` interface.
        """
        return jpath_values(kwargs['obj'], rule.value)

    def list(self, rule, **kwargs):
        """
        Implementation of :py:func:`pynspect.traversers.RuleTreeTraverser.list` interface.
        """
        return rule.values()

    def binary_operation_logical(self, rule, left, right, **kwargs):
        """
        Implementation of :py:func:`pynspect.traversers.RuleTreeTraverser.binary_operation_logical` interface.
        """
        return self.evaluate_binop_logical(rule.operation, left, right, **kwargs)

    def binary_operation_comparison(self, rule, left, right, **kwargs):
        """
        Implementation of :py:func:`pynspect.traversers.RuleTreeTraverser.binary_operation_comparison` interface.
        """
        return self.evaluate_binop_comparison(rule.operation, left, right, **kwargs)

    def binary_operation_math(self, rule, left, right, **kwargs):
        """
        Implementation of :py:func:`pynspect.traversers.RuleTreeTraverser.binary_operation_math` interface.
        """
        return self.evaluate_binop_math(rule.operation, left, right, **kwargs)

    def unary_operation(self, rule, right, **kwargs):
        """
        Implementation of :py:func:`pynspect.traversers.RuleTreeTraverser.unary_operation` interface.
        """
        return self.evaluate_unop(rule.operation, right, **kwargs)


#-------------------------------------------------------------------------------


#
# Perform the demonstration.
#
if __name__ == "__main__":

    import pprint

    from pynspect.rules import IntegerRule, VariableRule, ComparisonBinOpRule

    DEMO_DATA   = {"Test": 15, "Attr": "ABC"}
    DEMO_RULE   = ComparisonBinOpRule('OP_GT', VariableRule("Test"), IntegerRule(10))
    DEMO_FILTER = DataObjectFilter()
    pprint.pprint(DEMO_FILTER.filter(DEMO_RULE, DEMO_DATA))
