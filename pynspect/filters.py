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

There are two main tools in this package:

* :py:class:`DataObjectFilter`

  Tool capable of filtering data structures according to given filtering rules.

* :py:class:`IDEAFilterCompiler`

  Filter compiler, that ensures appropriate data types for correct variable
  comparison evaluation.

.. todo::

    There is quite a lot of code that needs to be written before actual filtering
    can take place. In the future, there should be some kind of object, that will
    be tailored for immediate processing and will take care of initializing
    uderlying parser, compiler and filter. This object will be designed later.

"""


__author__ = "Jan Mach <jan.mach@cesnet.cz>"
__credits__ = "Pavel Kácha <pavel.kacha@cesnet.cz>"


import re
import collections
import datetime
import calendar


import ipranges
from pynspect.rules import IPV4Rule, IPV6Rule, IntegerRule, FloatRule, NumberRule, VariableRule,\
    LogicalBinOpRule, UnaryOperationRule, ComparisonBinOpRule, MathBinOpRule, ListRule,\
    FilteringRuleException
from pynspect.traversers import RuleTreeTraverser
from pynspect.jpath import jpath_values


def py2_timestamp(val):
    """
    Get unix timestamp value out of given datetime object.

    Implemented for Python2 compatibility purposes.
    """
    return calendar.timegm(val.timetuple()) + val.microsecond / 1000000.0

def _to_numeric(val):
    """
    Helper function for conversion of various data types into numeric representation.
    """
    if isinstance(val, (int, float)):
        return val
    if isinstance(val, datetime.datetime):
        try:
            return val.timestamp()
        except:
            # python 2 compatibility
            return py2_timestamp(val)

    return float(val)

class FilteringTreeTraverser(RuleTreeTraverser):
    """
    Base class for all rule tree traversers.
    """

    binops_logical = {
        'OP_OR':    lambda x, y : x or y,
        'OP_XOR':   lambda x, y : (x and not y) or (not x and y),
        'OP_AND':   lambda x, y : x and y,
        'OP_OR_P':  lambda x, y : x or y,
        'OP_XOR_P': lambda x, y : (x and not y) or (not x and y),
        'OP_AND_P': lambda x, y : x and y,
    }
    """
    Definitions of all logical binary operations.
    """

    binops_comparison = {
        'OP_LIKE': lambda x, y : re.search(y, x),
        'OP_IN':   lambda x, y : x in y,
        'OP_IS':   lambda x, y : x == y,
        'OP_EQ':   lambda x, y : x == y,
        'OP_NE':   lambda x, y : x != y,
        'OP_GT':   lambda x, y : x > y,
        'OP_GE':   lambda x, y : x >= y,
        'OP_LT':   lambda x, y : x < y,
        'OP_LE':   lambda x, y : x <= y,
    }
    """
    Definitions of all comparison binary operations.
    """

    binops_math = {
        'OP_PLUS':   lambda x, y : x + y,
        'OP_MINUS':  lambda x, y : x - y,
        'OP_TIMES':  lambda x, y : x * y,
        'OP_DIVIDE': lambda x, y : x / y,
        'OP_MODULO': lambda x, y : x % y,
    }
    """
    Definitions of all mathematical binary operations.
    """

    unops = {
        'OP_NOT':    lambda x : not x,
        'OP_EXISTS': lambda x : x,
    }
    """
    Definitions of all unary operations.
    """

    def evaluate_binop_logical(self, operation, left, right, **kwargs):
        """
        Evaluate given logical binary operation with given operands.
        """
        if not operation in self.binops_logical:
            raise Exception("Invalid logical binary operation '{}'".format(operation))
        result = self.binops_logical[operation](left, right)
        return bool(result)

    def evaluate_binop_comparison(self, operation, left, right, **kwargs):
        """
        Evaluate given comparison binary operation with given operands.
        """
        if not operation in self.binops_comparison:
            raise Exception("Invalid comparison binary operation '{}'".format(operation))
        if left is None or right is None:
            return None
        if not isinstance(left, (list, ListIP)):
            left = [left]
        if not isinstance(right, (list, ListIP)):
            right = [right]
        if not left or not right:
            return None
        if operation in ['OP_IS']:
            res = self.binops_comparison[operation](left, right)
            if res:
                return True
        elif operation in ['OP_IN']:
            for iteml in left:
                res = self.binops_comparison[operation](iteml, right)
                if res:
                    return True
        else:
            for iteml in left:
                if iteml is None:
                    continue
                for itemr in right:
                    if itemr is None:
                        continue
                    res = self.binops_comparison[operation](iteml, itemr)
                    if res:
                        return True
        return False

    def _calculate_vector(self, operation, left, right):
        """
        Calculate vector result from two list operands with given mathematical operation.
        """
        result = []
        if len(right) == 1:
            right = _to_numeric(right[0])
            for iteml in left:
                iteml = _to_numeric(iteml)
                result.append(self.binops_math[operation](iteml, right))
        elif len(left) == 1:
            left = _to_numeric(left[0])
            for itemr in right:
                itemr = _to_numeric(itemr)
                result.append(self.binops_math[operation](left, itemr))
        elif len(left) == len(right):
            for iteml, itemr in zip(left, right):
                iteml = _to_numeric(iteml)
                itemr = _to_numeric(itemr)
                result.append(self.binops_math[operation](iteml, itemr))
        else:
            raise FilteringRuleException("Uneven length of math operation '{}' operands".format(operation))
        return result

    def evaluate_binop_math(self, operation, left, right, **kwargs):
        """
        Evaluate given mathematical binary operation with given operands.
        """
        if not operation in self.binops_math:
            raise Exception("Invalid math binary operation '{}'".format(operation))
        if left is None or right is None:
            return None
        if not isinstance(left, (list, ListIP)):
            left = [left]
        if not isinstance(right, (list, ListIP)):
            right = [right]
        if not left or not right:
            return None
        try:
            vect = self._calculate_vector(operation, left, right)
            if len(vect) > 1:
                return vect
            return vect[0]
        except:
            return None

    def evaluate_unop(self, operation, right, **kwargs):
        """
        Evaluate given unary operation with given operand.
        """
        if not operation in self.unops:
            raise Exception("Invalid unary operation '{}'".format(operation))
        if right is None:
            return None
        return self.unops[operation](right)

    #def evaluate(self, operation, *args):
    #    """
    #    Master method for evaluating any operation (both unary and binary).
    #    """
    #    if operation in self.binops_comparison:
    #        return self.evaluate_binop_comparison(operation, *args)
    #    if operation in self.binops_logical:
    #        return self.evaluate_binop_logical(operation, *args)
    #    if operation in self.binops_math:
    #        return self.evaluate_binop_math(operation, *args)
    #    if operation in self.unops:
    #        return self.evaluate_unop(operation, *args)
    #    raise Exception("Invalid operation '{}'".format(operation))

class DataObjectFilter(FilteringTreeTraverser):
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

        :param Rule rule: filtering rule to be checked
        :param any data: data structure to check against rule, ussually dict
        :return: True or False or expression result
        :rtype: bool or any
        """
        return rule.traverse(self, obj = data)

    #---------------------------------------------------------------------------

    def ipv4(self, rule, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return rule.value
    def ipv6(self, rule, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return rule.value
    def integer(self, rule, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return rule.value
    def constant(self, rule, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return rule.value
    def variable(self, rule, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return jpath_values(kwargs['obj'], rule.value)
    def list(self, rule, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return rule.values()
    def binary_operation_logical(self, rule, left, right, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return self.evaluate_binop_logical(rule.operation, left, right, **kwargs)
    def binary_operation_comparison(self, rule, left, right, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return self.evaluate_binop_comparison(rule.operation, left, right, **kwargs)
    def binary_operation_math(self, rule, left, right, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return self.evaluate_binop_math(rule.operation, left, right, **kwargs)
    def unary_operation(self, rule, right, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return self.evaluate_unop(rule.operation, right, **kwargs)


def compile_ip_v4(rule):
    """
    Compiler helper method: attempt to compile constant into object representing
    IPv4 address to enable relations and thus simple comparisons using Python
    operators.
    """
    if isinstance(rule.value, ipranges.Range):
        return rule
    return IPV4Rule(ipranges.from_str_v4(rule.value))

def compile_ip_v6(rule):
    """
    Compiler helper method: attempt to compile constant into object representing
    IPv6 address to enable relations and thus simple comparisons using Python
    operators.
    """
    if isinstance(rule.value, ipranges.Range):
        print("IPv6 {} already compiled".format(rule.value))
        return rule
    print("Compiling IPv6 {} to Range object".format(rule.value))
    return IPV6Rule(ipranges.from_str_v6(rule.value))

CVRE = re.compile(r'\[\d+\]')
def clean_variable(var):
    """
    Remove any array indices from variable name to enable indexing into :py:data:`COMPILATIONS_IDEA_OBJECT`
    callback dictionary.

    This dictionary contains postprocessing callback appropriate for opposing
    operand of comparison operation for variable on given JPath.
    """
    return CVRE.sub('', var)


class ListIP(collections.MutableSequence):
    """

    """
    def __init__(self, iterable = None):
        self.data = list()
        if iterable:
            self.extend(iterable)

    def __getitem__(self, val): return self.data[val]

    def __delitem__(self, val): del self.data[val]

    def __len__(self): return len(self.data)

    def __setitem__(self, idx, val):
        self.data[idx] = val

    def insert(self, idx, val):
        self.data.insert(idx, val)

    # Following definitions are not strictly necessary as MutableSequence
    # already defines them, however we can override them by calling to
    # possibly more optimized underlying implementations.

    def __contains__(self, val):
        for value in self.data:
            if val in value:
                return True
        return False

    def index(self, val):
        return self.data.index(val)

    def count(self, val):
        return self.data.count(val)

    def __iter__(self): return iter(self.data)

    def reverse(self): return self.data.reverse()

    def __reversed__(self): return reversed(self.data)

    def pop(self, index=-1): return self.data.pop(index)

    def __str__(self): return "%s(%s)" % (type(self).__name__, str(self.data))

    def __repr__(self): return "%s(%s)" % (type(self).__name__, repr(self.data))


class IPListRule(ListRule):
    def __init__(self, rules):
        """
        Initialize the constant with given value.
        """
        self.value = rules

    def values(self):
        return ListIP([i.value for i in self.value])

    def __repr__(self):
        return "IPLIST({})".format(', '.join([repr(v) for v in self.value]))


COMPILATIONS_IDEA_OBJECT = {
    'Source.IP4': {'comp_i': compile_ip_v4, 'comp_l': IPListRule },
    'Target.IP4': {'comp_i': compile_ip_v4, 'comp_l': IPListRule },
    'Source.IP6': {'comp_i': compile_ip_v6, 'comp_l': IPListRule },
    'Target.IP6': {'comp_i': compile_ip_v6, 'comp_l': IPListRule },
}


class IDEAFilterCompiler(FilteringTreeTraverser):
    """
    Rule tree traverser implementing IDEA filter compilation algorithm.

    Following example demonstrates DataObjectFilter usage in conjuction with
    PynspectFilterParser::

    >>> msg_idea = lite.Idea(test_msg)
    >>> flt = DataObjectFilter()
    >>> cpl = IDEAFilterCompiler()
    >>> psr = PynspectFilterParser()
    >>> psr.build()
    >>> rule = psr.parse('ID like "e214d2d9"')
    >>> rule = cpl.compile(rule)
    >>> result = flt.filter(rule, test_msg)
    """
    def compile(self, rule):
        """
        Compile given filtering rule into format appropriate for processing IDEA
        messages.

        :param Rule rule: filtering rule to be compiled
        :return: compiled filtering rule
        :rtype: Rule
        """
        return rule.traverse(self)


    #---------------------------------------------------------------------------


    def ipv4(self, rule, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        rule = compile_ip_v4(rule)
        return rule

    def ipv6(self, rule, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        rule = compile_ip_v4(rule)
        return rule

    def integer(self, rule, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        rule.value = int(rule.value)
        return rule

    def constant(self, rule, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return rule

    def variable(self, rule, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return rule

    def list(self, rule, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return rule

    def binary_operation_logical(self, rule, left, right, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return LogicalBinOpRule(rule.operation, left, right)

    def binary_operation_comparison(self, rule, left, right, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        var = val = None
        if isinstance(left, VariableRule) and not isinstance(right, VariableRule):
            var = left
            val = right
        elif isinstance(right, VariableRule) and not isinstance(left, VariableRule):
            var = right
            val = left
        if var and val:
            path = clean_variable(var.value)
            if path in COMPILATIONS_IDEA_OBJECT.keys():
                compilation = COMPILATIONS_IDEA_OBJECT[path]
                if isinstance(val, ListRule):
                    result = []
                    for itemv in val.value:
                        result.append(compilation['comp_i'](itemv))

                    right = compilation['comp_l'](result)
                else:
                    right = compilation['comp_i'](val)
        return ComparisonBinOpRule(rule.operation, left, right)

    def binary_operation_math(self, rule, left, right, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        if isinstance(left, IntegerRule) and isinstance(right, IntegerRule):
            result = self.evaluate_binop_math(rule.operation, left.value, right.value)
            if isinstance(result, list):
                return ListRule([IntegerRule(r) for r in result])
            return IntegerRule(result)
        elif isinstance(left, NumberRule) and isinstance(right, NumberRule):
            result = self.evaluate_binop_math(rule.operation, left.value, right.value)
            if isinstance(result, list):
                return ListRule([FloatRule(r) for r in result])
            return FloatRule(result)
        return MathBinOpRule(rule.operation, left, right)

    def unary_operation(self, rule, right, **kwargs):
        """Implementation of :py:class:`pynspect.rules.RuleTreeTraverser` interface"""
        return UnaryOperationRule(rule.operation, right)


#
# Perform the demonstration.
#
if __name__ == "__main__":

    import pprint

    DEMO_DATA   = {"Test": 15, "Attr": "ABC"}
    DEMO_RULE   = ComparisonBinOpRule('OP_GT', VariableRule("Test"), IntegerRule(10))
    DEMO_FILTER = DataObjectFilter()
    pprint.pprint(DEMO_FILTER.filter(DEMO_RULE, DEMO_DATA))
