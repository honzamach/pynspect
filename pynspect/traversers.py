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
This module contains implementation of object representations of rule tree traversers,
that are supposed to be used to work with rule tree structures.

The base implementation and interface definition is can be found in following class:

* :py:class:`pynspect.traversers.RuleTreeTraverser`

There is also a simple example implementation of rule tree traverser capable of
printing rule tree into a formated string:

* :py:class:`pynspect.traversers.PrintingTreeTraverser`

"""


__author__ = "Jan Mach <jan.mach@cesnet.cz>"
__credits__ = "Pavel Kácha <pavel.kacha@cesnet.cz>, Andrea Kropáčová <andrea.kropacova@cesnet.cz>"


class RuleTreeTraverser():
    """
    Base class and interface definition for all rule tree traversers. This is a
    mandatory interface that is required for an object to be able to traverse
    through given :py:class:`pynspect.rules.Rule` tree.
    """
    def ipv4(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.IPV4Rule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        raise NotImplementedError()

    def ipv6(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.IPV6Rule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        raise NotImplementedError()

    def integer(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.IntegerRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        raise NotImplementedError()

    def float(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.FloatRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        raise NotImplementedError()

    def constant(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.ConstantRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        raise NotImplementedError()

    def variable(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.VariableRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        raise NotImplementedError()

    def list(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.ListRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        raise NotImplementedError()

    def binary_operation_logical(self, rule, left, right, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.LogicalBinOpRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param left: Left operand for operation.
        :param right: right operand for operation.
        :param dict kwargs: Optional callback arguments.
        """
        raise NotImplementedError()

    def binary_operation_comparison(self, rule, left, right, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.ComparisonBinOpRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param left: Left operand for operation.
        :param right: right operand for operation.
        :param dict kwargs: Optional callback arguments.
        """
        raise NotImplementedError()

    def binary_operation_math(self, rule, left, right, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.MathBinOpRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param left: Left operand for operation.
        :param right: right operand for operation.
        :param dict kwargs: Optional callback arguments.
        """
        raise NotImplementedError()

    def unary_operation(self, rule, right, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.UnaryOperationRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param right: right operand for operation.
        :param dict kwargs: Optional callback arguments.
        """
        raise NotImplementedError()


class PrintingTreeTraverser(RuleTreeTraverser):
    """
    Demonstation of simple rule tree traverser - printing traverser.
    """
    def ipv4(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.IPV4Rule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        return "IPV4({})".format(rule.value)

    def ipv6(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.IPV6Rule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        return "IPV6({})".format(rule.value)

    def integer(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.IntegerRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        return "INTEGER({})".format(rule.value)

    def float(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.FloatRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        return "FLOAT({})".format(rule.value)

    def constant(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.ConstantRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        return "CONSTANT({})".format(rule.value)

    def variable(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.VariableRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        return "VARIABLE({})".format(rule.value)

    def list(self, rule, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.ListRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param dict kwargs: Optional callback arguments.
        """
        return "LIST({})".format(', '.join([str(v) for v in rule.value]))

    def binary_operation_logical(self, rule, left, right, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.LogicalBinOpRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param left: Left operand for operation.
        :param right: right operand for operation.
        :param dict kwargs: Optional callback arguments.
        """
        return "LOGBINOP({};{};{})".format(rule.operation, left, right)

    def binary_operation_comparison(self, rule, left, right, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.ComparisonBinOpRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param left: Left operand for operation.
        :param right: right operand for operation.
        :param dict kwargs: Optional callback arguments.
        """
        return "COMPBINOP({};{};{})".format(rule.operation, left, right)

    def binary_operation_math(self, rule, left, right, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.MathBinOpRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param left: Left operand for operation.
        :param right: right operand for operation.
        :param dict kwargs: Optional callback arguments.
        """
        return "MATHBINOP({};{};{})".format(rule.operation, left, right)

    def unary_operation(self, rule, right, **kwargs):
        """
        Callback method for rule tree traversing. Will be called at proper time
        from :py:class:`pynspect.rules.UnaryOperationRule.traverse` method.

        :param pynspect.rules.Rule rule: Reference to rule.
        :param right: right operand for operation.
        :param dict kwargs: Optional callback arguments.
        """
        return "UNOP({};{})".format(rule.operation, right)


#-------------------------------------------------------------------------------


#
# Perform the demonstration.
#
if __name__ == "__main__":

    from pynspect.rules import IntegerRule, VariableRule, LogicalBinOpRule,\
        UnaryOperationRule, ComparisonBinOpRule, MathBinOpRule

    # Create couple of test rules.
    RULE_VAR     = VariableRule("Test")
    RULE_INTEGER = IntegerRule(15)
    RULE_BINOP_L = LogicalBinOpRule('OP_OR', RULE_VAR, RULE_INTEGER)
    RULE_BINOP_C = ComparisonBinOpRule('OP_GT', RULE_VAR, RULE_INTEGER)
    RULE_BINOP_M = MathBinOpRule('OP_PLUS', RULE_VAR, RULE_INTEGER)
    RULE_BINOP   = LogicalBinOpRule('OP_OR', ComparisonBinOpRule('OP_GT', MathBinOpRule('OP_PLUS', VariableRule("Test"), IntegerRule(10)), IntegerRule(20)), ComparisonBinOpRule('OP_LT', VariableRule("Test"), IntegerRule(5)))
    RULE_UNOP    = UnaryOperationRule('OP_NOT', RULE_VAR)

    print("* Traverser usage:")
    RULE_TRAVERSER = PrintingTreeTraverser()
    print("{}".format(RULE_BINOP_L.traverse(RULE_TRAVERSER)))
    print("{}".format(RULE_BINOP_C.traverse(RULE_TRAVERSER)))
    print("{}".format(RULE_BINOP_M.traverse(RULE_TRAVERSER)))
    print("{}".format(RULE_BINOP.traverse(RULE_TRAVERSER)))
    print("{}".format(RULE_UNOP.traverse(RULE_TRAVERSER)))
