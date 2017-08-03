Pynspect - Python data inspection library documentation!
================================================================================

.. warning::

    Although production code is based on this library, it should still be considered
    as work in progress.


Introduction
--------------------------------------------------------------------------------

Python library for filtering, querying or inspecting almost arbitrary data
structures.

This README file is work in progress, for more information please consult source
code and unit tests.


Features
--------------------------------------------------------------------------------

Currently the package contains following features:

:py:mod:`pyzenkit.jsonconf`
    Module for handling JSON based configuration files and directories.

:py:mod:`pyzenkit.daemonizer`
    Module for taking care of all process daemonization tasks.

:py:mod:`pyzenkit.baseapp`
    Module for writing generic console applications.

:py:mod:`pyzenkit.zenscript`
    Module for writing generic console scripts with built-in support for repeated
    executions (for example by cron-like service).

:py:mod:`pyzenkit.zendaemon`
    Module for writing generic system services (daemons).


Copyright
--------------------------------------------------------------------------------

Copyright (C) since 2016 CESNET, z.s.p.o (http://www.ces.net/)
Copyright (C) since 2016 Jan Mach <honza.mach.ml@gmail.com>
Use of this package is governed by the MIT license, see LICENSE file.
