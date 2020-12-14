# Copyright 2013-2020 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

"""This module contains additional behavior that can be attached to any given
package.
"""
import collections
import os

try:
    from typing import Callable, DefaultDict, Dict, List  # novm
    CallbackDict = DefaultDict[str, List[Callable]]  # novm
except ImportError:
    pass

import llnl.util.filesystem

__all__ = [
    'filter_compiler_wrappers'
]


class PackageMixinsMeta(type):
    """This metaclass serves the purpose of implementing a declarative syntax
    for package mixins.

    Mixins are implemented below in the form of a function. Each one of them
    needs to register a callable that takes a single argument to be run
    before or after a certain phase. This callable is basically a method that
    gets implicitly attached to the package class by calling the mixin.
    """

    _methods_to_be_added = {}  # type: Dict[str, Callable]
    _add_method_before = collections.defaultdict(list)  # type: CallbackDict
    _add_method_after = collections.defaultdict(list)  # type: CallbackDict

    @staticmethod
    def register_method_before(fn, phase):  # type: (Callable, str) -> None
        """Registers a method to be run before a certain phase.

        Args:
            fn: function taking a single argument (self)
            phase (str): phase before which fn must run
        """
        PackageMixinsMeta._methods_to_be_added[fn.__name__] = fn
        PackageMixinsMeta._add_method_before[phase].append(fn)

    @staticmethod
    def register_method_after(fn, phase):  # type: (Callable, str) -> None
        """Registers a method to be run after a certain phase.

        Args:
            fn: function taking a single argument (self)
            phase (str): phase after which fn must run
        """
        PackageMixinsMeta._methods_to_be_added[fn.__name__] = fn
        PackageMixinsMeta._add_method_after[phase].append(fn)

    def __init__(cls, name, bases, attr_dict):

        # Add the methods to the class being created
        if PackageMixinsMeta._methods_to_be_added:
            attr_dict.update(PackageMixinsMeta._methods_to_be_added)
            PackageMixinsMeta._methods_to_be_added.clear()

        attr_fmt = '_InstallPhase_{0}'

        # Copy the phases that needs it to the most derived classes
        # in order not to interfere with other packages in the hierarchy
        phases_to_be_copied = list(
            PackageMixinsMeta._add_method_before.keys()
        )
        phases_to_be_copied += list(
            PackageMixinsMeta._add_method_after.keys()
        )

        for phase in phases_to_be_copied:

            attr_name = attr_fmt.format(phase)

            # Here we want to get the attribute directly from the class (not
            # from the instance), so that we can modify it and add the mixin
            # method to the pipeline.
            phase = getattr(cls, attr_name)

            # Due to MRO, we may have taken a method from a parent class
            # and modifying it may influence other packages in unwanted
            # manners. Solve the problem by copying the phase into the most
            # derived class.
            setattr(cls, attr_name, phase.copy())

        # Insert the methods in the appropriate position
        # in the installation pipeline.

        for phase in PackageMixinsMeta._add_method_before:

            attr_name = attr_fmt.format(phase)
            phase_obj = getattr(cls, attr_name)
            fn_list = PackageMixinsMeta._add_method_after[phase]

            for f in fn_list:
                phase_obj.run_before.append(f)

        # Flush the dictionary for the next class
        PackageMixinsMeta._add_method_before.clear()

        for phase in PackageMixinsMeta._add_method_after:

            attr_name = attr_fmt.format(phase)
            phase_obj = getattr(cls, attr_name)
            fn_list = PackageMixinsMeta._add_method_after[phase]

            for f in fn_list:
                phase_obj.run_after.append(f)

        # Flush the dictionary for the next class
        PackageMixinsMeta._add_method_after.clear()

        super(PackageMixinsMeta, cls).__init__(name, bases, attr_dict)


def filter_compiler_wrappers(*files, **kwargs):
    """Substitutes any path referring to a Spack compiler wrapper with the
    path of the underlying compiler that has been used.

    If this isn't done, the files will have CC, CXX, F77, and FC set to
    Spack's generic cc, c++, f77, and f90. We want them to be bound to
    whatever compiler they were built with.

    Args:
        *files: files to be filtered relative to the search root (which is,
            by default, the installation prefix)

        **kwargs: allowed keyword arguments

            after
                specifies after which phase the files should be
                filtered (defaults to 'install')

            relative_root
                path relative to prefix where to start searching for
                the files to be filtered. If not set the install prefix
                wil be used as the search root. **It is highly recommended
                to set this, as searching from the installation prefix may
                affect performance severely in some cases**.

            ignore_absent, backup
                these two keyword arguments, if present, will be forwarded
                to ``filter_file`` (see its documentation for more information
                on their behavior)

            recursive
                this keyword argument, if present, will be forwarded to
                ``find`` (see its documentation for more information on the
                behavior)
    """
    after = kwargs.get('after', 'install')
    relative_root = kwargs.get('relative_root', None)

    filter_kwargs = {
        'ignore_absent': kwargs.get('ignore_absent', True),
        'backup': kwargs.get('backup', False),
        'string': True
    }

    find_kwargs = {
        'recursive': kwargs.get('recursive', False)
    }

    def _filter_compiler_wrappers_impl(self):
        # Compute the absolute path of the search root
        root = os.path.join(
            self.prefix, relative_root
        ) if relative_root else self.prefix

        # Compute the absolute path of the files to be filtered and
        # remove links from the list.
        abs_files = llnl.util.filesystem.find(root, files, **find_kwargs)
        abs_files = [x for x in abs_files if not os.path.islink(x)]

        x = llnl.util.filesystem.FileFilter(*abs_files)

        replacements = [
            ('CC', self.compiler.cc),
            ('CXX', self.compiler.cxx),
            ('F77', self.compiler.f77),
            ('FC', self.compiler.fc)
        ]
        for env_var, compiler_path in replacements:
            if env_var in os.environ:
                x.filter(os.environ[env_var], compiler_path, **filter_kwargs)

        # Remove this linking flag if present (it turns RPATH into RUNPATH)
        x.filter('{0}--enable-new-dtags'.format(self.compiler.linker_arg), '',
                 **filter_kwargs)

        # NAG compiler is usually mixed with GCC, which has a different
        # prefix for linker arguments.
        if self.compiler.name == 'nag':
            x.filter('-Wl,--enable-new-dtags', '', **filter_kwargs)

    PackageMixinsMeta.register_method_after(
        _filter_compiler_wrappers_impl, after
    )
