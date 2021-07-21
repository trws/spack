# Copyright 2013-2021 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
import llnl.util.tty.color as cl

import spack.audit
import spack.repo

description = "audit configuration files, packages, etc."
section = "system"
level = "short"


def setup_parser(subparser):
    # Top level flags, valid for every audit class
    sp = subparser.add_subparsers(metavar='SUBCOMMAND', dest='subcommand')

    # Audit configuration files
    sp.add_parser('configs', help='audit configuration files')

    # Audit package recipes
    pkg_parser = sp.add_parser('packages', help='audit package recipes')
    pkg_parser.add_argument(
        'name', metavar='PKG', nargs='*',
        help='package to be analyzed (if none all packages will be processed)',
    )

    # List all checks
    sp.add_parser('list', help='list available checks and exits')


def configs(parser, args):
    reports = spack.audit.run_group(args.subcommand)
    _process_reports(reports)


def packages(parser, args):
    pkgs = args.name or spack.repo.path.all_package_names()
    reports = spack.audit.run_group(args.subcommand, pkgs=pkgs)
    _process_reports(reports)


def list(parser, args):
    for subcommand, check_tags in spack.audit.GROUPS.items():
        print(cl.colorize('@*b{' + subcommand + '}:'))
        for tag in check_tags:
            audit_obj = spack.audit.CALLBACKS[tag]
            print('  ' + audit_obj.description)
            if args.verbose:
                for idx, fn in enumerate(audit_obj.callbacks):
                    print('    {0}. '.format(idx + 1) + fn.__doc__)
                print()
        print()


def audit(parser, args):
    subcommands = {
        'configs': configs,
        'packages': packages,
        'list': list
    }
    subcommands[args.subcommand](parser, args)


def _process_reports(reports):
    for check, errors in reports:
        if errors:
            msg = '{0}: {1} issue{2} found'.format(
                check, len(errors), '' if len(errors) == 1 else 's'
            )
            header = '@*b{' + msg + '}'
            print(cl.colorize(header))
            for idx, error in enumerate(errors):
                print(str(idx + 1) + '. ' + str(error))
            raise SystemExit(1)
        else:
            msg = '{0}: 0 issues found.'.format(check)
            header = '@*b{' + msg + '}'
            print(cl.colorize(header))
