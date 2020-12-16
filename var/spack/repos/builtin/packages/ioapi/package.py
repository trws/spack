# Copyright 2013-2020 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

import os

from spack.std import *


class Ioapi(MakefilePackage):
    """Models-3/EDSS Input/Output Applications Programming Interface."""

    homepage = "https://www.cmascenter.org/ioapi/"
    url      = "https://www.cmascenter.org/ioapi/download/ioapi-3.2.tar.gz"
    version('3.2', sha256='56771ff0053d47f2445e00ff369bca7bfc484325a2816b2c648744e523134fe9')
    depends_on('netcdf-c@4:')
    depends_on('netcdf-fortran@4:')
    depends_on('sed', type='build')

    def edit(self, spec, prefix):
        # No default Makefile bundled; edit the template.
        os.symlink('Makefile.template', 'Makefile')
        # The makefile uses stubborn assignments of = instead of ?= so
        # edit the makefile instead of using environmental variables.
        makefile = FileFilter('Makefile')
        makefile.filter('^BASEDIR.*', 'BASEDIR = ' + self.build_directory)
        makefile.filter('^INSTALL.*', 'INSTALL = ' + prefix)
        makefile.filter('^BININST.*', 'BININST = ' + prefix.bin)
        makefile.filter('^LIBINST.*', 'LIBINST = ' + prefix.lib)

    def install(self, spec, prefix):
        make('install')
        # Install the header files.
        mkdirp(prefix.include.fixed132)
        install('ioapi/*.EXT', prefix.include)
        # Install the header files for CMAQ and SMOKE in the
        # non-standard -ffixed-line-length-132 format.
        install('ioapi/fixed_src/*.EXT', prefix.include.fixed132)
