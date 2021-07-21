# Copyright 2013-2021 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

import sys

from spack import *
from spack.pkg.builtin.boost import Boost


class Apex(CMakePackage):
    """Autonomic Performance Environment for eXascale (APEX)."""

    maintainers = ['khuck']
    homepage = "https://github.com/khuck/xpress-apex"
    url      = "https://github.com/khuck/xpress-apex/archive/v2.3.1.tar.gz"
    git      = "https://github.com/khuck/xpress-apex"

    version('develop', branch='develop')
    version('master', branch='master')
    version('2.4.0', sha256='15d8957da7b37d2c684a6f0f32aef65b0b26be6558da17963cf71f3fd3cfdf2f')
    version('2.3.2', sha256='acf37c024a2283cafbf206f508929208b62c8f800af22ad7c74c570863a31bb4')
    version('2.3.1', sha256='86bf6933f2c53531fcb24cda9fc7dc9919909bed54740d1e0bc3e7ce6ed78091')
    version('2.3.0', sha256='7e1d16c9651b913c5e28abdbad75f25c55ba25e9fa35f5d979c1d3f9b9852c58')
    version('2.2.0', sha256='cd5eddb1f6d26b7dbb4a8afeca2aa28036c7d0987e0af0400f4f96733889c75c')

    # Disable some default dependencies on Darwin/OSX
    darwin_default = False
    if sys.platform != 'darwin':
        darwin_default = True

    # Enable by default
    variant('activeharmony', default=True, description='Enables Active Harmony support')
    variant('plugins', default=True, description='Enables Policy Plugin support')
    variant('binutils', default=True, description='Enables Binutils support')
    variant('otf2', default=True, description='Enables OTF2 support')
    variant('gperftools', default=True, description='Enables Google PerfTools TCMalloc support')
    variant('openmp', default=darwin_default, description='Enables OpenMP support')
    variant('papi', default=darwin_default, description='Enables PAPI support')

    # Disable by default
    variant('cuda', default=False, description='Enables CUDA support')
    variant('boost', default=False, description='Enables Boost support')
    variant('jemalloc', default=False, description='Enables JEMalloc support')
    variant('lmsensors', default=False, description='Enables LM-Sensors support')
    variant('mpi', default=False, description='Enables MPI support')
    variant('tests', default=False, description='Build Unit Tests')
    variant('examples', default=False, description='Build Examples')

    # Dependencies
    depends_on('cmake@3.10.0:', type='build')
    depends_on('binutils@2.33:+libiberty+headers', when='+binutils')
    depends_on('activeharmony@4.6:', when='+activeharmony')
    depends_on('activeharmony@4.6:', when='+plugins')
    depends_on('otf2@2.1:', when='+otf2')
    depends_on('mpi', when='+mpi')
    depends_on('gperftools', when='+gperftools')
    depends_on('jemalloc', when='+jemalloc')
    depends_on('papi@5.7.0:', when='+papi')
    depends_on('cuda', when='+cuda')
    # TODO: replace this with an explicit list of components of Boost,
    # for instance depends_on('boost +filesystem')
    # See https://github.com/spack/spack/pull/22303 for reference
    depends_on(Boost.with_default_variants)

    # Conflicts
    conflicts('+jemalloc', when='+gperftools')
    conflicts('+plugins', when='~activeharmony')

    def cmake_args(self):
        args = []
        spec = self.spec
        # CMake variables were updated in version 2.3.0, to make
        prefix = 'APEX_WITH'
        test_prefix = 'APEX_'
        if '@2.2.0' in spec:
            prefix = 'USE'
            test_prefix = ''

        args.append(self.define_from_variant(prefix + '_ACTIVEHARMONY',
                                             'activeharmony'))
        args.append(self.define_from_variant(prefix + '_BFD', 'binutils'))
        args.append(self.define_from_variant('APEX_WITH_CUDA', 'cuda'))
        args.append(self.define_from_variant(prefix + '_MPI', 'mpi'))
        args.append(self.define_from_variant(prefix + '_OMPT', 'openmp'))
        args.append(self.define_from_variant(prefix + '_OTF2', 'otf2'))
        args.append(self.define_from_variant(prefix + '_PAPI', 'papi'))
        args.append(self.define_from_variant(prefix + '_PLUGINS', 'plugins'))
        args.append(self.define_from_variant(prefix + '_LM_SENSORS', 'lmsensors'))
        args.append(self.define_from_variant(prefix + '_TCMALLOC', 'gperftools'))
        args.append(self.define_from_variant(prefix + '_JEMALLOC', 'jemalloc'))
        args.append(self.define_from_variant(test_prefix + 'BUILD_TESTS', 'tests'))
        args.append(self.define_from_variant(test_prefix + 'BUILD_EXAMPLES',
                                             'examples'))

        if '+activeharmony' in spec:
            args.append('-DACTIVEHARMONY_ROOT={0}'.format(
                spec['activeharmony'].prefix))

        if '+binutils' in spec:
            args.append('-DBFD_ROOT={0}'.format(spec['binutils'].prefix))

        if '+otf2' in spec:
            args.append('-DOTF2_ROOT={0}'.format(spec['otf2'].prefix))

        if '+papi' in spec:
            args.append('-DPAPI_ROOT={0}'.format(spec['papi'].prefix))

        if '+gperftools' in spec:
            args.append('-DGPERFTOOLS_ROOT={0}'.format(
                spec['gperftools'].prefix))

        if '+jemalloc' in spec:
            args.append('-DJEMALLOC_ROOT={0}'.format(spec['jemalloc'].prefix))

        if '+boost' in spec:
            args.append('-DBOOST_ROOT={0}'.format(spec['boost'].prefix))

        return args
