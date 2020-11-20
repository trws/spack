# Copyright 2013-2021 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

from spack import *


class Kripke(CMakePackage,CudaPackage):
    """Kripke is a simple, scalable, 3D Sn deterministic particle
       transport proxy/mini app.
    """
    homepage = "https://computing.llnl.gov/projects/co-design/kripke"
    git      = "https://github.com/LLNL/Kripke.git"

    tags = ['proxy-app']
    version('1.2.4', submodules=True, tag='v1.2.4')
    version('1.2.3', submodules=True, tag='v1.2.3')
    version('1.2.2', submodules=True, tag='v1.2.2-CORAL2')
    version('1.2.1', submodules=True, tag='v1.2.1-CORAL2')
    version('1.2.0', submodules=True, tag='v1.2.0-CORAL2')

    variant('mpi',    default=True, description='Build with MPI.')
    variant('openmp', default=True, description='Build with OpenMP enabled.')
    variant('caliper', default=False, description='Build with Caliper support enabled.')
    variant('chai', default=False, description='Build with CHAI/umpire memory management.')

    depends_on('mpi', when='+mpi')
    depends_on('cmake@3.0:', type='build')
    depends_on('caliper', when='+caliper')

    depends_on('raja')
    depends_on('raja+cuda', when='+cuda')
    depends_on('chai', when='+chai')
    depends_on('chai+cuda', when='+chai+cuda')

    def dfve(self, name, prefix='ENABLE_'):
        return self.define_from_variant(prefix + name.upper(), name)
    def cmake_args(self):
        return [
            self.dfve('openmp'),
            self.dfve('mpi'),
            self.dfve('caliper'),
            self.dfve('cuda'),
            self.dfve('chai'),
        ]

    def install(self, spec, prefix):
        # Kripke does not provide install target, so we have to copy
        # things into place.
        mkdirp(prefix.bin)
        install(join_path(self.build_directory, 'bin/kripke.exe'), prefix.bin)

    def test(self):
        self.run_test('kripke.exe', options=['--groups', '64', '--gset', '1', '--quad', '128', '--dset', '128', '--legendre', '4', '--zones', '64,32,32', '--procs', '1,1,1'])
