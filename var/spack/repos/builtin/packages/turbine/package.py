# Copyright 2013-2020 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)


import os

from spack.std import *


class Turbine(AutotoolsPackage):
    """Turbine: The Swift/T runtime"""

    homepage = 'http://swift-lang.org/Swift-T'
    url      = 'http://swift-lang.github.io/swift-t-downloads/spack/turbine-1.2.3.tar.gz'
    git      = "https://github.com/swift-lang/swift-t.git"
    configure_directory = 'turbine/code'

    version('master', branch='master')
    version('1.2.3', sha256='a3156c7e0b39e166da3de8892f55fa5d535b0c99c87a9add067c801098fe51ba')
    version('1.1.0', sha256='98fad47597935a04d15072e42bf85411d55ef00cb6f953e9f14d6de902e33209')

    variant('python', default=False,
            description='Enable calling python')
    variant('r', default=False,
            description='Enable calling R')
    variant('hdf5', default=False,
            description='Enable HDF5 support')
    depends_on('adlbx@master', when='@master')
    depends_on('adlbx@:0.8.0', when='@:1.1.0')
    depends_on('adlbx', when='@1.2.1:')
    depends_on('adlbx')
    depends_on('tcl', type=('build', 'run'))
    depends_on('zsh', type=('build', 'run'))
    depends_on('swig', type='build')
    depends_on('python', when='+python')
    depends_on('r', when='+r')
    depends_on('r-rinside', when='+r')
    depends_on('hdf5', when='+hdf5')
    depends_on('mpi')
    depends_on('autoconf', type='build', when='@master')
    depends_on('automake', type='build', when='@master')
    depends_on('libtool', type='build', when='@master')
    depends_on('m4', type=('build', 'run'))

    def setup_build_environment(self, env):
        spec = self.spec

        env.set('CC', spec['mpi'].mpicc)
        env.set('CXX', spec['mpi'].mpicxx)
        env.set('CXXLD', spec['mpi'].mpicxx)

    @property
    def configure_directory(self):
        if self.version == Version('master'):
            return 'turbine/code'
        else:
            return '.'

    def configure_args(self):
        args = ['--with-c-utils=' + self.spec['exmcutils'].prefix,
                '--with-adlb='    + self.spec['adlbx'].prefix,
                '--with-tcl='     + self.spec['tcl'].prefix,
                '--with-mpi='     + self.spec['mpi'].prefix,
                '--disable-static-pkg']
        if '+hdf5' in self.spec:
            args.append('--with-hdf5=ON')
        else:
            args.append('--with-hdf5=OFF')
        if '+python' in self.spec:
            args.append('--with-python-exe={0}'.format(
                        self.spec['python'].command.path))
        if '+r' in self.spec:
            r_location = '{0}/rlib/R'.format(self.spec['r'].prefix)
            if not os.path.exists(r_location):
                rscript = which('Rscript')
                if rscript is not None:
                    r_location = rscript('-e', 'cat(R.home())', output=str)
                else:
                    msg = 'Could not locate Rscript on your PATH!'
                    raise RuntimeError(msg)
            args.append('--with-r={0}'.format(r_location))
        return args
