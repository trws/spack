# Copyright 2013-2020 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

from spack.package import *


class PyAdios(PythonPackage):
    """NumPy bindings of ADIOS1"""

    homepage = "https://www.olcf.ornl.gov/center-projects/adios/"
    url      = "https://github.com/ornladios/ADIOS/archive/v1.12.0.tar.gz"
    git      = "https://github.com/ornladios/ADIOS.git"

    maintainers = ['ax3l']

    version('develop', branch='master')
    version('1.13.0', sha256='7b5ee8ff7a5f7215f157c484b20adb277ec0250f87510513edcc25d2c4739f50')
    version('1.12.0', sha256='22bc22c157322abec2d1a0817a259efd9057f88c2113e67d918a9a5ebcb3d88d')
    version('1.11.1', sha256='9f5c10b9471a721ba57d1cf6e5a55a7ad139a6c12da87b4dc128539e9eef370e')
    version('1.11.0', sha256='e89d14ccbe7181777225e0ba6c272c0941539b8ccd440e72ed5a9457441dae83')
    version('1.10.0', sha256='6713069259ee7bfd4d03f47640bf841874e9114bab24e7b0c58e310c42a0ec48')
    version('1.9.0', sha256='23b2bb70540d51ab0855af0b205ca484fd1bd963c39580c29e3133f9e6fffd46')

    variant('mpi', default=True,
            description='Enable MPI support')

    for v in ['1.9.0', '1.10.0', '1.11.0', '1.11.1', '1.12.0', '1.13.0',
              'develop']:
        depends_on('adios@{0} ~mpi'.format(v),
                   when='@{0} ~mpi'.format(v),
                   type=['build', 'link', 'run'])
        depends_on('adios@{0} +mpi'.format(v),
                   when='@{0} +mpi'.format(v),
                   type=['build', 'link', 'run'])

    # NOTE: this dependency is a work-around for a bug in Adios itself.
    # Specifically, Adios uses code that was generated by Cython 0.28.2.
    # This code won't compile against the Python 3.7 C API.
    # See https://github.com/ornladios/ADIOS/issues/202 and
    # the first entry under "Bug Fixes" at
    # https://github.com/cython/cython/blob/0.29.x/CHANGES.rst
    depends_on('python@:3.6')

    depends_on('py-numpy', type=['build', 'run'])
    depends_on('mpi', when='+mpi')
    depends_on('py-mpi4py', type=['run'], when='+mpi')
    depends_on('py-cython', type=['build'])

    phases = ['build_clib', 'install']
    build_directory = 'wrappers/numpy'

    def setup_file(self):
        """Returns the name of the setup file to use."""
        if '+mpi' in self.spec:
            return 'setup_mpi.py'
        else:
            return 'setup.py'

    def build_clib(self, spec, prefix):
        # calls: make [MPI=y] python
        args = ''
        if '+mpi' in self.spec:
            args = 'MPI=y '
        args += 'python'
        with working_dir(self.build_directory):
            make(args)
