# Copyright 2013-2021 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)


from spack import *
from spack.pkg.builtin.boost import Boost


class Folly(CMakePackage):
    """Folly (acronymed loosely after Facebook Open Source Library) is a
    library of C++11 components designed with practicality and efficiency
    in mind.

    Folly contains a variety of core library components used extensively at
    Facebook. In particular, it's often a dependency of Facebook's other open
    source C++ efforts and place where those projects can share code.
    """

    homepage = "https://github.com/facebook/folly"
    url = "https://github.com/facebook/folly/releases/download/v2021.05.24.00/folly-v2021.05.24.00.tar.gz"
    version('2021.05.24.00', sha256='9d308adefe4670637f5c7d96309b3b394ac3fa129bc954f5dfbdd8b741c02aad')

    # CMakePackage Dependency
    depends_on('pkgconfig', type='build')

    # folly requires gcc 4.9+ and a version of boost compiled with >= C++14
    # TODO: Specify the boost components
    variant('cxxstd', default='14', values=('14', '17'), multi=False, description='Use the specified C++ standard when building.')
    for cxx_ver in ('cxxstd=14', 'cxxstd=17'):
        depends_on(Boost.with_default_variants + '+context+container ' + cxx_ver, when=cxx_ver)

    # required dependencies
    depends_on('gflags')
    depends_on('glog')
    depends_on('double-conversion')
    depends_on('libevent')
    depends_on('fmt')

    # optional dependencies
    variant('libdwarf', default=False, description="Optional Dependency")
    variant('elfutils', default=False, description="Optional Dependency")
    variant('libunwind', default=False, description="Optional Dependency")
    depends_on('libdwarf', when='+libdwarf')
    depends_on('elfutils', when='+elfutils')
    depends_on('libunwind', when='+libunwind')

    configure_directory = 'folly'
