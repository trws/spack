# Copyright 2013-2021 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

from spack import *
from spack.pkg.builtin.boost import Boost


class FenicsDolfinx(CMakePackage):
    """Next generation FEniCS problem solving environment"""

    homepage = "https://github.com/FEniCS/dolfinx"
    git = "https://github.com/FEniCS/dolfinx.git"
    url = "https://github.com/FEniCS/dolfinx/archive/0.1.0.tar.gz"
    maintainers = ["js947", "chrisrichardson", "garth-wells"]

    version("main", branch="main")
    version("0.1.0", sha256="0269379769b5b6d4d1864ded64402ecaea08054c2a5793c8685ea15a59af5e33")

    variant("kahip", default=False, description="kahip support")
    variant("parmetis", default=False, description="parmetis support")
    variant("slepc", default=False, description="slepc support")

    depends_on("cmake@3.12:")
    depends_on("pkgconfig", type="build")
    depends_on("mpi")
    depends_on("hdf5")
    depends_on("boost@1.7.0:+filesystem+program_options+timer")
    depends_on("petsc+mpi+shared")
    depends_on("petsc+mpi+shared@3.15.0:", when="@0.1.0")
    depends_on("scotch+mpi")

    depends_on("kahip", when="+kahip")
    depends_on("parmetis", when="+parmetis")
    depends_on("slepc", when="+slepc")

    depends_on("py-fenics-ffcx", type=("build", "run"))
    depends_on("py-fenics-ffcx@main", type=("build", "run"), when="@main")
    depends_on("py-fenics-ffcx@0.1.0", type=("build", "run"), when="@0.1.0")

    depends_on("fenics-basix", type=("build", "run"))
    depends_on("fenics-basix@main", type=("build", "run"), when="@main")
    depends_on("fenics-basix@0.1.0", type=("build", "run"), when="@0.1.0")

    depends_on("py-fenics-basix", type=("build", "run"))
    depends_on("py-fenics-basix@main", type=("build", "run"), when="@main")
    depends_on("py-fenics-basix@0.1.0", type=("build", "run"), when="@0.1.0")

    conflicts('%gcc@:8', msg='Improved C++17 support required')

    root_cmakelists_dir = "cpp"

    def cmake_args(self):
        args = [
            "-DDOLFINX_SKIP_BUILD_TESTS=True",
            "-DDOLFINX_ENABLE_KAHIP=%s" % (
                'ON' if "+kahip" in self.spec else 'OFF'),
            "-DDOLFINX_ENABLE_PARMETIS=%s" % (
                'ON' if "+parmetis" in self.spec else 'OFF'),
            "-DDOLFINX_ENABLE_SLEPC=%s" % (
                'ON' if "+slepc" in self.spec else 'OFF'),
            "-DPython3_ROOT_DIR=%s" % self.spec['python'].home,
            "-DPython3_FIND_STRATEGY=LOCATION",
        ]
        return args
