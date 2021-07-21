# Copyright 2013-2021 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

from spack import *


class PyFenicsBasix(PythonPackage):
    """Python basis evaluation library for Next generation FEniCS problem solving
    environment"""

    homepage = "https://github.com/FEniCS/basix"
    url = "https://github.com/FEniCS/basix/archive/0.1.0.tar.gz"
    git = "https://github.com/FEniCS/basix.git"
    maintainers = ["chrisrichardson", "mscroggs", "garth-wells"]

    version("main", branch="main")
    version("0.1.0", sha256="2ab41fe6ad4f6c42f01b17a6e7c39debb4e0ae61c334d1caebee78b741bca4e7")

    depends_on("fenics-basix@main", type=("build", "run"), when="@main")
    depends_on("fenics-basix@0.1.0", type=("build", "run"), when="@0.1.0")

    depends_on("python@3.7:", type=('build', 'run'))
    depends_on("py-setuptools", type="build")
    depends_on("cmake@3.18:", type="build")
    depends_on("py-pybind11@2.6.2:", type="build")

    phases = ['build_ext', 'build', 'install']

    build_directory = 'python'
