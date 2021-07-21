# Copyright 2013-2021 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

from spack import *


class PyTorchmetrics(PythonPackage):
    """Machine learning metrics for distributed, scalable PyTorch applications."""

    homepage = "https://github.com/PyTorchLightning/metrics"
    pypi     = "torchmetrics/torchmetrics-0.3.1.tar.gz"

    version('0.3.1', sha256='78f4057db53f7c219fdf9ec9eed151adad18dd43488a44e5c780806d218e3f1d')
    version('0.2.0', sha256='481a28759acd2d77cc088acba6bc7dc4a356c7cb767da2e1495e91e612e2d548')

    depends_on('python@3.6:',     type=('build', 'run'))
    depends_on('py-setuptools',   type='build')
    depends_on('py-numpy',        type=('build', 'run'), when='@0.3.0:')
    depends_on('py-torch@1.3.1:', type=('build', 'run'))
    depends_on('py-packaging',    type=('build', 'run'), when='@0.3.0:')
