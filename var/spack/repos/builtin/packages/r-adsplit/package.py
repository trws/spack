# Copyright 2013-2020 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

from spack.std import *


class RAdsplit(RPackage):
    """Annotation-Driven Clustering.

       This package implements clustering of microarray gene expression
       profiles according to functional annotations. For each term genes are
       annotated to, splits into two subclasses are computed and a significance
       of the supporting gene set is determined."""

    homepage = "https://bioconductor.org/packages/adSplit"
    git      = "https://git.bioconductor.org/packages/adSplit.git"

    version('1.54.0', commit='ce8fb61f4a3d0942294da2baa28be1472acb0652')
    version('1.52.0', commit='3bd105dbd76c52798b7d52f60c17de62ef13da19')
    version('1.50.0', commit='a02e2c994e78ececd5a248575109c5ed36c969db')
    version('1.48.0', commit='57dfcd93b9232cf53f05c34179ecb759bb7aff46')
    version('1.46.0', commit='7e81a83f34d371447f491b3a146bf6851e260c7c')

    depends_on('r@2.1.0:', type=('build', 'run'))
    depends_on('r-annotationdbi', type=('build', 'run'))
    depends_on('r-biobase@1.5.12:', type=('build', 'run'))
    depends_on('r-cluster@1.9.1:', type=('build', 'run'))
    depends_on('r-go-db@1.8.1:', type=('build', 'run'))
    depends_on('r-kegg-db@1.8.1:', type=('build', 'run'))
    depends_on('r-multtest@1.6.0:', type=('build', 'run'))
