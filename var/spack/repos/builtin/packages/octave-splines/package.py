# Copyright 2013-2020 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

from spack.package import *


class OctaveSplines(OctavePackage, SourceforgePackage):
    """Additional spline functions."""

    homepage = "http://octave.sourceforge.net/splines/index.html"
    sourceforge_mirror_path = "octave/splines-1.3.1.tar.gz"

    version('1.3.1', sha256='f9665d780c37aa6a6e17d1f424c49bdeedb89d1192319a4e39c08784122d18f9')
    extends('octave@3.6.0:')
