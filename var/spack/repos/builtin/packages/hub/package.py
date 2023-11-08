# Copyright 2013-2023 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

import os

from spack.package import *


class Hub(Package):
    """The github git wrapper"""

    homepage = "https://github.com/github/hub"
    url = "https://github.com/github/hub/archive/v2.2.2.tar.gz"
    git = "https://github.com/github/hub.git"

    version("master", branch="master")
    version("2.14.2", sha256="e19e0fdfd1c69c401e1c24dd2d4ecf3fd9044aa4bd3f8d6fd942ed1b2b2ad21a")

    extends("go")

    def install(self, spec, prefix):
        bash = which("bash")
        bash(os.path.join("script", "build"), "-o", os.path.join(prefix, "bin", "hub"))
