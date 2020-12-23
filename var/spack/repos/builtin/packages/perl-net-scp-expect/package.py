# Copyright 2013-2020 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

from spack.package import *


class PerlNetScpExpect(PerlPackage):
    """Wrapper for scp that allows passwords via Expect."""

    homepage = "http://search.cpan.org/~rybskej/Net-SCP-Expect/Expect.pm"
    url      = "http://search.cpan.org/CPAN/authors/id/R/RY/RYBSKEJ/Net-SCP-Expect-0.16.tar.gz"

    version('0.16', sha256='97586e0ee0d61c987a7efaaffbfa551b95c426b3ef3625e046dc456fe9170591')
