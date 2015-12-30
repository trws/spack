from spack import *
import os

class Ats(Package):
    """Automated Testing System for batch-script-based projects"""
    homepage = "https://rzlc.llnl.gov/stash"
    url      = "https://rzlc.llnl.gov/stash/scm/ats/ats.git"

    version('current', 'bah')
    
    extends('python')
    depends_on('py-nose')
    depends_on('py-scipy')
    depends_on('py-mysqldb1')

    def install(self, spec, prefix):
        python('setup.py', 'install', '--prefix=%s' % prefix)
        os.chdir("LC")
        python('setup.py', 'install', '--prefix=%s' % prefix)
