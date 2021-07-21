# Copyright 2013-2021 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)
import pytest

import spack.bootstrap
import spack.store
import spack.util.path


@pytest.mark.regression('22294')
def test_store_is_restored_correctly_after_bootstrap(mutable_config, tmpdir):
    # Prepare a custom store path. This should be in a writeable location
    # since Spack needs to initialize the DB.
    user_path = str(tmpdir.join('store'))
    # Reassign global variables in spack.store to the value
    # they would have at Spack startup.
    spack.store.reinitialize()
    # Set the custom user path
    spack.config.set('config:install_tree:root', user_path)

    # Test that within the context manager we use the bootstrap store
    # and that outside we restore the correct location
    with spack.bootstrap.ensure_bootstrap_configuration():
        assert spack.store.root == spack.bootstrap.store_path()
    assert spack.store.root == user_path


@pytest.mark.parametrize('config_value,expected', [
    # Absolute path without expansion
    ('/opt/spack/bootstrap', '/opt/spack/bootstrap/store'),
    # Path with placeholder
    ('$spack/opt/bootstrap', '$spack/opt/bootstrap/store'),
])
def test_store_path_customization(config_value, expected, mutable_config):
    # Set the current configuration to a specific value
    spack.config.set('bootstrap:root', config_value)

    # Check the store path
    current = spack.bootstrap.store_path()
    assert current == spack.util.path.canonicalize_path(expected)


def test_raising_exception_if_bootstrap_disabled(mutable_config):
    # Disable bootstrapping in config.yaml
    spack.config.set('bootstrap:enable', False)

    # Check the correct exception is raised
    with pytest.raises(RuntimeError, match='bootstrapping is currently disabled'):
        spack.bootstrap.store_path()
