import importlib

import pytest

from certomancer._asn1_types import register_extensions
from certomancer.integrations import illusionist
from certomancer.registry import (
    ArchLabel,
    CertLabel,
    CertomancerConfig,
    KeyLabel,
)

register_extensions()
importlib.import_module('certomancer.default_plugins')
importlib.import_module('scep_plugin')


@pytest.fixture
def setup(requests_mock):
    cfg = CertomancerConfig.from_file('tests/data/with-scep.yml', 'tests/data')
    arch = cfg.get_pki_arch(ArchLabel('testing-ca'))
    illusionist.Illusionist(pki_arch=arch).register(requests_mock)
    return cfg, arch


@pytest.fixture
def arch(setup):
    return setup[1]


@pytest.fixture
def materials(arch):
    """Certificates and private keys referenced by the SCEP tests."""
    ra_cert = arch.get_cert(CertLabel('scep-ra'))
    ra_key = arch.key_set.get_private_key(KeyLabel('interm'))
    target_cert = arch.get_cert(CertLabel('scep-target'))
    target_key = arch.key_set.get_private_key(KeyLabel('signer1'))
    other_cert = arch.get_cert(CertLabel('other-client'))
    other_key = arch.key_set.get_private_key(KeyLabel('signer2'))
    return {
        'ra_cert': ra_cert,
        'ra_key': ra_key,
        'target_cert': target_cert,
        'target_key': target_key,
        'other_cert': other_cert,
        'other_key': other_key,
    }
