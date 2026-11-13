"""
Tests for endpoint-aware certificate chain construction and PKCS#12
packaging, including self-issued key rollover, cross-signed intermediate
certificates (multiple viable chains) and configuration cycles.
"""
import importlib
import os
import re

import pytest
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12

from certomancer.config_utils import SearchDir
from certomancer.registry import (
    ArchLabel,
    CertLabel,
    PKIArchitecture,
)
from certomancer.registry.entities import EntityRegistry
from certomancer.registry.keys import KeySet
from certomancer.services import CertomancerChainError, CertomancerServiceError

importlib.import_module('certomancer.default_plugins')

TEST_DATA_DIR = 'tests/data'
DUMMY_PASSWORD = 'secret'
KEY_NAME_REGEX = re.compile(r'([a-zA-Z0-9-]+)\.key\.pem')

VALIDITY = '''
    valid-from: "2000-01-01T00:00:00+0000"
    valid-to: "2500-01-01T00:00:00+0000"'''
CA_EXTENSIONS = '''
    - id: basic_constraints
      critical: true
      value: {ca: true}'''


def _rsa_keyset():
    def _keys():
        for fname in os.listdir(os.path.join(TEST_DATA_DIR, 'keys-rsa')):
            match = KEY_NAME_REGEX.fullmatch(fname)
            if not match:
                continue
            key_cfg = {'path': fname}
            if 'pub' in fname:
                key_cfg['public-only'] = True
            elif 'aa' not in fname:
                key_cfg['password'] = DUMMY_PASSWORD
            yield match.group(1), key_cfg

    return KeySet(
        {'path-prefix': 'keys-rsa', 'keys': dict(_keys())},
        search_dir=SearchDir(TEST_DATA_DIR),
    )


RSA_KEYS = _rsa_keyset()

ENTITIES = EntityRegistry(
    yaml.safe_load(
        '''
root1: {common-name: Root CA 1}
root2: {common-name: Root CA 2}
interm: {common-name: Intermediate CA}
signer1: {common-name: Alice}
'''
    ),
    defaults=yaml.safe_load(
        'country-name: BE\norganization-name: Testing Authority\n'
    ),
)

# Two self-signed roots. The intermediate entity owns the same-key cert
# interm-a (signed by root1) and its cross-cert interm-b (signed by root2).
# interm-rollover is a self-issued but NOT self-signed key-rollover cert.
# The leaf's issuer entity owns both cross-signed intermediates, so two
# distinct chains are viable depending on the requested endpoint.
CROSS_SIGNED_CFG = f'''
root1:
  subject: root1
  subject-key: root
  issuer: root1
  authority-key: root
  validity:{VALIDITY}
  extensions:{CA_EXTENSIONS}
root2:
  subject: root2
  subject-key: tsa2
  issuer: root2
  authority-key: tsa2
  validity:{VALIDITY}
  extensions:{CA_EXTENSIONS}
interm-a:
  subject: interm
  subject-key: interm
  issuer: root1
  authority-key: root
  issuer-cert: root1
  validity:{VALIDITY}
  extensions:{CA_EXTENSIONS}
interm-b:
  subject: interm
  subject-key: interm
  issuer: root2
  authority-key: tsa2
  issuer-cert: root2
  validity:{VALIDITY}
  extensions:{CA_EXTENSIONS}
interm-rollover:
  subject: interm
  subject-key: tsa
  issuer: interm
  authority-key: interm
  issuer-cert: interm-a
  validity:{VALIDITY}
  extensions:{CA_EXTENSIONS}
signer1:
  subject: signer1
  subject-key: signer
  issuer: interm
  authority-key: interm
  issuer-cert: interm-a
  validity:
    valid-from: "2010-01-01T00:00:00+0000"
    valid-to: "2100-01-01T00:00:00+0000"
  extensions:
    - id: key_usage
      critical: true
      smart-value:
        schema: key-usage
        params: [digital_signature]
'''


@pytest.fixture(scope='module')
def arch():
    architecture = PKIArchitecture(
        arch_label=ArchLabel('cross-signed'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(CROSS_SIGNED_CFG),
        service_config={},
        external_url_prefix='http://test.test',
    )
    return architecture


def _verify_signature(architecture, child_label, issuer_label):
    child = architecture.get_cert(CertLabel(child_label))
    issuer = architecture.get_cert(CertLabel(issuer_label))
    public_key = serialization.load_der_public_key(
        issuer.public_key.dump()
    )
    public_key.verify(
        child.signature,
        child['tbs_certificate'].dump(),
        padding.PKCS1v15(),
        getattr(hashes, child.hash_algo.upper())(),
    )
    assert (
        child.authority_key_identifier
        == issuer.key_identifier_value.native
    )


def test_no_cycles_in_cross_signed_architecture(arch):
    # must not raise
    arch.check_chain_cycles()


def test_default_chain_preserves_compatibility(arch):
    chain = list(arch.get_chain(CertLabel('signer1')))
    assert [str(label) for label in chain] == ['interm-a', 'root1']


def test_self_issued_rollover_does_not_terminate_chain(arch):
    # the rollover cert is self-issued (same subject/issuer entity) but not
    # self-signed, so the walk must continue up to the root instead of
    # stopping at the matching name
    spec = arch.get_cert_spec(CertLabel('interm-rollover'))
    assert spec.self_issued
    assert not spec.self_signed
    chain = list(arch.get_chain(CertLabel('interm-rollover')))
    assert [str(label) for label in chain] == ['interm-a', 'root1']


def test_chains_for_different_endpoints(arch):
    to_root1 = arch.build_chain(CertLabel('signer1'), CertLabel('root1'))
    to_root2 = arch.build_chain(CertLabel('signer1'), CertLabel('root2'))
    assert [str(label) for label in to_root1] == ['interm-a', 'root1']
    assert [str(label) for label in to_root2] == ['interm-b', 'root2']

    # stopping at an intermediate endpoint includes that endpoint and stops
    to_interm_b = arch.build_chain(
        CertLabel('signer1'), CertLabel('interm-b')
    )
    assert [str(label) for label in to_interm_b] == ['interm-b']


def test_get_chain_with_endpoint_matches_build_chain(arch):
    assert list(arch.get_chain(CertLabel('signer1'), CertLabel('root2'))) == (
        arch.build_chain(CertLabel('signer1'), CertLabel('root2'))
    )


def test_possible_chains_enumerates_both_roots(arch):
    chains = arch.get_possible_chains(CertLabel('signer1'))
    rendered = sorted(
        tuple(str(label) for label in chain) for chain in chains
    )
    assert rendered == [
        ('interm-a', 'root1'),
        ('interm-b', 'root2'),
    ]


def test_explicit_endpoint_argument_to_possible_chains(arch):
    chains = arch.get_possible_chains(
        CertLabel('signer1'), endpoints=[CertLabel('interm-a')]
    )
    assert [
        [str(label) for label in chain] for chain in chains
    ] == [['interm-a']]


def test_unreachable_endpoint_raises(arch):
    # root1 cannot be reached by walking upwards from root2
    with pytest.raises(CertomancerChainError, match='no valid issuer path'):
        arch.build_chain(CertLabel('root1'), CertLabel('root2'))


def test_unknown_endpoint_raises(arch):
    with pytest.raises(CertomancerServiceError):
        arch.build_chain(CertLabel('signer1'), CertLabel('nope'))


def test_self_signed_root_has_empty_chain(arch):
    assert list(arch.get_chain(CertLabel('root1'))) == []


def test_endpoint_equal_to_start_returns_empty_chain(arch):
    assert arch.build_chain(
        CertLabel('root1'), CertLabel('root1')
    ) == []
    assert arch.build_chain(
        CertLabel('signer1'), CertLabel('signer1')
    ) == []


def test_raw_string_labels_are_accepted(arch):
    chain = arch.build_chain('signer1', 'root2')
    assert [str(label) for label in chain] == ['interm-b', 'root2']


def test_every_chain_signature_relation_verifies(arch):
    for endpoint in ('root1', 'root2'):
        chain = arch.build_chain(CertLabel('signer1'), CertLabel(endpoint))
        sequence = ['signer1'] + [str(label) for label in chain]
        for child_label, issuer_label in zip(sequence, sequence[1:]):
            _verify_signature(arch, child_label, issuer_label)

    # the rollover cert is signed with the old intermediate key
    _verify_signature(arch, 'interm-rollover', 'interm-a')


def test_cross_cert_does_not_verify_under_wrong_root(arch):
    # interm-a is signed by root1, so its signature must fail against root2
    with pytest.raises(Exception):
        _verify_signature(arch, 'interm-a', 'root2')
    with pytest.raises(Exception):
        _verify_signature(arch, 'interm-b', 'root1')


@pytest.mark.parametrize(
    'endpoint,expected',
    [
        ('root1', ['interm-a', 'root1']),
        ('root2', ['interm-b', 'root2']),
    ],
)
def test_pkcs12_packages_only_the_selected_chain(arch, endpoint, expected):
    package = arch.package_pkcs12(
        CertLabel('signer1'),
        password=b'secret',
        chain_endpoint=CertLabel(endpoint),
    )
    _, _, extra_certs = pkcs12.load_key_and_certificates(
        package, b'secret'
    )
    embedded_der = {
        cert.public_bytes(serialization.Encoding.DER) for cert in extra_certs
    }
    expected_der = {
        arch.get_cert(CertLabel(label)).dump() for label in expected
    }
    assert embedded_der == expected_der

    # the intermediate of the *other* chain must not leak into the package
    other = 'interm-b' if endpoint == 'root1' else 'interm-a'
    assert arch.get_cert(CertLabel(other)).dump() not in embedded_der


def test_pkcs12_default_packaging_is_compatible(arch):
    package = arch.package_pkcs12(CertLabel('signer1'), password=b'secret')
    _, _, extra_certs = pkcs12.load_key_and_certificates(
        package, b'secret'
    )
    assert len(extra_certs) == 2


def test_pkcs12_rejects_endpoint_with_explicit_certs(arch):
    with pytest.raises(CertomancerServiceError, match='cannot be combined'):
        arch.package_pkcs12(
            CertLabel('signer1'),
            certs_to_embed=[CertLabel('root1')],
            chain_endpoint=CertLabel('root2'),
        )


def test_animator_pfx_honours_chain_to_form_field(arch):
    from werkzeug.test import Client
    from werkzeug.wrappers import Response

    from certomancer.integrations.animator import (
        Animator,
        AnimatorArchStore,
    )

    animator = Animator(
        AnimatorArchStore({ArchLabel('cross-signed'): arch}),
    )
    client = Client(animator, Response)

    response = client.post(
        '/_certomancer/pfx-download/cross-signed',
        data={'cert': 'signer1', 'passphrase': 'secret',
              'chain_to': 'root2'},
    )
    assert response.status_code == 200
    _, _, extra_certs = pkcs12.load_key_and_certificates(
        response.data, b'secret'
    )
    embedded_der = {
        cert.public_bytes(serialization.Encoding.DER) for cert in extra_certs
    }
    expected = arch.build_chain(CertLabel('signer1'), CertLabel('root2'))
    assert embedded_der == {
        arch.get_cert(label).dump() for label in expected
    }


CYCLE_CFG = '''
a:
  subject: signer1
  subject-key: signer
  issuer: signer1
  authority-key: tsa
  issuer-cert: b
  validity:
    valid-from: "2010-01-01T00:00:00+0000"
    valid-to: "2100-01-01T00:00:00+0000"
b:
  subject: signer1
  subject-key: tsa
  issuer: signer1
  authority-key: signer
  issuer-cert: a
  validity:
    valid-from: "2010-01-01T00:00:00+0000"
    valid-to: "2100-01-01T00:00:00+0000"
'''


def _cycle_arch():
    return PKIArchitecture(
        arch_label=ArchLabel('cyclic'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(CYCLE_CFG),
        service_config={},
        external_url_prefix='http://test.test',
    )


def test_configuration_cycle_is_detected():
    with pytest.raises(CertomancerChainError, match='cycle'):
        _cycle_arch().check_chain_cycles()


def test_build_chain_on_cycle_raises_instead_of_looping():
    with pytest.raises(CertomancerChainError):
        _cycle_arch().build_chain(CertLabel('a'))
