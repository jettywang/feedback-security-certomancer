"""
Tests and demo for validity references: certificates whose validity
endpoints are anchored to explicitly named endpoints of other certificates,
plus an offset.
"""

from datetime import datetime, timedelta, timezone

import pytest

from certomancer import CertomancerConfig
from certomancer.config_utils import ConfigurationError
from certomancer.registry import ArchLabel, CertLabel

KEY_DIR = 'tests/data'

UTC = timezone.utc


def _keysets():
    return {
        'testing-ca': {
            'path-prefix': 'keys-rsa',
            'keys': {
                'root': {'path': 'root.key.pem', 'password': 'secret'},
                'interm': {'path': 'interm.key.pem', 'password': 'secret'},
                'interm2': {
                    'path': 'interm-ocsp.key.pem',
                    'password': 'secret',
                },
                'client': {'path': 'signer.key.pem', 'password': 'secret'},
            },
        }
    }


def _entities():
    return {
        'root': {'common-name': 'Root CA'},
        'interm': {'common-name': 'Intermediate CA'},
        'client': {'common-name': 'Test Client'},
    }


CA_EXTENSIONS = [
    {'id': 'basic_constraints', 'critical': True, 'value': {'ca': True}},
]


def rotation_certs(anchor_from, anchor_to):
    """
    A CA, two rotating intermediates and a client certificate.
    Only the CA's validity window is anchored to absolute timestamps;
    everything else is derived from explicitly named certificate endpoints.
    """
    return {
        'root': {
            'subject': 'root',
            'issuer': 'root',
            'validity': {'valid-from': anchor_from, 'valid-to': anchor_to},
            'extensions': CA_EXTENSIONS,
        },
        'interm-1': {
            'subject': 'interm',
            'issuer': 'root',
            'subject-key': 'interm',
            'validity': {
                'valid-from': {
                    'cert': 'root',
                    'endpoint': 'not-before',
                    'offset': 'P1D',
                },
                'valid-to': {
                    'cert': 'root',
                    'endpoint': 'not-before',
                    'offset': 'P180D',
                },
            },
            'extensions': CA_EXTENSIONS,
        },
        # inherits issuer & extensions from interm-1;
        # validity references are resolved after template inheritance
        'interm-2': {
            'template': 'interm-1',
            'subject': 'interm',
            'subject-key': 'interm2',
            'validity': {
                'valid-from': {
                    'cert': 'root',
                    'endpoint': 'not-before',
                    'offset': 'P180D',
                },
                'valid-to': {
                    'cert': 'root',
                    'endpoint': 'not-after',
                    'offset': '-P1D',
                },
            },
        },
        'client': {
            'subject': 'client',
            'issuer': 'interm',
            'issuer-cert': 'interm-2',
            'authority-key': 'interm2',
            'validity': {
                'valid-from': {
                    'cert': 'interm-2',
                    'endpoint': 'not-before',
                    'offset': 'P1D',
                },
                'valid-to': {
                    'cert': 'interm-2',
                    'endpoint': 'not-after',
                    'offset': '-P1D',
                },
            },
        },
    }


def make_config(certs, strict_validity=False, attr_certs=None):
    arch_cfg = {'entities': _entities(), 'certs': certs}
    if attr_certs is not None:
        arch_cfg['attr-certs'] = attr_certs
    cfg = {
        'keysets': _keysets(),
        'pki-architectures': {'testing-ca': arch_cfg},
    }
    return CertomancerConfig(
        cfg, key_search_dir=KEY_DIR, strict_validity=strict_validity
    )


def get_arch(cfg):
    return cfg.get_pki_arch(ArchLabel('testing-ca'))


def signed_validity(arch, label):
    cert = arch.get_cert(CertLabel(label))
    return cert.not_valid_before, cert.not_valid_after


def test_anchor_shift_moves_derived_validity():
    # first anchor position
    arch = get_arch(
        make_config(
            rotation_certs(
                "2020-01-01T00:00:00+0000", "2030-01-01T00:00:00+0000"
            )
        )
    )
    a = datetime(2020, 1, 1, tzinfo=UTC)
    z = datetime(2030, 1, 1, tzinfo=UTC)
    assert signed_validity(arch, 'interm-1') == (
        a + timedelta(days=1),
        a + timedelta(days=180),
    )
    assert signed_validity(arch, 'interm-2') == (
        a + timedelta(days=180),
        z - timedelta(days=1),
    )
    assert signed_validity(arch, 'client') == (
        a + timedelta(days=181),
        z - timedelta(days=2),
    )

    # move the anchor; all derived dates in the signed certs move along
    arch = get_arch(
        make_config(
            rotation_certs(
                "2021-06-15T00:00:00+0000", "2031-06-15T00:00:00+0000"
            )
        )
    )
    a2 = datetime(2021, 6, 15, tzinfo=UTC)
    z2 = datetime(2031, 6, 15, tzinfo=UTC)
    assert signed_validity(arch, 'interm-1') == (
        a2 + timedelta(days=1),
        a2 + timedelta(days=180),
    )
    assert signed_validity(arch, 'interm-2') == (
        a2 + timedelta(days=180),
        z2 - timedelta(days=1),
    )
    assert signed_validity(arch, 'client') == (
        a2 + timedelta(days=181),
        z2 - timedelta(days=2),
    )


def test_declaration_order_does_not_matter():
    certs = rotation_certs(
        "2020-01-01T00:00:00+0000", "2030-01-01T00:00:00+0000"
    )
    arch = get_arch(make_config(certs))

    # shuffle declaration order: client first, anchor (root) last;
    # interm-1 still precedes interm-2 because of the template relation
    shuffled = {
        lbl: certs[lbl] for lbl in ('client', 'interm-1', 'interm-2', 'root')
    }
    arch_shuffled = get_arch(make_config(shuffled))

    for lbl in ('root', 'interm-1', 'interm-2', 'client'):
        assert signed_validity(arch, lbl) == signed_validity(arch_shuffled, lbl)


def _minimal_certs(**cert_overrides):
    certs = {
        'root': {
            'subject': 'root',
            'issuer': 'root',
            'validity': {
                'valid-from': "2020-01-01T00:00:00+0000",
                'valid-to': "2030-01-01T00:00:00+0000",
            },
        }
    }
    certs.update(cert_overrides)
    return certs


def test_circular_reference():
    certs = _minimal_certs(
        **{
            'cert-a': {
                'subject': 'client',
                'issuer': 'root',
                'validity': {
                    'valid-from': {'cert': 'cert-b', 'endpoint': 'not-before'},
                    'valid-to': "2025-01-01T00:00:00+0000",
                },
            },
            'cert-b': {
                'subject': 'interm',
                'issuer': 'root',
                'validity': {
                    'valid-from': {'cert': 'cert-a', 'endpoint': 'not-before'},
                    'valid-to': "2025-01-01T00:00:00+0000",
                },
            },
        }
    )
    with pytest.raises(ConfigurationError, match="[Cc]ircular"):
        make_config(certs)


def test_self_reference():
    certs = _minimal_certs(
        **{
            'cert-a': {
                'subject': 'client',
                'issuer': 'root',
                'validity': {
                    'valid-from': {'cert': 'cert-a', 'endpoint': 'not-before'},
                    'valid-to': "2025-01-01T00:00:00+0000",
                },
            },
        }
    )
    with pytest.raises(ConfigurationError, match="itself"):
        make_config(certs)


def test_unknown_reference_target():
    certs = _minimal_certs(
        **{
            'cert-a': {
                'subject': 'client',
                'issuer': 'root',
                'validity': {
                    'valid-from': {'cert': 'nope', 'endpoint': 'not-before'},
                    'valid-to': "2025-01-01T00:00:00+0000",
                },
            },
        }
    )
    with pytest.raises(ConfigurationError, match="unknown certificate 'nope'"):
        make_config(certs)


def test_missing_timezone():
    certs = _minimal_certs(
        **{
            'cert-a': {
                'subject': 'client',
                'issuer': 'root',
                'validity': {
                    'valid-from': "2020-06-01T00:00:00",
                    'valid-to': "2025-01-01T00:00:00+0000",
                },
            },
        }
    )
    with pytest.raises(ConfigurationError, match="timezone"):
        make_config(certs)


def test_inverted_validity():
    certs = _minimal_certs(
        **{
            'cert-a': {
                'subject': 'client',
                'issuer': 'root',
                'validity': {
                    'valid-from': {'cert': 'root', 'endpoint': 'not-after'},
                    'valid-to': {'cert': 'root', 'endpoint': 'not-before'},
                },
            },
        }
    )
    with pytest.raises(ConfigurationError, match="inverted"):
        make_config(certs)


def test_same_subject_rotation_reference():
    # interm-2 may not anchor to interm-1: both are issued to 'interm'
    certs = rotation_certs(
        "2020-01-01T00:00:00+0000", "2030-01-01T00:00:00+0000"
    )
    certs['interm-2']['validity'] = {
        'valid-from': {'cert': 'interm-1', 'endpoint': 'not-after'},
        'valid-to': {'cert': 'root', 'endpoint': 'not-after'},
    }
    with pytest.raises(ConfigurationError, match="same subject"):
        make_config(certs)


def test_strict_issuer_validity_window():
    certs = rotation_certs(
        "2020-01-01T00:00:00+0000", "2030-01-01T00:00:00+0000"
    )
    # client outlives its issuer certificate interm-2
    certs['client']['validity']['valid-to'] = "2040-01-01T00:00:00+0000"

    # non-strict: dates are used as configured, never silently clipped
    arch = get_arch(make_config(certs))
    _, client_not_after = signed_validity(arch, 'client')
    assert client_not_after == datetime(2040, 1, 1, tzinfo=UTC)

    # strict: the violation is reported with a reason
    with pytest.raises(
        ConfigurationError,
        match="'client' exceeds that of its issuer certificate 'interm-2'",
    ):
        make_config(certs, strict_validity=True)


def test_attr_cert_validity_ref():
    certs = _minimal_certs(
        **{
            'client': {
                'subject': 'client',
                'issuer': 'root',
                'validity': {
                    'valid-from': "2020-01-01T00:00:00+0000",
                    'valid-to': "2030-01-01T00:00:00+0000",
                },
            },
        }
    )
    attr_certs = {
        'test-ac': {
            'holder': {'name': 'client', 'cert': 'client'},
            'issuer': 'root',
            'attributes': [
                {
                    'id': 'role',
                    'smart-value': {
                        'schema': 'role-syntax',
                        'params': {
                            'name': {
                                'type': 'email',
                                'value': 'bigboss@example.com',
                            }
                        },
                    },
                }
            ],
            'validity': {
                'valid-from': {
                    'cert': 'root',
                    'endpoint': 'not-before',
                    'offset': 'P2D',
                },
                'valid-to': {
                    'cert': 'root',
                    'endpoint': 'not-after',
                    'offset': '-P2D',
                },
            },
        }
    }
    arch = get_arch(make_config(certs, attr_certs=attr_certs))
    ac = arch.get_attr_cert(CertLabel('test-ac'))
    period = ac['ac_info']['att_cert_validity_period']
    assert period['not_before_time'].native == datetime(2020, 1, 3, tzinfo=UTC)
    assert period['not_after_time'].native == datetime(2029, 12, 30, tzinfo=UTC)
