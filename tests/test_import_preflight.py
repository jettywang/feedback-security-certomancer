import importlib
import logging

import pytest
from asn1crypto import algos, ocsp, x509

from certomancer.config_utils import ConfigurationError
from certomancer.crypto_utils import load_cert_from_pemder
from certomancer.registry import (
    ArchLabel,
    CertLabel,
    CertomancerConfig,
    EntityLabel,
    ServiceLabel,
)

importlib.import_module('certomancer.default_plugins')

SAMPLE_DIR = 'tests/data/import-samples'


def _load(name):
    return CertomancerConfig.from_file(
        f'{SAMPLE_DIR}/{name}', 'tests/data'
    ).get_pki_arch(ArchLabel('testing-ca'))


def _at_time():
    from datetime import datetime, timezone

    return datetime(2021, 6, 1, tzinfo=timezone.utc)


def _cert_id(arch, issuer, serial):
    issuer_cert = arch.get_cert(issuer)
    return ocsp.CertId(
        {
            'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
            'issuer_name_hash': arch.entities.get_name_hash(issuer, 'sha256'),
            'issuer_key_hash': issuer_cert.public_key.sha256,
            'serial_number': serial,
        }
    )


def _pyca_verify(cert: x509.Certificate, issuer_cert: x509.Certificate):
    from cryptography import x509 as pyca_x509

    pyca_leaf = pyca_x509.load_der_x509_certificate(cert.dump())
    pyca_leaf.verify_directly_issued_by(
        pyca_x509.load_der_x509_certificate(issuer_cert.dump())
    )


@pytest.mark.parametrize(
    'config_file, cert_label, fields',
    [
        ('with-wrong-serial.yml', 'signer', ['serial number']),
        ('with-rotated-key.yml', 'signer', ['subject public key info']),
    ],
)
def test_import_mismatch_rejected(config_file, cert_label, fields):
    with pytest.raises(ConfigurationError) as exc_info:
        _load(config_file)

    msg = str(exc_info.value)
    assert cert_label in msg
    for field in fields:
        assert field in msg
    # the diagnostic must identify the affected trust services explicitly
    assert "OCSP responder 'ca'" in msg
    assert "CRL repository 'ca'" in msg


def test_wrong_serial_diagnostic_mentions_values():
    with pytest.raises(ConfigurationError) as exc_info:
        _load('with-wrong-serial.yml')

    msg = str(exc_info.value)
    assert '0x2000' in msg  # value mandated by the spec
    assert '0x9999' in msg  # value in the imported DER


def test_rotated_key_diagnostic_mentions_keys_not_files():
    with pytest.raises(ConfigurationError) as exc_info:
        _load('with-rotated-key.yml')

    msg = str(exc_info.value)
    # key fingerprints, not the PEM file name or its text
    assert 'SHA-256' in msg
    assert 'rotated-key.pem' not in msg
    assert 'BEGIN CERTIFICATE' not in msg


def test_serial_collision_rejected():
    with pytest.raises(ConfigurationError) as exc_info:
        _load('with-serial-collision.yml')

    msg = str(exc_info.value)
    assert 'signer2' in msg
    assert "OCSP responder 'ca'" in msg
    assert "CRL repository 'ca'" in msg


def test_serial_collision_swaps_certificate_identity():
    """
    With allow-import-mismatch, the imported DER is served with a serial that
    also belongs to signer2. A query for signer2's serial consequently resolves
    to the imported signer spec, so OCSP and CRL answer about the wrong
    certificate. This is exactly the conflict the preflight rejects by default.
    """

    arch = _load('with-serial-collision-allowed.yml')
    check = arch.get_import_preflight_results()[CertLabel('signer')]
    assert "OCSP responder 'ca'" in check.affected_services

    issuer = arch.get_cert(CertLabel('ca'))
    collision_serial = arch.get_cert_spec(CertLabel('signer2')).serial
    cid = _cert_id(arch, EntityLabel('ca'), collision_serial)

    # A client asking about signer2 is answered as if it asked about signer.
    found = arch.find_cert_label(cid, issuer_label=EntityLabel('ca'))
    assert found == CertLabel('signer')

    responder = arch.service_registry.summon_responder(
        ServiceLabel('ca'), at_time=_at_time()
    )
    single = responder.format_single_ocsp_response(cid, issuer_cert=issuer)
    assert single['cert_status'].name == 'revoked'

    # The CRL lists the colliding serial once, whichever spec generated it.
    crl = arch.service_registry.get_crl(ServiceLabel('ca'), at_time=_at_time())
    revoked = crl['tbs_cert_list']['revoked_certificates']
    assert [r['user_certificate'].native for r in revoked] == [collision_serial]


def test_allow_import_mismatch_retains_diagnostics(caplog):
    with caplog.at_level(
        logging.WARNING, logger='certomancer.registry.import_check'
    ):
        arch = _load('with-wrong-serial-allowed.yml')

    results = arch.get_import_preflight_results()
    check = results[CertLabel('signer')]
    assert not check.ok
    assert check.mismatches[0].field == 'serial number'
    assert check.mismatches[0].expected == '0x2000'
    assert check.mismatches[0].actual == '0x9999'
    assert "OCSP responder 'ca'" in check.affected_services
    assert "CRL repository 'ca'" in check.affected_services

    # the mismatch remains visible in the log
    assert any('allow-import-mismatch' in rec.message for rec in caplog.records)


def test_allowed_mismatch_keeps_der_and_spec_apart():
    """
    Pin down what "allowed" means: the imported DER is served verbatim, while
    OCSP and CRL keep answering about the certificate described by the spec.
    """

    arch = _load('with-wrong-serial-allowed.yml')
    der_serial = 0x9999

    served = arch.get_cert(CertLabel('signer'))
    assert served.serial_number == der_serial

    # CertID lookup uses the served DER serial, so the responder can find the
    # certificate by the serial number clients actually see.
    der_cid = _cert_id(arch, EntityLabel('ca'), der_serial)
    found = arch.find_cert_label(der_cid, issuer_label=EntityLabel('ca'))
    assert found == CertLabel('signer')

    # Revocation, on the other hand, follows the spec; the service reports on
    # the spec's identity, not on the DER identity.
    responder = arch.service_registry.summon_responder(
        ServiceLabel('ca'), at_time=_at_time()
    )
    single = responder.format_single_ocsp_response(
        der_cid, issuer_cert=arch.get_cert(CertLabel('ca'))
    )
    assert single['cert_status'].name == 'revoked'


def test_allowed_serial_collision_names_the_conflicting_label():
    from certomancer.registry.import_check import (
        ImportedCertificateCheck,
        ImportedCertMismatch,
    )

    # Construct a minimal check to assert on the diagnostics format.
    m = ImportedCertMismatch(
        field='serial number',
        expected="unique serial for issuer 'ca'",
        actual='0x2000 also used by signer2',
    )
    check = ImportedCertificateCheck(
        label=CertLabel('signer'),
        certificate=None,
        mismatches=[m],
        affected_services=["OCSP responder 'ca'"],
    )
    text = check.describe()
    assert 'serial number' in text
    assert 'signer2' in text
    assert "OCSP responder 'ca'" in text


def test_external_certs_without_local_private_keys():
    cfg = CertomancerConfig.from_file(
        f'{SAMPLE_DIR}/with-external.yml', SAMPLE_DIR
    )
    arch = cfg.get_pki_arch(ArchLabel('external'))

    results = arch.get_import_preflight_results()
    assert set(results) == {
        CertLabel('external-ca'),
        CertLabel('external-leaf'),
    }
    assert all(check.ok for check in results.values())

    ca = arch.get_cert(CertLabel('external-ca'))
    leaf = arch.get_cert(CertLabel('external-leaf'))
    assert (
        ca.dump()
        == load_cert_from_pemder(f'{SAMPLE_DIR}/external-ca.pem').dump()
    )
    assert leaf.issuer == ca.subject
    _pyca_verify(leaf, ca)

    # no local key material was needed for the imported certificates
    assert not any(
        key.private_key_info is not None for key in arch.key_set._dict.values()
    )


def test_external_leaf_with_wrong_issuer_fails():
    """
    The external leaf is only accepted because it verifies against the
    imported CA. Swapping the CA for a certificate with the same subject DN
    but a different key must fail the signature check.
    """

    with pytest.raises(ConfigurationError) as exc_info:
        CertomancerConfig.from_file(
            f'{SAMPLE_DIR}/with-wrong-external-issuer.yml', SAMPLE_DIR
        )

    msg = str(exc_info.value)
    assert 'signature' in msg
    assert "impostor-ca" in msg
    # the subject DN and serial are identical; the key is what differs
    assert 'subject public key info' not in msg
    assert 'serial number' not in msg


def test_import_uses_der_not_file_name(tmp_path):
    """
    A copy of an imported certificate with another file name and PEM line
    wrapping produces the same result: the check compares DER content.
    """

    from asn1crypto import pem as asn1_pem

    source = load_cert_from_pemder(f'{SAMPLE_DIR}/wrong-serial.pem')
    der = source.dump()

    different_name = tmp_path / 'some-other-name.pem'
    different_name.write_bytes(asn1_pem.armor('certificate', der))
    reloaded = load_cert_from_pemder(str(different_name))
    assert reloaded.dump() == der


def test_implicit_serial_adopted_from_der():
    cfg = CertomancerConfig.from_file(
        f'{SAMPLE_DIR}/with-external.yml', SAMPLE_DIR
    )
    arch = cfg.get_pki_arch(ArchLabel('external'))
    ca_spec = arch.get_cert_spec(CertLabel('external-ca'))
    leaf_spec = arch.get_cert_spec(CertLabel('external-leaf'))
    assert (
        ca_spec.serial == arch.get_cert(CertLabel('external-ca')).serial_number
    )
    assert (
        leaf_spec.serial
        == arch.get_cert(CertLabel('external-leaf')).serial_number
    )


def test_own_file_reimport_with_implicit_serial_is_fine():
    """
    Writing a certificate served by Certomancer back out and importing it
    under the same label must pass, even without an explicit serial.
    """

    import os
    import shutil
    import tempfile

    import yaml
    from asn1crypto import pem as asn1_pem

    arch = _load('with-wrong-serial-allowed.yml')
    cert = arch.get_cert(CertLabel('signer'))

    # The certificate file is resolved relative to config_root, so create a
    # scratch config root with the served certificate and the key directory
    # inside it.
    with tempfile.TemporaryDirectory() as scratch_root:
        shutil.copytree(
            'tests/data/keys-ecdsa', os.path.join(scratch_root, 'keys-ecdsa')
        )
        with open(f'{SAMPLE_DIR}/base-import.yml') as inf:
            cfg = yaml.safe_load(inf)
        cfg['keysets']['testing-ca']['path-prefix'] = 'keys-ecdsa'
        certs = cfg['pki-architectures']['testing-ca']['certs']
        certs['signer'].pop('serial', None)
        certs['signer']['certificate-file'] = 'served.pem'
        with open(os.path.join(scratch_root, 'served.pem'), 'wb') as outf:
            outf.write(asn1_pem.armor('certificate', cert.dump()))
        cfg_path = os.path.join(scratch_root, 'cfg.yml')
        with open(cfg_path, 'w') as outf:
            yaml.safe_dump(cfg, outf, sort_keys=False)

        rebuilt = CertomancerConfig.from_file(
            cfg_path, scratch_root
        ).get_pki_arch(ArchLabel('testing-ca'))
    check = rebuilt.get_import_preflight_results()[CertLabel('signer')]
    assert check.ok
    assert rebuilt.get_cert(CertLabel('signer')).dump() == cert.dump()


def test_name_comparison_is_rfc5280_aware():
    """
    Names are compared per RFC 5280: an equivalent PrintableString encoding
    of the same DN is not a mismatch, even though the DER bytes differ.
    """

    from asn1crypto.x509 import (
        DirectoryString,
        NameTypeAndValue,
        RDNSequence,
        RelativeDistinguishedName,
    )

    from certomancer.registry.import_check import _check_names

    utf8 = x509.Name.build(
        {
            'country_name': 'BE',
            'organization_name': 'Testing Authority',
            'common_name': 'CA',
        }
    )
    rdns = []
    for rdn in utf8.chosen:
        new_rdn = RelativeDistinguishedName()
        for tv in rdn:
            new_rdn.append(
                NameTypeAndValue(
                    {
                        'type': tv['type'],
                        'value': DirectoryString(
                            name='printable_string',
                            value=tv['value'].native,
                        ),
                    }
                )
            )
        rdns.append(new_rdn)
    printable = x509.Name.load(RDNSequence(rdns).dump())

    assert printable.dump() != utf8.dump()
    assert _check_names('subject', utf8, printable) is None
