"""
Contract tests for batch OCSP requests against the offline ``Illusionist``
service.

A single OCSP request may contain several ``Request`` entries that differ in
CertID hash algorithm, serial number and issuer. The responder must therefore
not take any decision based on the first entry only: each entry has to be
examined in order, and an error on any single entry fails the whole request at
the response-status level (RFC 6960 response statuses are per *response*, not
per certificate).

These tests deliberately do more than checking for HTTP 200 / ASN.1
decodability:

* successful responses are re-decoded from DER and their signatures are
  verified independently with the public key embedded in the response;
* response-level errors (``malformed_request``, ``internal_error``,
  ``unauthorized``) are distinguished from per-certificate statuses
  (``good`` / ``revoked``), and are asserted to carry no signed payload;
* the relative order of the single responses, the nonce extension, the
  responderId and the exact coverage of the signature are all checked.
"""
import hashlib
from datetime import datetime, timedelta, timezone
from itertools import product

import pytest
import requests
from asn1crypto import algos, core, ocsp, x509
from cryptography import x509 as cx509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    padding,
)
from freezegun import freeze_time

from certomancer.integrations import illusionist
from certomancer.registry import (
    ArchLabel,
    CertLabel,
    CertomancerConfig,
    ServiceLabel,
)

INTERM_URL = "http://test.test/testing-ca/ocsp/interm"
FROZEN_NOW = datetime(2020, 12, 5, tzinfo=timezone.utc)
UNKNOWN_SERIAL = 0xDEADBEEF
NONCE_BYTES = b"batch-ocsp-nonce-0123456789ab"[:16]


def _setup(cfgfile):
    cfg = CertomancerConfig.from_file(cfgfile, 'tests/data')
    arch = cfg.get_pki_arch(ArchLabel('testing-ca'))
    return arch, illusionist.Illusionist(pki_arch=arch)


RSA_ARCH, RSA_ILLUSIONIST = _setup('tests/data/with-services.yml')


@pytest.fixture(
    scope='module',
    params=['rsa', 'dsa', 'ecdsa', 'ed25519', 'ed448'],
)
def signing_setup(request):
    if request.param == 'rsa':
        return RSA_ARCH, RSA_ILLUSIONIST
    return _setup(f'tests/data/with-services-{request.param}.yml')


def _make_cert_id(issuer: x509.Certificate, serial: int, hash_algo: str):
    """Build a CertID, including hashes the responder doesn't support."""
    if hash_algo in ('sha1', 'sha256'):
        name_hash = getattr(issuer.subject, hash_algo)
        key_hash = getattr(issuer.public_key, hash_algo)
    else:
        name_hash = hashlib.new(hash_algo, issuer.subject.dump()).digest()
        # hash the raw subjectPublicKey BIT STRING contents, not the SPKI
        key_hash = hashlib.new(
            hash_algo, issuer.public_key['public_key'].contents
        ).digest()
    return ocsp.CertId(
        {
            'hash_algorithm': algos.DigestAlgorithm(
                {'algorithm': hash_algo}
            ),
            'issuer_name_hash': name_hash,
            'issuer_key_hash': key_hash,
            'serial_number': core.Integer(serial),
        }
    )


def _make_request(cert_ids, *, nonce=None):
    request_list = [
        ocsp.Request({'req_cert': cert_id}) for cert_id in cert_ids
    ]
    tbs_kwargs = {'request_list': request_list}
    if nonce is not None:
        tbs_kwargs['request_extensions'] = [
            ocsp.TBSRequestExtension(
                {'extn_id': 'nonce', 'extn_value': nonce}
            )
        ]
    return ocsp.OCSPRequest(
        {'tbs_request': ocsp.TBSRequest(tbs_kwargs)}
    )


def _post(illusionist_obj, mocker, req: ocsp.OCSPRequest):
    illusionist_obj.register(mocker)
    http_response = requests.post(INTERM_URL, data=req.dump())
    # The transport always answers 200; protocol-level failure is signalled
    # inside the OCSP payload, so make sure nobody mistakes one for the other.
    assert http_response.status_code == 200
    assert (
        http_response.headers['Content-Type'] == 'application/ocsp-response'
    )
    return ocsp.OCSPResponse.load(http_response.content)


def _verify_ocsp_signature(basic_response: ocsp.BasicOCSPResponse):
    """
    Independently verify the OCSP signature with ``cryptography`` against the
    public key of the certificate embedded in the response. Covers RSA
    (PKCS#1 v1.5 and PSS), DSA, ECDSA, Ed25519 and Ed448.
    """
    tbs_bytes = basic_response['tbs_response_data'].dump()
    signature = basic_response['signature'].native
    signer_cert = cx509.load_der_x509_certificate(
        basic_response['certs'][0].dump()
    )
    public_key = signer_cert.public_key()
    sig_algo = basic_response['signature_algorithm']
    sig_algo_name = sig_algo['algorithm'].native

    if isinstance(public_key, ed25519.Ed25519PublicKey):
        assert sig_algo_name == 'ed25519'
        public_key.verify(signature, tbs_bytes)
    elif isinstance(public_key, ed448.Ed448PublicKey):
        assert sig_algo_name == 'ed448'
        public_key.verify(signature, tbs_bytes)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(
            signature, tbs_bytes, ec.ECDSA(hashes.SHA256())
        )
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key.verify(signature, tbs_bytes, hashes.SHA256())
    else:
        if sig_algo_name == 'rsassa_pss':
            params = sig_algo['parameters']
            hash_name = params['hash_algorithm']['algorithm'].native
            pss_hash = getattr(hashes, hash_name.upper())()
            public_key.verify(
                signature,
                tbs_bytes,
                padding.PSS(
                    mgf=padding.MGF1(pss_hash),
                    salt_length=params['salt_length'].native,
                ),
                pss_hash,
            )
        else:
            assert sig_algo_name == 'sha256_rsa'
            public_key.verify(
                signature,
                tbs_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )


def _assert_tampered_signature_fails(basic_response):
    tbs = basic_response['tbs_response_data']
    tampered_tbs = bytearray(tbs.dump())
    tampered_tbs[-1] ^= 0x01
    signer_cert = cx509.load_der_x509_certificate(
        basic_response['certs'][0].dump()
    )
    public_key = signer_cert.public_key()
    signature = basic_response['signature'].native
    with pytest.raises(InvalidSignature):
        if isinstance(
            public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)
        ):
            public_key.verify(signature, bytes(tampered_tbs))
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature, bytes(tampered_tbs), ec.ECDSA(hashes.SHA256())
            )
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(
                signature, bytes(tampered_tbs), hashes.SHA256()
            )
        else:
            public_key.verify(
                signature,
                bytes(tampered_tbs),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )


def _assert_response_level_error(resp: ocsp.OCSPResponse, expected_status):
    """
    A non-successful OCSP response is a bare, self-describing rejection: it
    carries its response status in DER but has no responseBytes to trust.
    """
    # the rejection must survive a DER round-trip on its own, i.e. clients can
    # parse and act on it without any out-of-band context
    reloaded = ocsp.OCSPResponse.load(resp.dump())
    assert reloaded['response_status'].native == expected_status
    assert resp['response_status'].native == expected_status
    assert resp['response_bytes'].native is None
    # the optional responseBytes field is entirely absent (asn1crypto models
    # missing optional components as Void, which cannot be subscripted)
    with pytest.raises(TypeError):
        resp['response_bytes']['response'].parsed


def _interm_cert(arch):
    return arch.get_cert(CertLabel('interm'))


def _root_cert(arch):
    return arch.get_cert(CertLabel('root'))


def _serial(arch, label):
    return arch.get_cert(CertLabel(label)).serial_number


def test_batch_mixed_hash_algorithms_preserves_order_and_status(
    requests_mock,
):
    """
    sha1 and sha256 CertIDs in the same request must both be answered; the
    response entries keep the request order, and each entry carries its own
    certificate status rather than the first entry's.
    """
    arch = RSA_ARCH
    interm = _interm_cert(arch)
    good_serial = _serial(arch, 'signer1')
    revoked_serial = _serial(arch, 'signer2')

    cert_ids = [
        # sha1 first, revoked cert; sha256 second, good cert (different
        # ordering from the natural serial order, on purpose)
        _make_cert_id(interm, revoked_serial, 'sha1'),
        _make_cert_id(interm, good_serial, 'sha256'),
        _make_cert_id(interm, revoked_serial, 'sha256'),
    ]
    req = _make_request(cert_ids, nonce=NONCE_BYTES)

    with freeze_time(FROZEN_NOW):
        resp = _post(RSA_ILLUSIONIST, requests_mock, req)

    assert resp['response_status'].native == 'successful'
    basic = resp['response_bytes']['response'].parsed
    rdata = basic['tbs_response_data']
    single_responses = rdata['responses']

    # one SingleResponse per request entry, in the exact same order
    assert len(single_responses) == len(cert_ids)
    expected = [
        ('sha1', revoked_serial, 'revoked'),
        ('sha256', good_serial, 'good'),
        ('sha256', revoked_serial, 'revoked'),
    ]
    actual = [
        (
            entry['cert_id']['hash_algorithm']['algorithm'].native,
            entry['cert_id']['serial_number'].native,
            entry['cert_status'].name,
        )
        for entry in single_responses
    ]
    assert actual == expected

    # the revoked entry must carry its own revocation details instead of
    # inheriting the 'good' status of the second entry
    revoked_entry = single_responses[0]
    revoked_info = revoked_entry['cert_status'].chosen
    assert revoked_info['revocation_time'].native == datetime(
        2020, 12, 1, tzinfo=timezone.utc
    )
    assert revoked_info['revocation_reason'].native == 'key_compromise'

    # timing fields per entry
    for entry in single_responses:
        assert entry['this_update'].native == FROZEN_NOW
        assert entry['next_update'].native == FROZEN_NOW + timedelta(
            minutes=10
        )

    # nonce is echoed verbatim inside the signed response data
    nonce_ext = next(
        ext
        for ext in rdata['response_extensions']
        if ext['extn_id'].native == 'nonce'
    )
    assert nonce_ext['extn_value'].native == NONCE_BYTES

    # responderId is by-key SHA-1 of the embedded responder cert
    responder_cert = basic['certs'][0]
    assert rdata['responder_id'].name == 'by_key'
    assert (
        rdata['responder_id'].native
        == responder_cert.public_key.sha1
    )
    assert rdata['produced_at'].native == FROZEN_NOW

    # independent signature verification, plus proof it covers tbsResponseData
    _verify_ocsp_signature(basic)
    _assert_tampered_signature_fails(basic)


def test_batch_without_nonce_has_no_nonce_extension(requests_mock):
    arch = RSA_ARCH
    interm = _interm_cert(arch)
    cert_ids = [
        _make_cert_id(interm, _serial(arch, 'signer1'), 'sha256'),
        _make_cert_id(interm, _serial(arch, 'signer2'), 'sha1'),
    ]
    resp = _post(RSA_ILLUSIONIST, requests_mock, _make_request(cert_ids))
    assert resp['response_status'].native == 'successful'
    rdata = resp['response_bytes']['response'].parsed['tbs_response_data']
    # no configured static extensions either: the field must be absent
    assert rdata['response_extensions'].native is None
    assert len(rdata['responses']) == 2


@pytest.mark.parametrize('bad_position', [0, 1])
def test_batch_unknown_serial_fails_whole_request(
    requests_mock, bad_position
):
    """
    An unknown serial makes the responder unable to answer that entry; per the
    current contract this aborts the entire request with 'unauthorized', even
    when the other entry is perfectly valid. Position must not matter.
    """
    arch = RSA_ARCH
    interm = _interm_cert(arch)
    good = _make_cert_id(interm, _serial(arch, 'signer1'), 'sha1')
    unknown = _make_cert_id(interm, UNKNOWN_SERIAL, 'sha256')
    entries = [unknown, good] if bad_position == 0 else [good, unknown]
    resp = _post(
        RSA_ILLUSIONIST,
        requests_mock,
        _make_request(entries, nonce=NONCE_BYTES),
    )
    _assert_response_level_error(resp, 'unauthorized')


@pytest.mark.parametrize('bad_position', [0, 1])
def test_batch_unauthorized_issuer_fails_whole_request(
    requests_mock, bad_position
):
    """
    A CertID naming an issuer this responder doesn't serve (here the root CA)
    yields 'unauthorized' for the whole request, regardless of where the
    offending entry sits.
    """
    arch = RSA_ARCH
    interm = _interm_cert(arch)
    root = _root_cert(arch)
    valid = _make_cert_id(interm, _serial(arch, 'signer1'), 'sha256')
    foreign = _make_cert_id(root, _serial(arch, 'signer1'), 'sha1')
    entries = [foreign, valid] if bad_position == 0 else [valid, foreign]
    resp = _post(
        RSA_ILLUSIONIST, requests_mock, _make_request(entries)
    )
    _assert_response_level_error(resp, 'unauthorized')


@pytest.mark.parametrize('bad_position', [0, 1])
def test_batch_unsupported_hash_algorithm_fails_whole_request(
    requests_mock, bad_position
):
    """
    CertID hash algorithms outside sha1/sha256 are not implemented by the
    responder and surface as the response-level status 'internal_error'
    (not 'unauthorized', and not a per-certificate status).
    """
    arch = RSA_ARCH
    interm = _interm_cert(arch)
    valid = _make_cert_id(interm, _serial(arch, 'signer1'), 'sha1')
    unsupported = _make_cert_id(
        interm, _serial(arch, 'signer2'), 'sha512'
    )
    entries = (
        [unsupported, valid] if bad_position == 0 else [valid, unsupported]
    )
    resp = _post(RSA_ILLUSIONIST, requests_mock, _make_request(entries))
    _assert_response_level_error(resp, 'internal_error')


def test_empty_request_list_is_malformed(requests_mock):
    resp = _post(
        RSA_ILLUSIONIST,
        requests_mock,
        _make_request([]),
    )
    _assert_response_level_error(resp, 'malformed_request')


@pytest.mark.parametrize(
    'hash_algo,status_at,expected',
    [
        ('sha1', datetime(2020, 11, 5, tzinfo=timezone.utc), 'good'),
        ('sha256', datetime(2020, 11, 5, tzinfo=timezone.utc), 'good'),
        ('sha1', FROZEN_NOW, 'revoked'),
        ('sha256', FROZEN_NOW, 'revoked'),
    ],
)
def test_single_entry_batch_equivalent_to_plain_request(
    requests_mock, hash_algo, status_at, expected
):
    """A one-entry batch behaves like the legacy single-cert request."""
    arch = RSA_ARCH
    interm = _interm_cert(arch)
    cert_id = _make_cert_id(
        interm, _serial(arch, 'signer2'), hash_algo
    )
    with freeze_time(status_at):
        resp = _post(
            RSA_ILLUSIONIST,
            requests_mock,
            _make_request([cert_id], nonce=NONCE_BYTES),
        )
    assert resp['response_status'].native == 'successful'
    basic = resp['response_bytes']['response'].parsed
    entry = basic['tbs_response_data']['responses'][0]
    assert entry['cert_status'].name == expected
    _verify_ocsp_signature(basic)


def test_batch_success_signature_verifies_for_all_key_types(
    requests_mock, signing_setup
):
    """
    Run the successful mixed-hash batch against every supported responder key
    type; the independently verified signature must hold in each case.
    """
    arch, illusionist_obj = signing_setup
    interm = _interm_cert(arch)
    cert_ids = [
        _make_cert_id(interm, _serial(arch, 'signer2'), 'sha1'),
        _make_cert_id(interm, _serial(arch, 'signer1'), 'sha256'),
    ]
    with freeze_time(
        datetime(2020, 11, 5, tzinfo=timezone.utc)
    ):
        resp = _post(
            illusionist_obj,
            requests_mock,
            _make_request(cert_ids, nonce=NONCE_BYTES),
        )
    assert resp['response_status'].native == 'successful'
    basic = resp['response_bytes']['response'].parsed
    rdata = basic['tbs_response_data']
    assert [
        entry['cert_status'].name for entry in rdata['responses']
    ] == ['good', 'good']
    # both entries present, ordered, and their CertIDs echoed byte-for-byte
    assert [
        entry['cert_id'].dump() for entry in rdata['responses']
    ] == [cert_id.dump() for cert_id in cert_ids]
    _verify_ocsp_signature(basic)
    _assert_tampered_signature_fails(basic)


def test_batch_error_independent_of_order_across_all_failure_modes(
    requests_mock,
):
    """
    Exhaustive ordering check: for every combination of failure mode and
    position, a batch containing one good entry and one failing entry never
    gets answered from the good entry alone.
    """
    arch = RSA_ARCH
    interm = _interm_cert(arch)
    root = _root_cert(arch)
    good = _make_cert_id(interm, _serial(arch, 'signer1'), 'sha1')
    failures = {
        'unauthorized-unknown-serial': (
            _make_cert_id(interm, UNKNOWN_SERIAL, 'sha1'),
            'unauthorized',
        ),
        'unauthorized-foreign-issuer': (
            _make_cert_id(root, _serial(arch, 'signer1'), 'sha256'),
            'unauthorized',
        ),
        'internal-error-bad-hash': (
            _make_cert_id(interm, _serial(arch, 'signer1'), 'sha512'),
            'internal_error',
        ),
    }
    for (_label, (bad_entry, expected_status)), bad_first in product(
        failures.items(), (True, False)
    ):
        entries = [bad_entry, good] if bad_first else [good, bad_entry]
        resp = _post(
            RSA_ILLUSIONIST, requests_mock, _make_request(entries)
        )
        _assert_response_level_error(resp, expected_status)
