"""
End-to-end tests for the offline SCEP responder plugin.

The client code under ``tests/scep/scep_client.py`` builds requests and
unwraps responses independently of the responder implementation. These
tests therefore exercise real cryptographic verification rather than
inspecting a few status fields.
"""

import secrets

import pytest
import requests
from asn1crypto import algos, cms, core
from cryptography.hazmat.primitives.asymmetric import rsa as cryptography_rsa

from certomancer.registry.plugin_api import PluginServiceRequestError
from scep_plugin.asn1 import (
    OID_MESSAGE_TYPE,
    OID_TRANSACTION_ID,
    register_scep_oids,
)
from scep_plugin.cms_utils import (
    ScepProtocolError,
    UnsupportedScepAlgorithm,
    verify_signed_data,
)

from . import scep_client

register_scep_oids()

# pkiStatus integer values (RFC 8894 section 3.2.1.2)
STATUS_SUCCESS = 0
STATUS_PENDING = 2
STATUS_FAILURE = 3

IMMEDIATE_URL = 'http://test.test/testing-ca/plugin/scep-responder/immediate'
PENDING_URL = 'http://test.test/testing-ca/plugin/scep-responder/pending'


def _new_nonce() -> bytes:
    return secrets.token_bytes(16)


def _target_issuer_subject(materials):
    target = materials['target_cert']
    return target.issuer, target.subject


# --------------------------------------------------------------------------- #
# happy path: immediate enrollment
# --------------------------------------------------------------------------- #


def test_immediate_enrollment_success(setup, materials):
    target_key = materials['target_key']
    target_cert = materials['target_cert']

    csr_der = scep_client.build_csr(target_key, target_cert.subject)
    transaction_id = 'immediate-tx-001'
    sender_nonce = _new_nonce()
    request_der = scep_client.build_pkcs_req(
        csr_der,
        transaction_id=transaction_id,
        sender_nonce=sender_nonce,
        signer_cert=materials['target_cert'],
        signer_key=target_key,
        recipient_cert=materials['ra_cert'],
    )

    response = requests.post(IMMEDIATE_URL, data=request_der)
    assert response.status_code == 200

    parsed = scep_client.parse_scep_response(
        response.content,
        recipient_key=target_key,
        trusted_ra=materials['ra_cert'],
    )
    # SCEP bookkeeping attributes
    assert parsed.message_type == scep_client.MT_CERT_REP
    assert parsed.pki_status == STATUS_SUCCESS
    assert parsed.fail_info is None
    assert parsed.transaction_id == transaction_id
    # the RA must echo our senderNonce back as recipientNonce
    assert parsed.recipient_nonce == sender_nonce
    assert parsed.sender_nonce is not None and len(parsed.sender_nonce) == 16

    issued = scep_client.extract_issued_cert(parsed.inner_plaintext)
    assert issued.dump() == target_cert.dump()


# --------------------------------------------------------------------------- #
# happy path: PENDING then SUCCESS after a poll
# --------------------------------------------------------------------------- #


def test_pending_then_poll_success(setup, materials):
    target_key = materials['target_key']
    target_cert = materials['target_cert']
    issuer, subject = _target_issuer_subject(materials)

    # --- step 1: PKCSReq is answered with PENDING ---
    csr_der = scep_client.build_csr(target_key, target_cert.subject)
    transaction_id = 'pending-tx-001'
    nonce1 = _new_nonce()
    request_der = scep_client.build_pkcs_req(
        csr_der,
        transaction_id=transaction_id,
        sender_nonce=nonce1,
        signer_cert=target_cert,
        signer_key=target_key,
        recipient_cert=materials['ra_cert'],
    )
    pending_response = requests.post(PENDING_URL, data=request_der)
    assert pending_response.status_code == 200

    pending = scep_client.parse_scep_response(
        pending_response.content,
        recipient_key=target_key,
        trusted_ra=materials['ra_cert'],
    )
    assert pending.pki_status == STATUS_PENDING
    assert pending.transaction_id == transaction_id
    assert pending.recipient_nonce == nonce1
    # no certificate yet
    assert pending.inner_plaintext == b''

    # --- step 2: CertPoll returns the configured certificate ---
    nonce2 = _new_nonce()
    poll_der = scep_client.build_cert_poll(
        issuer=issuer,
        subject=subject,
        transaction_id=transaction_id,
        sender_nonce=nonce2,
        signer_cert=target_cert,
        signer_key=target_key,
        recipient_cert=materials['ra_cert'],
    )
    poll_response = requests.post(PENDING_URL, data=poll_der)
    assert poll_response.status_code == 200

    completed = scep_client.parse_scep_response(
        poll_response.content,
        recipient_key=target_key,
        trusted_ra=materials['ra_cert'],
    )
    assert completed.pki_status == STATUS_SUCCESS
    assert completed.recipient_nonce == nonce2
    issued = scep_client.extract_issued_cert(completed.inner_plaintext)
    assert issued.dump() == target_cert.dump()


# --------------------------------------------------------------------------- #
# rejection: CSR public key does not match the configured target cert
# --------------------------------------------------------------------------- #


def test_wrong_csr_public_key_rejected(setup, materials):
    # generate a fresh, unrelated RSA key for the CSR
    foreign_key = cryptography_rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    from asn1crypto import keys as asn1_keys

    foreign_private_info = asn1_keys.PrivateKeyInfo.load(
        foreign_key.private_bytes(
            encoding=__import__(
                'cryptography'
            ).hazmat.primitives.serialization.Encoding.DER,
            format=__import__(
                'cryptography'
            ).hazmat.primitives.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=__import__(
                'cryptography'
            ).hazmat.primitives.serialization.NoEncryption(),
        )
    )

    # the outer SCEP message is still signed correctly by the enrolled
    # client; only the CSR key is swapped
    csr_der = scep_client.build_csr(
        foreign_private_info, materials['target_cert'].subject
    )
    request_der = scep_client.build_pkcs_req(
        csr_der,
        transaction_id='wrong-key-tx',
        sender_nonce=_new_nonce(),
        signer_cert=materials['target_cert'],
        signer_key=materials['target_key'],
        recipient_cert=materials['ra_cert'],
    )
    response = requests.post(IMMEDIATE_URL, data=request_der)
    parsed = scep_client.parse_scep_response(
        response.content,
        recipient_key=materials['target_key'],
        trusted_ra=materials['ra_cert'],
    )
    assert parsed.pki_status == STATUS_FAILURE
    # badCertId (4): the CSR key does not identify the target certificate
    assert parsed.fail_info == 4
    # a failure must not carry a certificate payload
    with pytest.raises(Exception):
        scep_client.extract_issued_cert(parsed.inner_plaintext)


# --------------------------------------------------------------------------- #
# rejection: transaction isolation between two enrollments
# --------------------------------------------------------------------------- #


def test_unknown_transaction_poll_does_not_leak_cert(setup, materials):
    target_cert = materials['target_cert']
    issuer, subject = _target_issuer_subject(materials)

    # a valid PKCSReq opens transaction A
    csr_der = scep_client.build_csr(
        materials['target_key'], target_cert.subject
    )
    requests.post(
        PENDING_URL,
        data=scep_client.build_pkcs_req(
            csr_der,
            transaction_id='transaction-A',
            sender_nonce=_new_nonce(),
            signer_cert=target_cert,
            signer_key=materials['target_key'],
            recipient_cert=materials['ra_cert'],
        ),
    )

    # polling a different, unknown transaction B must fail without a cert
    poll_b = scep_client.build_cert_poll(
        issuer=issuer,
        subject=subject,
        transaction_id='transaction-B',
        sender_nonce=_new_nonce(),
        signer_cert=target_cert,
        signer_key=materials['target_key'],
        recipient_cert=materials['ra_cert'],
    )
    response = requests.post(PENDING_URL, data=poll_b)
    parsed = scep_client.parse_scep_response(
        response.content,
        recipient_key=materials['target_key'],
        trusted_ra=materials['ra_cert'],
    )
    assert parsed.pki_status == STATUS_FAILURE
    assert parsed.fail_info == 2  # badRequest
    with pytest.raises(Exception):
        scep_client.extract_issued_cert(parsed.inner_plaintext)

    # ... and transaction A can still complete and get exactly its own cert
    poll_a = scep_client.build_cert_poll(
        issuer=issuer,
        subject=subject,
        transaction_id='transaction-A',
        sender_nonce=_new_nonce(),
        signer_cert=target_cert,
        signer_key=materials['target_key'],
        recipient_cert=materials['ra_cert'],
    )
    ok = scep_client.parse_scep_response(
        requests.post(PENDING_URL, data=poll_a).content,
        recipient_key=materials['target_key'],
        trusted_ra=materials['ra_cert'],
    )
    assert ok.pki_status == STATUS_SUCCESS
    assert (
        scep_client.extract_issued_cert(ok.inner_plaintext).dump()
        == target_cert.dump()
    )


def test_poll_from_different_signer_rejected(setup, materials):
    target_cert = materials['target_cert']
    issuer, subject = _target_issuer_subject(materials)

    csr_der = scep_client.build_csr(
        materials['target_key'], target_cert.subject
    )
    requests.post(
        PENDING_URL,
        data=scep_client.build_pkcs_req(
            csr_der,
            transaction_id='signer-binding-tx',
            sender_nonce=_new_nonce(),
            signer_cert=target_cert,
            signer_key=materials['target_key'],
            recipient_cert=materials['ra_cert'],
        ),
    )

    # another client (other-client) tries to harvest the pending certificate
    poll_der = scep_client.build_cert_poll(
        issuer=issuer,
        subject=subject,
        transaction_id='signer-binding-tx',
        sender_nonce=_new_nonce(),
        signer_cert=materials['other_cert'],
        signer_key=materials['other_key'],
        recipient_cert=materials['ra_cert'],
    )
    response = requests.post(PENDING_URL, data=poll_der)
    parsed = scep_client.parse_scep_response(
        response.content,
        recipient_key=materials['other_key'],
        trusted_ra=materials['ra_cert'],
    )
    assert parsed.pki_status == STATUS_FAILURE
    with pytest.raises(Exception):
        scep_client.extract_issued_cert(parsed.inner_plaintext)


# --------------------------------------------------------------------------- #
# rejection: tampered outer signature
# --------------------------------------------------------------------------- #


def test_tampered_signature_rejected(setup, materials):
    target_cert = materials['target_cert']
    csr_der = scep_client.build_csr(
        materials['target_key'], target_cert.subject
    )
    request_der = scep_client.build_pkcs_req(
        csr_der,
        transaction_id='tampered-sig-tx',
        sender_nonce=_new_nonce(),
        signer_cert=target_cert,
        signer_key=materials['target_key'],
        recipient_cert=materials['ra_cert'],
    )

    outer = cms.ContentInfo.load(request_der)
    signer_info = outer['content']['signer_infos'][0]
    original_sig = bytearray(signer_info['signature'].native)
    # flip a bit in the signature value
    original_sig[0] ^= 0x01
    signer_info['signature'] = core.OctetString(bytes(original_sig))
    tampered = outer.dump()

    with pytest.raises(ScepProtocolError):
        verify_signed_data(cms.ContentInfo.load(tampered))

    # unauthenticated messages are rejected outright; the WSGI animator maps
    # PluginServiceRequestError to HTTP 400, while the illusionist test
    # transport surfaces the exception itself
    with pytest.raises(PluginServiceRequestError):
        requests.post(IMMEDIATE_URL, data=tampered)


# --------------------------------------------------------------------------- #
# rejection: unknown / unsupported algorithms
# --------------------------------------------------------------------------- #


def test_unknown_digest_algorithm_rejected(setup, materials):
    target_cert = materials['target_cert']
    csr_der = scep_client.build_csr(
        materials['target_key'], target_cert.subject
    )
    request_der = scep_client.build_pkcs_req(
        csr_der,
        transaction_id='bad-algo-tx',
        sender_nonce=_new_nonce(),
        signer_cert=target_cert,
        signer_key=materials['target_key'],
        recipient_cert=materials['ra_cert'],
        digest_algo='sha1',
    )
    with pytest.raises(UnsupportedScepAlgorithm):
        verify_signed_data(cms.ContentInfo.load(request_der))

    # the disallowed digest is rejected while authenticating the outer
    # SignedData, before any SCEP state is touched; the real animator maps
    # this PluginServiceRequestError to HTTP 400
    with pytest.raises(PluginServiceRequestError):
        requests.post(IMMEDIATE_URL, data=request_der)


def test_unsupported_content_encryption_rejected(setup, materials):
    target_cert = materials['target_cert']
    csr_der = scep_client.build_csr(
        materials['target_key'], target_cert.subject
    )
    # the envelope is otherwise valid, but advertises an unrecognised
    # content-encryption algorithm OID instead of AES-CBC
    request_der = scep_client.build_pkcs_req(
        csr_der,
        transaction_id='bad-encalg-tx',
        sender_nonce=_new_nonce(),
        signer_cert=target_cert,
        signer_key=materials['target_key'],
        recipient_cert=materials['ra_cert'],
        algorithm_oid_override='1.2.3.4.5.6.7.8.9',
    )
    response = requests.post(IMMEDIATE_URL, data=request_der)
    parsed = scep_client.parse_scep_response(
        response.content,
        recipient_key=materials['target_key'],
        trusted_ra=materials['ra_cert'],
    )
    assert parsed.pki_status == STATUS_FAILURE
    assert parsed.fail_info == 0  # badAlg


# --------------------------------------------------------------------------- #
# rejection: message type / attribute sanity
# --------------------------------------------------------------------------- #


def test_unknown_message_type_rejected(setup, materials):
    target_cert = materials['target_cert']
    csr_der = scep_client.build_csr(
        materials['target_key'], target_cert.subject
    )
    # hand-build a request whose SCEP messageType attribute is 99
    request_der = scep_client.build_pkcs_req(
        csr_der,
        transaction_id='bad-mt-tx',
        sender_nonce=_new_nonce(),
        signer_cert=target_cert,
        signer_key=materials['target_key'],
        recipient_cert=materials['ra_cert'],
    )
    outer = cms.ContentInfo.load(request_der)
    signed_attrs = outer['content']['signer_infos'][0]['signed_attrs']
    for attr in signed_attrs:
        if attr['type'].dotted == OID_MESSAGE_TYPE:
            attr['values'] = type(attr['values'])([99])
    # re-sign because authenticated attributes changed
    request_der = _resign(outer, materials['target_key'])

    response = requests.post(IMMEDIATE_URL, data=request_der)
    parsed = scep_client.parse_scep_response(
        response.content,
        recipient_key=materials['target_key'],
        trusted_ra=materials['ra_cert'],
    )
    assert parsed.pki_status == STATUS_FAILURE
    assert parsed.fail_info == 2  # badRequest


def test_missing_transaction_id_rejected(setup, materials):
    target_cert = materials['target_cert']
    csr_der = scep_client.build_csr(
        materials['target_key'], target_cert.subject
    )
    request_der = scep_client.build_pkcs_req(
        csr_der,
        transaction_id='dropped-tx',
        sender_nonce=_new_nonce(),
        signer_cert=target_cert,
        signer_key=materials['target_key'],
        recipient_cert=materials['ra_cert'],
    )
    outer = cms.ContentInfo.load(request_der)
    signed_attrs = outer['content']['signer_infos'][0]['signed_attrs']
    kept = cms.CMSAttributes(
        [a for a in signed_attrs if a['type'].dotted != OID_TRANSACTION_ID]
    )
    outer['content']['signer_infos'][0]['signed_attrs'] = kept
    request_der = _resign(outer, materials['target_key'])

    with pytest.raises(PluginServiceRequestError):
        requests.post(IMMEDIATE_URL, data=request_der)


def test_garbage_body_is_bad_request(setup):
    with pytest.raises(PluginServiceRequestError):
        requests.post(IMMEDIATE_URL, data=b'this is not cms at all')


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _resign(outer: cms.ContentInfo, signer_key) -> bytes:
    """Re-sign an outer SignedData after its authenticated attrs changed."""
    from scep_plugin.cms_utils import authenticated_attributes_bytes

    signed_data = outer['content']
    signer_info = signed_data['signer_infos'][0]
    signed_attrs = signer_info['signed_attrs']
    signature_algo = algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})
    from certomancer.crypto_utils import generic_sign

    signer_info['signature'] = core.OctetString(
        generic_sign(
            signer_key,
            authenticated_attributes_bytes(signed_attrs),
            signature_algo,
        )
    )
    return outer.dump()


def test_rfc8894_message_type_mapping():
    from scep_plugin.asn1 import MessageType

    # RFC 8894 section 3.2.1.1
    assert MessageType._map[3] == 'cert_rep'
    assert MessageType._map[19] == 'pkcs_req'
    assert MessageType._map[20] == 'cert_poll'
    assert MessageType._map[21] == 'get_cert'
    assert MessageType._map[22] == 'get_crl'
