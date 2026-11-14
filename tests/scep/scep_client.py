"""
A deliberately independent, minimal SCEP (RFC 8894) client used only by the
test suite.

It is written against ``asn1crypto`` + ``cryptography`` directly and never
imports the responder's envelope code, so a passing test proves that the
plugin's output is a genuinely interoperable SCEP message rather than a
round trip through the same helper functions.

The client:

* builds PKCS#10 CSRs and wraps them into double-wrapped PKCSReq messages,
* builds IssuerAndSubject-based CertPoll messages,
* verifies the outer SignedData against the trusted RA certificate,
* decrypts the inner EnvelopedData with the client's own private key,
* parses every SCEP authenticated attribute (message type, pkiStatus,
  failInfo, transactionID, sender/recipient nonce),
* extracts the issued certificate from a successful certs-only payload.
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import List, Optional

from asn1crypto import algos, cms, core, csr, x509
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from scep_plugin.asn1 import (
    OID_FAIL_INFO,
    OID_MESSAGE_TYPE,
    OID_PKI_STATUS,
    OID_RECIPIENT_NONCE,
    OID_SENDER_NONCE,
    OID_TRANSACTION_ID,
    FailInfo,
    IssuerAndSubject,
    MessageType,
    PKIStatus,
    register_scep_oids,
)

register_scep_oids()

MT_CERT_REP = 3
MT_PKCS_REQ = 19
MT_CERT_POLL = 20


def _authenticated_attributes_bytes(signed_attrs: cms.CMSAttributes) -> bytes:
    # RFC 5652 section 5.4: sign over the universal SET encoding, while the
    # wire format uses [0] IMPLICIT SET. A freshly constructed CMSAttributes
    # already carries the universal SET tag; embedded copies use 0xA0.
    encoded = signed_attrs.dump()
    if encoded[0] == 0x31:
        return encoded
    assert encoded[0] == 0xA0
    return bytes([0x31]) + encoded[1:]


# --------------------------------------------------------------------------- #
# low-level CMS construction (client side)
# --------------------------------------------------------------------------- #


def _attribute(oid: str, value) -> cms.CMSAttribute:
    return cms.CMSAttribute(
        {'type': cms.CMSAttributeType(oid), 'values': [value]}
    )


def _aes_encrypt(data: bytes, key: bytes):
    iv = secrets.token_bytes(16)
    padder = PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, encryptor.update(padded) + encryptor.finalize()


def _envelope(
    payload: bytes,
    recipient_cert: x509.Certificate,
    content_encryption: str = 'aes256_cbc',
    algorithm_oid_override: Optional[str] = None,
) -> cms.ContentInfo:
    key_sizes = {'aes128_cbc': 16, 'aes192_cbc': 24, 'aes256_cbc': 32}
    content_key = secrets.token_bytes(key_sizes[content_encryption])
    iv, encrypted_content = _aes_encrypt(payload, content_key)

    public_key = serialization.load_der_public_key(
        recipient_cert.public_key.dump()
    )
    encrypted_key = public_key.encrypt(content_key, padding.PKCS1v15())

    recipient_info = cms.RecipientInfo(
        {
            'ktri': cms.KeyTransRecipientInfo(
                {
                    'version': 0,
                    'rid': cms.RecipientIdentifier(
                        {
                            'issuer_and_serial_number': cms.IssuerAndSerialNumber(
                                {
                                    'issuer': recipient_cert.issuer,
                                    'serial_number': recipient_cert.serial_number,
                                }
                            )
                        }
                    ),
                    'key_encryption_algorithm': cms.KeyEncryptionAlgorithm(
                        {'algorithm': 'rsaes_pkcs1v15'}
                    ),
                    'encrypted_key': encrypted_key,
                }
            )
        }
    )
    declared_algorithm = algorithm_oid_override or content_encryption
    return cms.ContentInfo(
        {
            'content_type': 'enveloped_data',
            'content': cms.EnvelopedData(
                {
                    'version': 0,
                    'recipient_infos': [recipient_info],
                    'encrypted_content_info': cms.EncryptedContentInfo(
                        {
                            'content_type': 'data',
                            'content_encryption_algorithm': algos.EncryptionAlgorithm(
                                {
                                    'algorithm': declared_algorithm,
                                    'parameters': core.OctetString(iv),
                                }
                            ),
                            'encrypted_content': encrypted_content,
                        }
                    ),
                }
            ),
        }
    )


def _sign(
    content: bytes,
    signer_cert: x509.Certificate,
    signer_key,
    attributes: List[cms.CMSAttribute],
    digest_algo: str = 'sha256',
) -> cms.ContentInfo:
    attrs = list(attributes)
    attrs.append(_attribute('content_type', cms.ContentType('data')))
    attrs.append(
        _attribute(
            'message_digest',
            core.OctetString(hashlib.new(digest_algo, content).digest()),
        )
    )
    signed_attrs = cms.CMSAttributes(attrs)

    from certomancer.crypto_utils import generic_sign

    signature_algo = algos.SignedDigestAlgorithm(
        {'algorithm': f'{digest_algo}_rsa'}
    )
    signature = generic_sign(
        signer_key,
        _authenticated_attributes_bytes(signed_attrs),
        signature_algo,
    )
    signer_info = cms.SignerInfo(
        {
            'version': 'v1',
            'sid': cms.SignerIdentifier(
                {
                    'issuer_and_serial_number': cms.IssuerAndSerialNumber(
                        {
                            'issuer': signer_cert.issuer,
                            'serial_number': signer_cert.serial_number,
                        }
                    )
                }
            ),
            'digest_algorithm': algos.DigestAlgorithm(
                {'algorithm': digest_algo}
            ),
            'signed_attrs': signed_attrs,
            'signature_algorithm': signature_algo,
            'signature': signature,
        }
    )
    return cms.ContentInfo(
        {
            'content_type': 'signed_data',
            'content': cms.SignedData(
                {
                    'version': 'v3',
                    'digest_algorithms': cms.DigestAlgorithms(
                        (algos.DigestAlgorithm({'algorithm': digest_algo}),)
                    ),
                    'encap_content_info': cms.EncapsulatedContentInfo(
                        {
                            'content_type': 'data',
                            'content': cms.ParsableOctetString(content),
                        }
                    ),
                    'certificates': [signer_cert],
                    'signer_infos': [signer_info],
                }
            ),
        }
    )


# --------------------------------------------------------------------------- #
# CSR and SCEP message construction
# --------------------------------------------------------------------------- #


def build_csr(private_key, subject_name: x509.Name) -> bytes:
    """Build and self-sign a PKCS#10 CSR, returning DER bytes."""
    public_key_info = keys_public_info(private_key)
    # an empty, context-tagged attributes SET (a000) is still required by
    # strict DER parsers such as the cryptography library
    empty_attributes = csr.CRIAttributes()
    empty_attributes.contents = b''
    csr_info = csr.CertificationRequestInfo(
        {
            'version': 0,
            'subject': subject_name,
            'subject_pk_info': public_key_info,
            'attributes': empty_attributes,
        }
    )
    signature_algo = algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})
    from certomancer.crypto_utils import generic_sign

    signature = generic_sign(private_key, csr_info.dump(), signature_algo)
    request = csr.CertificationRequest(
        {
            'certification_request_info': csr_info,
            'signature_algorithm': signature_algo,
            'signature': signature,
        }
    )
    # sanity: the produced CSR must verify on its own
    cx509.load_der_x509_csr(request.dump())
    return request.dump()


def keys_public_info(private_key):
    public_key = serialization.load_der_private_key(
        private_key.dump(), password=None
    ).public_key()
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return x509.PublicKeyInfo.load(der)


def _scep_attributes(
    message_type: int,
    transaction_id: str,
    sender_nonce: bytes,
) -> List[cms.CMSAttribute]:
    return [
        _attribute(OID_MESSAGE_TYPE, int(message_type)),
        _attribute(OID_TRANSACTION_ID, str(transaction_id)),
        _attribute(OID_SENDER_NONCE, bytes(sender_nonce)),
    ]


def build_pkcs_req(
    csr_der: bytes,
    *,
    transaction_id: str,
    sender_nonce: bytes,
    signer_cert: x509.Certificate,
    signer_key,
    recipient_cert: x509.Certificate,
    digest_algo: str = 'sha256',
    content_encryption: str = 'aes256_cbc',
    algorithm_oid_override: Optional[str] = None,
) -> bytes:
    envelope = _envelope(
        csr_der,
        recipient_cert,
        content_encryption,
        algorithm_oid_override=algorithm_oid_override,
    )
    attrs = _scep_attributes(MT_PKCS_REQ, transaction_id, sender_nonce)
    return _sign(
        envelope.dump(), signer_cert, signer_key, attrs, digest_algo
    ).dump()


def build_cert_poll(
    *,
    issuer: x509.Name,
    subject: x509.Name,
    transaction_id: str,
    sender_nonce: bytes,
    signer_cert: x509.Certificate,
    signer_key,
    recipient_cert: x509.Certificate,
    digest_algo: str = 'sha256',
) -> bytes:
    payload = IssuerAndSubject({'issuer': issuer, 'subject': subject}).dump()
    envelope = _envelope(payload, recipient_cert)
    attrs = _scep_attributes(MT_CERT_POLL, transaction_id, sender_nonce)
    return _sign(
        envelope.dump(), signer_cert, signer_key, attrs, digest_algo
    ).dump()


# --------------------------------------------------------------------------- #
# response unwrapping and verification (client side)
# --------------------------------------------------------------------------- #


@dataclass
class ScepResponse:
    message_type: int
    pki_status: int
    fail_info: Optional[int]
    transaction_id: str
    sender_nonce: Optional[bytes]
    recipient_nonce: Optional[bytes]
    inner_plaintext: bytes
    signer_cert: x509.Certificate


def _find_attr(attrs: cms.CMSAttributes, oid: str):
    for attr in attrs:
        if attr['type'].dotted == oid or attr['type'].native == oid:
            return attr['values'][0]
    return None


def _verify_outer_signed_data(
    outer: cms.ContentInfo, trusted_ra: x509.Certificate
) -> tuple:
    assert outer['content_type'].native == 'signed_data'
    signed_data = outer['content']
    signer_info = signed_data['signer_infos'][0]

    certificates = [
        c.chosen for c in signed_data['certificates'] if c.name == 'certificate'
    ]
    sid = signer_info['sid'].chosen
    signer_cert = next(
        c
        for c in certificates
        if c.issuer == sid['issuer']
        and c.serial_number == sid['serial_number'].native
    )
    # authenticate the signer against the trust anchor, not just any cert
    assert signer_cert.issuer == trusted_ra.issuer
    assert signer_cert.serial_number == trusted_ra.serial_number

    econtent = signed_data['encap_content_info']['content'].native
    signed_attrs = signer_info['signed_attrs']

    digest_name = signer_info['digest_algorithm']['algorithm'].native
    md_attr = next(
        a for a in signed_attrs if a['type'].native == 'message_digest'
    )
    assert (
        md_attr['values'][0].native
        == hashlib.new(digest_name, econtent).digest()
    )

    public_key = serialization.load_der_public_key(
        signer_cert.public_key.dump()
    )
    hash_name = signer_info['signature_algorithm'].hash_algo
    public_key.verify(
        signer_info['signature'].native,
        _authenticated_attributes_bytes(signed_attrs),
        padding.PKCS1v15(),
        getattr(hashes, hash_name.upper())(),
    )
    return econtent, signed_attrs, signer_cert


def _decrypt_envelope(envelope: cms.ContentInfo, private_key) -> bytes:
    assert envelope['content_type'].native == 'enveloped_data'
    ed = envelope['content']
    eci = ed['encrypted_content_info']
    cea = eci['content_encryption_algorithm']
    iv = cea['parameters'].native

    key_obj = serialization.load_der_private_key(
        private_key.dump(), password=None
    )
    content_key = None
    for ri in ed['recipient_infos']:
        ktri = ri.chosen
        try:
            content_key = key_obj.decrypt(
                ktri['encrypted_key'].native, padding.PKCS1v15()
            )
            break
        except ValueError:
            continue
    assert content_key is not None, "no matching RecipientInfo"

    decryptor = Cipher(algorithms.AES(content_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(eci['encrypted_content'].native)
    padded += decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def parse_scep_response(
    response_der: bytes,
    *,
    recipient_key,
    trusted_ra: x509.Certificate,
) -> ScepResponse:
    """Fully verify and decrypt a SCEP CertRep message."""
    outer = cms.ContentInfo.load(response_der)
    econtent, signed_attrs, signer_cert = _verify_outer_signed_data(
        outer, trusted_ra
    )
    inner_plaintext = _decrypt_envelope(
        cms.ContentInfo.load(econtent), recipient_key
    )

    message_type = _find_attr(signed_attrs, OID_MESSAGE_TYPE).native
    if isinstance(message_type, str):
        message_type = MessageType._reverse_map[message_type]
    assert int(message_type) == MT_CERT_REP

    def _raw(oid, enum_cls):
        attr = _find_attr(signed_attrs, oid)
        if attr is None:
            return None
        value = attr.native
        if isinstance(value, str):
            value = enum_cls._reverse_map[value]
        return int(value)

    pki_status = _raw(OID_PKI_STATUS, PKIStatus)
    fail_info = _raw(OID_FAIL_INFO, FailInfo)
    transaction_id = _find_attr(signed_attrs, OID_TRANSACTION_ID).native
    sender_nonce_attr = _find_attr(signed_attrs, OID_SENDER_NONCE)
    recipient_nonce_attr = _find_attr(signed_attrs, OID_RECIPIENT_NONCE)

    return ScepResponse(
        message_type=message_type,
        pki_status=pki_status,
        fail_info=fail_info,
        transaction_id=transaction_id,
        sender_nonce=sender_nonce_attr.native
        if sender_nonce_attr is not None
        else None,
        recipient_nonce=recipient_nonce_attr.native
        if recipient_nonce_attr is not None
        else None,
        inner_plaintext=inner_plaintext,
        signer_cert=signer_cert,
    )


def extract_issued_cert(inner_plaintext: bytes) -> x509.Certificate:
    """Pull the certificate out of a successful certs-only payload."""
    certs_only = cms.ContentInfo.load(inner_plaintext)
    assert certs_only['content_type'].native == 'signed_data'
    sd = certs_only['content']
    assert len(sd['signer_infos']) == 0
    certificates = [
        c.chosen for c in sd['certificates'] if c.name == 'certificate'
    ]
    assert len(certificates) == 1
    return certificates[0]
