"""
CMS (RFC 5652) primitives used by the offline SCEP test responder.

These helpers deliberately rely only on ``asn1crypto`` (for DER parsing and
encoding) and ``cryptography`` (for the actual cryptographic operations), so
that both the service plugin and the independently written test client can
share one well-defined envelope format without pulling in a heavyweight SCEP
stack.

Only the algorithm families that the SCEP test service is configured to
support are implemented:

* digest / signature: SHA-2 family with RSA PKCS#1 v1.5 (RSASSA-PSS and
  ECDSA are accepted on verification as well),
* content encryption: AES-CBC (128/192/256),
* key transport: RSAES-PKCS1-v1_5.

Anything else raises :class:`UnsupportedScepAlgorithm`, which the responder
translates into an explicit SCEP ``badAlg`` rejection.
"""

import hashlib
import secrets
from typing import Iterable, List, Optional, Tuple

from asn1crypto import algos, cms, core, x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from .asn1 import (
    OID_FAIL_INFO,
    OID_MESSAGE_TYPE,
    OID_PKI_STATUS,
    OID_RECIPIENT_NONCE,
    OID_SENDER_NONCE,
    OID_TRANSACTION_ID,
)


class ScepProtocolError(Exception):
    """Raised when a SCEP message cannot be parsed or authenticated."""


class UnsupportedScepAlgorithm(ScepProtocolError):
    """Raised when a message names an algorithm the test service does not do."""


SUPPORTED_DIGEST_ALGOS = {'sha256', 'sha384', 'sha512'}
SUPPORTED_CONTENT_ENCRYPTION = {
    'aes128_cbc': 16,
    'aes192_cbc': 24,
    'aes256_cbc': 32,
}
KEY_TRANSPORT_ALGO = 'rsaes_pkcs1v15'


# --------------------------------------------------------------------------- #
# Attribute helpers
# --------------------------------------------------------------------------- #


def _attr(oid: str, value) -> cms.CMSAttribute:
    return cms.CMSAttribute(
        {'type': cms.CMSAttributeType(oid), 'values': [value]}
    )


def find_attribute(attrs: cms.CMSAttributes, oid: str):
    for attr in attrs or ():
        if attr['type'].native == oid or attr['type'].dotted == oid:
            values = attr['values']
            if len(values) != 1:
                raise ScepProtocolError(
                    f"SCEP attribute {oid} must have exactly one value"
                )
            return values[0]
    return None


def require_attribute(attrs: cms.CMSAttributes, oid: str):
    value = find_attribute(attrs, oid)
    if value is None:
        raise ScepProtocolError(f"Missing mandatory SCEP attribute {oid}")
    return value


# DER tag bytes
_SET_TAG = 0x31
_IMPLICIT_SET0_TAG = 0xA0


def authenticated_attributes_bytes(
    signed_attrs: cms.CMSAttributes,
) -> bytes:
    """
    Return the DER bytes over which a SignerInfo signature is computed.

    On the wire authenticatedAttributes are ``[0] IMPLICIT SET OF
    CMSAttribute`` (tag 0xA0), but RFC 5652 section 5.4 requires the
    signature to be calculated over the value encoded as a normal universal
    SET (tag 0x31) instead. A freshly constructed CMSAttributes can already
    carry the universal SET tag, so both encodings are handled.
    """
    encoded = signed_attrs.dump()
    if encoded[0] == _SET_TAG:
        return encoded
    if encoded[0] != _IMPLICIT_SET0_TAG:
        raise ScepProtocolError(
            "authenticatedAttributes are not encoded as a SET"
        )
    return bytes([_SET_TAG]) + encoded[1:]


# --------------------------------------------------------------------------- #
# Signature verification (SignedData)
# --------------------------------------------------------------------------- #


def _verify_digest_algo(digest_algorithm: algos.DigestAlgorithm) -> str:
    name = digest_algorithm['algorithm'].native
    if name not in SUPPORTED_DIGEST_ALGOS:
        raise UnsupportedScepAlgorithm(
            f"Digest algorithm '{name}' is not supported by this SCEP test "
            f"service (allowed: {', '.join(sorted(SUPPORTED_DIGEST_ALGOS))})"
        )
    return name


def _extract_signer_cert(
    sid: cms.SignerIdentifier, certificates: Iterable[x509.Certificate]
) -> x509.Certificate:
    for cert in certificates:
        if sid.name == 'issuer_and_serial_number':
            ias = sid.chosen
            if (
                cert.issuer == ias['issuer']
                and cert.serial_number == ias['serial_number'].native
            ):
                return cert
        elif sid.name == 'subject_key_identifier':
            if cert.key_identifier_value == sid.chosen.native:
                return cert
    raise ScepProtocolError(
        "Signer certificate referenced by SignerInfo not present in the "
        "SignedData certificate set"
    )


def _verify_signature(
    cert: x509.Certificate,
    signature_algo: algos.SignedDigestAlgorithm,
    signed_bytes: bytes,
    signature: bytes,
):
    public_key = serialization.load_der_public_key(cert.public_key.dump())
    algo_name = signature_algo.signature_algo
    hash_name = signature_algo.hash_algo

    try:
        if algo_name in ('rsassa_pkcs1v15', 'rsassa_pss'):
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise UnsupportedScepAlgorithm(
                    f"Algorithm '{algo_name}' requires an RSA public key"
                )
            if hash_name not in SUPPORTED_DIGEST_ALGOS:
                raise UnsupportedScepAlgorithm(
                    f"Signature hash '{hash_name}' is not supported"
                )
            if algo_name == 'rsassa_pkcs1v15':
                asym_padding: padding.AsymmetricPadding = padding.PKCS1v15()
            else:
                params = signature_algo['parameters']
                if params['mask_gen_algorithm']['algorithm'].native != 'mgf1':
                    raise UnsupportedScepAlgorithm("Only MGF1 PSS is supported")
                mgf_hash = params['mask_gen_algorithm']['parameters'][
                    'algorithm'
                ].native
                asym_padding = padding.PSS(
                    mgf=padding.MGF1(getattr(hashes, mgf_hash.upper())()),
                    salt_length=params['salt_length'].native,
                )
            public_key.verify(
                signature,
                signed_bytes,
                asym_padding,
                getattr(hashes, hash_name.upper())(),
            )
        elif algo_name == 'ecdsa':
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise UnsupportedScepAlgorithm(
                    "Algorithm 'ecdsa' requires an EC public key"
                )
            if hash_name not in SUPPORTED_DIGEST_ALGOS:
                raise UnsupportedScepAlgorithm(
                    f"Signature hash '{hash_name}' is not supported"
                )
            public_key.verify(
                signature,
                signed_bytes,
                ec.ECDSA(getattr(hashes, hash_name.upper())()),
            )
        else:
            raise UnsupportedScepAlgorithm(
                f"Signature algorithm '{algo_name}' is not supported"
            )
    except InvalidSignature as e:
        raise ScepProtocolError(
            "CMS SignerInfo signature does not verify"
        ) from e


def verify_signed_data(
    outer: cms.ContentInfo,
) -> Tuple[bytes, cms.CMSAttributes, x509.Certificate]:
    """
    Verify a CMS SignedData object and return the encapsulated content bytes,
    the SignerInfo's authenticated attributes and the signer's certificate.

    The encapsulated content type must be ``id-data`` (as required for SCEP
    request/response payloads).
    """
    if outer['content_type'].native != 'signed_data':
        raise ScepProtocolError(
            "Outer SCEP message must be a CMS SignedData object"
        )
    signed_data: cms.SignedData = outer['content']

    certificates = [
        cert.chosen
        for cert in signed_data['certificates']
        if cert.name == 'certificate'
    ]
    signer_infos = signed_data['signer_infos']
    if len(signer_infos) != 1:
        raise ScepProtocolError(
            "SCEP messages must carry exactly one SignerInfo"
        )
    signer_info: cms.SignerInfo = signer_infos[0]
    digest_name = _verify_digest_algo(signer_info['digest_algorithm'])
    signer_cert = _extract_signer_cert(signer_info['sid'], certificates)

    encap = signed_data['encap_content_info']
    if encap['content_type'].native != 'data':
        raise ScepProtocolError(
            "Encapsulated content in SCEP SignedData must be id-data"
        )
    econtent = (
        encap['content'].native if encap['content'].native is not None else b''
    )

    signed_attrs = signer_info['signed_attrs']
    if not isinstance(signed_attrs, cms.CMSAttributes):
        raise ScepProtocolError(
            "SCEP SignerInfo must include authenticatedAttributes"
        )

    # message digest check against the encapsulated content
    message_digest_attr = require_attribute(signed_attrs, 'message_digest')
    expected_digest = hashlib.new(digest_name, econtent).digest()
    if not secrets.compare_digest(message_digest_attr.native, expected_digest):
        raise ScepProtocolError(
            "messageDigest authenticated attribute does not match the "
            "encapsulated content"
        )

    content_type_attr = require_attribute(signed_attrs, 'content_type')
    if content_type_attr.native != 'data':
        raise ScepProtocolError(
            "contentType authenticated attribute must be id-data"
        )

    # the signature is computed over the DER encoding of the authenticated
    # attributes with a universal SET tag (RFC 5652 section 5.4)
    _verify_signature(
        signer_cert,
        signer_info['signature_algorithm'],
        authenticated_attributes_bytes(signed_attrs),
        signer_info['signature'].native,
    )
    return econtent, signed_attrs, signer_cert


# --------------------------------------------------------------------------- #
# EnvelopedData decryption / encryption
# --------------------------------------------------------------------------- #


def _load_rsa_private_key(private_key_info):
    private_key = serialization.load_der_private_key(
        private_key_info.dump(), password=None
    )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ScepProtocolError("Only RSA recipients are supported")
    return private_key


def decrypt_enveloped_data(outer: cms.ContentInfo, recipient_key) -> bytes:
    """
    Decrypt a CMS EnvelopedData object addressed to ``recipient_key`` using
    RSAES-PKCS1-v1_5 key transport and AES-CBC content encryption.
    """
    if outer['content_type'].native != 'enveloped_data':
        raise ScepProtocolError(
            "Inner SCEP message must be a CMS EnvelopedData object"
        )
    enveloped: cms.EnvelopedData = outer['content']
    eci: cms.EncryptedContentInfo = enveloped['encrypted_content_info']
    if eci['content_type'].native != 'data':
        raise ScepProtocolError(
            "Enveloped content in SCEP message must be id-data"
        )

    cea = eci['content_encryption_algorithm']
    cea_name = cea['algorithm'].native
    if cea_name not in SUPPORTED_CONTENT_ENCRYPTION:
        raise UnsupportedScepAlgorithm(
            f"Content encryption algorithm '{cea_name}' is not supported "
            f"(allowed: {', '.join(sorted(SUPPORTED_CONTENT_ENCRYPTION))})"
        )

    private_key = _load_rsa_private_key(recipient_key)
    content_key = None
    for recipient_info in enveloped['recipient_infos']:
        if recipient_info.name != 'ktri':
            raise UnsupportedScepAlgorithm(
                "Only key-transport recipient info (ktri) is supported"
            )
        ktri: cms.KeyTransRecipientInfo = recipient_info.chosen
        kea = ktri['key_encryption_algorithm']['algorithm'].native
        if kea != KEY_TRANSPORT_ALGO:
            raise UnsupportedScepAlgorithm(
                f"Key encryption algorithm '{kea}' is not supported"
            )
        try:
            content_key = private_key.decrypt(
                ktri['encrypted_key'].native, padding.PKCS1v15()
            )
        except ValueError:
            # not the recipient this KTRI was made out to
            continue
    if content_key is None:
        raise ScepProtocolError(
            "No RecipientInfo could be decrypted with the configured "
            "recipient key"
        )

    expected_len = SUPPORTED_CONTENT_ENCRYPTION[cea_name]
    if len(content_key) != expected_len:
        raise ScepProtocolError(
            f"Decrypted content key has length {len(content_key)}, expected "
            f"{expected_len} for {cea_name}"
        )

    iv = cea['parameters'].native
    decryptor = Cipher(algorithms.AES(content_key), modes.CBC(iv)).decryptor()
    padded = (
        decryptor.update(eci['encrypted_content'].native) + decryptor.finalize()
    )
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt_enveloped_data(
    content: bytes,
    recipient_cert: x509.Certificate,
    content_encryption: str = 'aes256_cbc',
) -> cms.ContentInfo:
    """
    Wrap ``content`` in an EnvelopedData object for ``recipient_cert``.
    """
    if content_encryption not in SUPPORTED_CONTENT_ENCRYPTION:
        raise UnsupportedScepAlgorithm(
            f"Content encryption algorithm '{content_encryption}' is not "
            "supported"
        )
    if recipient_cert.public_key.algorithm != 'rsa':
        raise ScepProtocolError("EnvelopedData recipients must use RSA keys")

    key_length = SUPPORTED_CONTENT_ENCRYPTION[content_encryption]
    content_key = secrets.token_bytes(key_length)
    iv = secrets.token_bytes(16)

    padder = PKCS7(128).padder()
    padded = padder.update(content) + padder.finalize()
    encryptor = Cipher(algorithms.AES(content_key), modes.CBC(iv)).encryptor()
    encrypted_content = encryptor.update(padded) + encryptor.finalize()

    public_key = serialization.load_der_public_key(
        recipient_cert.public_key.dump()
    )
    assert isinstance(public_key, rsa.RSAPublicKey)
    encrypted_key = public_key.encrypt(content_key, padding.PKCS1v15())

    rid = cms.RecipientIdentifier(
        {
            'issuer_and_serial_number': cms.IssuerAndSerialNumber(
                {
                    'issuer': recipient_cert.issuer,
                    'serial_number': recipient_cert.serial_number,
                }
            )
        }
    )
    recipient_info = cms.RecipientInfo(
        {
            'ktri': cms.KeyTransRecipientInfo(
                {
                    'version': 0,
                    'rid': rid,
                    'key_encryption_algorithm': cms.KeyEncryptionAlgorithm(
                        {'algorithm': KEY_TRANSPORT_ALGO}
                    ),
                    'encrypted_key': encrypted_key,
                }
            )
        }
    )

    encrypted_content_info = cms.EncryptedContentInfo(
        {
            'content_type': 'data',
            'content_encryption_algorithm': algos.EncryptionAlgorithm(
                {'algorithm': content_encryption, 'parameters': iv}
            ),
            'encrypted_content': encrypted_content,
        }
    )
    enveloped = cms.EnvelopedData(
        {
            'version': 0,
            'recipient_infos': [recipient_info],
            'encrypted_content_info': encrypted_content_info,
        }
    )
    return cms.ContentInfo(
        {'content_type': 'enveloped_data', 'content': enveloped}
    )


# --------------------------------------------------------------------------- #
# SignedData construction
# --------------------------------------------------------------------------- #


def build_signed_data(
    inner_content: bytes,
    signer_cert: x509.Certificate,
    signer_key,
    authenticated_attributes: List[cms.CMSAttribute],
    digest_algo: str = 'sha256',
    extra_certificates: Optional[List[x509.Certificate]] = None,
) -> cms.ContentInfo:
    """
    Build a CMS SignedData object with id-data encapsulating
    ``inner_content`` and the supplied authenticated attributes.
    """
    if digest_algo not in SUPPORTED_DIGEST_ALGOS:
        raise UnsupportedScepAlgorithm(
            f"Digest algorithm '{digest_algo}' is not supported"
        )
    digest_algorithm = algos.DigestAlgorithm({'algorithm': digest_algo})
    message_digest = hashlib.new(digest_algo, inner_content).digest()

    attrs = list(authenticated_attributes)
    attrs.append(_attr('content_type', cms.ContentType('data')))
    attrs.append(_attr('message_digest', core.OctetString(message_digest)))
    signed_attrs = cms.CMSAttributes(attrs)

    signature_algo = algos.SignedDigestAlgorithm(
        {'algorithm': f'{digest_algo}_rsa'}
    )
    from certomancer.crypto_utils import generic_sign

    signature = generic_sign(
        signer_key,
        authenticated_attributes_bytes(signed_attrs),
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
            'digest_algorithm': digest_algorithm,
            'signed_attrs': signed_attrs,
            'signature_algorithm': signature_algo,
            'signature': signature,
        }
    )

    certificates = {signer_cert}
    for extra in extra_certificates or ():
        certificates.add(extra)

    signed_data = cms.SignedData(
        {
            'version': 'v3',
            'digest_algorithms': cms.DigestAlgorithms((digest_algorithm,)),
            'encap_content_info': cms.EncapsulatedContentInfo(
                {
                    'content_type': 'data',
                    'content': cms.ParsableOctetString(inner_content),
                }
            ),
            'certificates': certificates,
            'signer_infos': [signer_info],
        }
    )
    return cms.ContentInfo(
        {'content_type': 'signed_data', 'content': signed_data}
    )


# --------------------------------------------------------------------------- #
# SCEP-specific authenticated attribute construction
# --------------------------------------------------------------------------- #


def scep_message_type_attr(value: int) -> cms.CMSAttribute:
    return _attr(OID_MESSAGE_TYPE, int(value))


def scep_pki_status_attr(status: int) -> cms.CMSAttribute:
    return _attr(OID_PKI_STATUS, int(status))


def scep_fail_info_attr(fail_info: int) -> cms.CMSAttribute:
    return _attr(OID_FAIL_INFO, int(fail_info))


def scep_sender_nonce_attr(nonce: bytes) -> cms.CMSAttribute:
    return _attr(OID_SENDER_NONCE, bytes(nonce))


def scep_recipient_nonce_attr(nonce: bytes) -> cms.CMSAttribute:
    return _attr(OID_RECIPIENT_NONCE, bytes(nonce))


def scep_transaction_id_attr(transaction_id: str) -> cms.CMSAttribute:
    return _attr(OID_TRANSACTION_ID, str(transaction_id))
