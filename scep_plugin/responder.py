"""
Offline SCEP test responder implemented as a Certomancer service plugin.

The plugin implements the three message flows required to exercise an
RFC 8894 SCEP client entirely offline:

* ``PKCSReq`` (``messageType`` 19) -- an enrollment request carrying a CSR,
* ``CertPoll`` (``messageType`` 20) -- a poll for a previously requested
  certificate,
* ``CertRep`` (``messageType`` 3) -- the response produced by this plugin.

It is intentionally *not* a certification authority: it never issues
certificates. The only certificate it can ever hand out is the single
Certomancer certificate named in the plugin configuration, and it only does
so when the CSR in the request carries that certificate's public key. All
state is keyed on the client-chosen ``transactionID`` and kept in memory.

Every response is a full SCEP "double-wrapped" message: an inner
EnvelopedData (for the client) inside an outer SignedData (from the
configured RA/CA), so a real SCEP client can verify the signature and
decrypt the payload end to end.
"""

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional, Set, Tuple

from asn1crypto import cms, core, csr, x509

from certomancer.registry import CertLabel, KeyLabel, PKIArchitecture
from certomancer.registry.plugin_api import (
    PluginServiceInfo,
    PluginServiceRequestError,
    ServicePlugin,
)

from .asn1 import (
    OID_MESSAGE_TYPE,
    OID_SENDER_NONCE,
    OID_TRANSACTION_ID,
    FailInfo,
    IssuerAndSubject,
    MessageType,
    PKIStatus,
    register_scep_oids,
)
from .cms_utils import (
    ScepProtocolError,
    UnsupportedScepAlgorithm,
    build_signed_data,
    decrypt_enveloped_data,
    encrypt_enveloped_data,
    find_attribute,
    require_attribute,
    scep_fail_info_attr,
    scep_message_type_attr,
    scep_pki_status_attr,
    scep_recipient_nonce_attr,
    scep_sender_nonce_attr,
    scep_transaction_id_attr,
    verify_signed_data,
)

logger = logging.getLogger(__name__)

register_scep_oids()

# message type integer constants from RFC 8894 section 3.2.1.1
MT_CERT_REP = 3
MT_PKCS_REQ = 19
MT_CERT_POLL = 20

# pkiStatus integer constants from RFC 8894 section 3.2.1.2
STATUS_SUCCESS = 0
STATUS_PENDING = 2
STATUS_FAILURE = 3

# fail info integer constants from RFC 8894 section 3.2.1.3
FAIL_BAD_ALG = 0
FAIL_BAD_MESSAGE_CHECK = 1
FAIL_BAD_REQUEST = 2
FAIL_BAD_CERT_ID = 4


@dataclass(frozen=True)
class ScepServiceConfig:
    """Validated plugin configuration for one SCEP endpoint."""

    target_cert: CertLabel
    """Label of the only certificate this endpoint may return."""

    responder_cert: CertLabel
    """Certificate used to sign outer SignedData responses."""

    responder_key_label: KeyLabel
    """Key label holding the responder's private signing key."""

    recipient_key_label: KeyLabel
    """Key label that can decrypt incoming EnvelopedData messages."""

    recipient_cert: CertLabel
    """Certificate whose public key clients encrypt requests for."""

    pending_first: bool = False
    """When true, the first PKCSReq answer is PENDING instead of SUCCESS."""


@dataclass
class _PendingTransaction:
    transaction_id: str
    signer_cert: x509.Certificate
    sender_nonce: bytes
    csr_public_key: bytes


class ScepResponderPlugin(ServicePlugin):
    """
    Service plugin serving one configured SCEP enrollment endpoint.
    Transaction bookkeeping lives in an instance dict so each
    ``transactionID`` is kept isolated from every other in-flight request.
    """

    plugin_label = 'scep-responder'
    content_type = 'application/x-pki-message'

    def __init__(self):
        # maps (service label, transaction id) -> pending transaction
        self._pending: Dict[Tuple[str, str], _PendingTransaction] = {}
        # (service label, transaction id) pairs that may collect a cert
        self._completed: Set[Tuple[str, str]] = set()

    # ------------------------------------------------------------------ #
    # configuration
    # ------------------------------------------------------------------ #
    def process_plugin_config(self, params):
        if not isinstance(params, dict):
            raise PluginServiceRequestError(
                "SCEP plugin configuration must be a mapping"
            )
        try:
            target_cert = CertLabel(params['target-cert'])
            responder_cert = CertLabel(params['responder-cert'])
            recipient_cert = CertLabel(params['recipient-cert'])
        except KeyError as e:
            raise PluginServiceRequestError(
                f"SCEP plugin requires a '{e.args[0]}' entry"
            ) from e

        responder_key = params.get('responder-key')
        recipient_key = params.get('recipient-key')
        responder_key_label = KeyLabel(
            responder_key if responder_key is not None else str(responder_cert)
        )
        recipient_key_label = KeyLabel(
            recipient_key if recipient_key is not None else str(recipient_cert)
        )

        pending_first = bool(params.get('pending-first', False))
        return ScepServiceConfig(
            target_cert=target_cert,
            responder_cert=responder_cert,
            responder_key_label=responder_key_label,
            recipient_key_label=recipient_key_label,
            recipient_cert=recipient_cert,
            pending_first=pending_first,
        )

    # ------------------------------------------------------------------ #
    # entry point
    # ------------------------------------------------------------------ #
    def invoke(
        self,
        arch: PKIArchitecture,
        info: PluginServiceInfo,
        request: bytes,
        at_time: Optional[datetime] = None,
    ) -> bytes:
        cfg: ScepServiceConfig = info.plugin_config

        # Phase 1: parse and cryptographically verify the outer SignedData.
        # A failure here means the message cannot be authenticated at all, so
        # no SCEP-level answer is produced; the transport reports a bad
        # request (HTTP 400 in the Animator integration).
        try:
            outer = cms.ContentInfo.load(request)
            econtent, signed_attrs, signer_cert = verify_signed_data(outer)
        except UnsupportedScepAlgorithm as e:
            logger.info("SCEP request rejected: unsupported algorithm: %s", e)
            raise PluginServiceRequestError(
                f"Unsupported algorithm in SCEP message: {e}",
                user_msg='Bad request',
            ) from e
        except (ValueError, ScepProtocolError) as e:
            logger.info("SCEP request rejected during CMS processing: %s", e)
            raise PluginServiceRequestError(
                f"Malformed or unauthenticated SCEP message: {e}",
                user_msg='Bad request',
            ) from e

        # Phase 2: decrypt the inner EnvelopedData. The outer signature has
        # already authenticated the sender, so an unsupported content/key
        # encryption algorithm is reported as a proper SCEP badAlg CertRep
        # that the client can verify and decrypt.
        try:
            inner_envelope = cms.ContentInfo.load(econtent)
            plaintext = decrypt_enveloped_data(
                inner_envelope,
                arch.key_set.get_private_key(cfg.recipient_key_label),
            )
        except UnsupportedScepAlgorithm as e:
            logger.info("SCEP request rejected: unsupported algorithm: %s", e)
            return self._bad_alg_failure(arch, cfg, signer_cert, signed_attrs)
        except (ValueError, ScepProtocolError) as e:
            logger.info("SCEP request rejected during decryption: %s", e)
            raise PluginServiceRequestError(
                f"Undecryptable SCEP inner message: {e}",
                user_msg='Bad request',
            ) from e

        try:
            message_type = _message_type_attr_value(
                require_attribute(signed_attrs, OID_MESSAGE_TYPE)
            )
            transaction_id = require_attribute(
                signed_attrs, OID_TRANSACTION_ID
            ).native
            if not isinstance(transaction_id, str) or not transaction_id:
                raise ScepProtocolError(
                    "transactionID must be a nonempty string"
                )
            sender_nonce_attr = find_attribute(signed_attrs, OID_SENDER_NONCE)
            sender_nonce = (
                sender_nonce_attr.native
                if sender_nonce_attr is not None
                else None
            )
        except ScepProtocolError as e:
            raise PluginServiceRequestError(
                str(e), user_msg='Bad request'
            ) from e

        logger.info(
            "SCEP %s on service %s for transaction %s",
            MessageType._map.get(message_type, message_type),
            info.label,
            transaction_id,
        )

        ctx = _RequestContext(arch, cfg, str(info.label), self, signer_cert)
        if message_type == MT_PKCS_REQ:
            return ctx.handle_pkcs_req(
                plaintext,
                signed_attrs,
                signer_cert,
                transaction_id,
                sender_nonce,
            )
        elif message_type == MT_CERT_POLL:
            return ctx.handle_cert_poll(
                plaintext,
                signed_attrs,
                signer_cert,
                transaction_id,
                sender_nonce,
            )
        else:
            return ctx.failure_response(
                signed_attrs,
                transaction_id,
                sender_nonce,
                FAIL_BAD_REQUEST,
                f"Unsupported SCEP messageType {message_type}; only "
                f"PKCSReq (19) and CertPoll (20) are implemented",
            )

    def _bad_alg_failure(
        self,
        arch: PKIArchitecture,
        cfg: ScepServiceConfig,
        client_cert: x509.Certificate,
        signed_attrs,
    ) -> bytes:
        # The outer signature verified, so the sender is known. Echo its
        # transactionID/nonce when present and encrypt the failure for that
        # same client, producing a fully verifiable SCEP badAlg CertRep.
        responder_cert = arch.get_cert(cfg.responder_cert)
        responder_key = arch.key_set.get_private_key(cfg.responder_key_label)

        transaction_attr = find_attribute(signed_attrs, OID_TRANSACTION_ID)
        transaction_id = (
            transaction_attr.native if transaction_attr is not None else ''
        )
        nonce_attr = find_attribute(signed_attrs, OID_SENDER_NONCE)
        sender_nonce = nonce_attr.native if nonce_attr is not None else None

        attrs = [
            scep_message_type_attr(MT_CERT_REP),
            scep_transaction_id_attr(transaction_id),
            scep_pki_status_attr(STATUS_FAILURE),
            scep_fail_info_attr(FAIL_BAD_ALG),
            scep_sender_nonce_attr(_fresh_nonce()),
        ]
        if sender_nonce is not None:
            attrs.append(scep_recipient_nonce_attr(sender_nonce))

        payload = _encode_status_message(STATUS_FAILURE, FAIL_BAD_ALG)
        return _double_wrap(
            payload,
            responder_cert=responder_cert,
            responder_key=responder_key,
            recipient_cert=client_cert,
            authenticated_attributes=attrs,
        )


class _RequestContext:
    """Per-request helper bundling architecture access and response logic."""

    def __init__(
        self,
        arch: PKIArchitecture,
        cfg: ScepServiceConfig,
        service_label: str,
        plugin: ScepResponderPlugin,
        client_cert: x509.Certificate,
    ):
        self.arch = arch
        self.cfg = cfg
        self.service_label = service_label
        self.plugin = plugin
        # responses are encrypted for the authenticated SCEP client, i.e.
        # the signer of the incoming message -- not for the RA itself
        self.client_cert = client_cert

        self.responder_cert = arch.get_cert(cfg.responder_cert)
        self.responder_key = arch.key_set.get_private_key(
            cfg.responder_key_label
        )
        self.target_cert = arch.get_cert(cfg.target_cert)
        self.target_public_key_der = self.target_cert.public_key.dump()

    # ------------------------------------------------------------------ #
    # PKCSReq
    # ------------------------------------------------------------------ #
    def handle_pkcs_req(
        self,
        plaintext,
        signed_attrs,
        signer_cert,
        transaction_id,
        sender_nonce,
    ) -> bytes:
        key = (self.service_label, transaction_id)
        try:
            csr_obj = csr.CertificationRequest.load(plaintext)
        except ValueError as e:
            return self.failure_response(
                signed_attrs,
                transaction_id,
                sender_nonce,
                FAIL_BAD_REQUEST,
                f"Inner payload is not a valid PKCS#10 CSR: {e}",
            )

        # Verify the CSR's own signature before trusting its body.
        if not _verify_csr_signature(csr_obj):
            return self.failure_response(
                signed_attrs,
                transaction_id,
                sender_nonce,
                FAIL_BAD_MESSAGE_CHECK,
                "CSR self-signature does not verify",
            )

        csr_public_key_der = csr_obj['certification_request_info'][
            'subject_pk_info'
        ].dump()
        if not secrets.compare_digest(
            csr_public_key_der, self.target_public_key_der
        ):
            logger.info(
                "SCEP CSR public key does not match configured target "
                "certificate for transaction %s",
                transaction_id,
            )
            return self.failure_response(
                signed_attrs,
                transaction_id,
                sender_nonce,
                FAIL_BAD_CERT_ID,
                "CSR public key does not correspond to the configured "
                "target certificate",
            )

        # Record the transaction binding before any success path so a
        # transaction can never borrow another transaction's certificate.
        self.plugin._completed.discard(key)
        self.plugin._pending[key] = _PendingTransaction(
            transaction_id=transaction_id,
            signer_cert=signer_cert,
            sender_nonce=sender_nonce or b'',
            csr_public_key=csr_public_key_der,
        )

        if self.cfg.pending_first:
            return self.pending_response(
                signed_attrs, transaction_id, sender_nonce
            )
        self.plugin._completed.add(key)
        return self.success_response(signed_attrs, transaction_id, sender_nonce)

    # ------------------------------------------------------------------ #
    # CertPoll
    # ------------------------------------------------------------------ #
    def handle_cert_poll(
        self,
        plaintext,
        signed_attrs,
        signer_cert,
        transaction_id,
        sender_nonce,
    ) -> bytes:
        key = (self.service_label, transaction_id)
        pending = self.plugin._pending.get(key)
        if pending is None:
            # Unknown transaction: never reveal any certificate.
            return self.failure_response(
                signed_attrs,
                transaction_id,
                sender_nonce,
                FAIL_BAD_REQUEST,
                "No enrollment request is known for this transactionID",
            )

        # The poll must originate from the same SCEP signer certificate that
        # opened the transaction.
        if not _same_cert(pending.signer_cert, signer_cert):
            return self.failure_response(
                signed_attrs,
                transaction_id,
                sender_nonce,
                FAIL_BAD_REQUEST,
                "CertPoll signer does not match the original PKCSReq",
            )

        # CertPoll's inner payload is IssuerAndSubject; make sure it names
        # the configured target certificate before issuing anything.
        try:
            issuer_and_subject = IssuerAndSubject.load(plaintext)
        except ValueError as e:
            return self.failure_response(
                signed_attrs,
                transaction_id,
                sender_nonce,
                FAIL_BAD_REQUEST,
                f"CertPoll payload is not a valid IssuerAndSubject: {e}",
            )
        if (
            issuer_and_subject['issuer'].native
            != self.target_cert.issuer.native
            or issuer_and_subject['subject'].native
            != self.target_cert.subject.native
        ):
            return self.failure_response(
                signed_attrs,
                transaction_id,
                sender_nonce,
                FAIL_BAD_CERT_ID,
                "CertPoll issuer/subject does not identify the configured "
                "target certificate",
            )

        if key not in self.plugin._completed and self.cfg.pending_first:
            # first poll after a PENDING answer completes the enrollment
            self.plugin._completed.add(key)
            return self.success_response(
                signed_attrs, transaction_id, sender_nonce
            )

        if key in self.plugin._completed:
            return self.success_response(
                signed_attrs, transaction_id, sender_nonce
            )
        return self.pending_response(signed_attrs, transaction_id, sender_nonce)

    # ------------------------------------------------------------------ #
    # response builders
    # ------------------------------------------------------------------ #
    def _wrap_response(
        self, authenticated_attributes, inner_payload: bytes
    ) -> bytes:
        return _double_wrap(
            inner_payload,
            responder_cert=self.responder_cert,
            responder_key=self.responder_key,
            recipient_cert=self.client_cert,
            authenticated_attributes=authenticated_attributes,
        )

    def _base_response_attrs(self, transaction_id, sender_nonce, status: int):
        attrs = [
            scep_message_type_attr(MT_CERT_REP),
            scep_transaction_id_attr(transaction_id),
            scep_pki_status_attr(status),
            scep_sender_nonce_attr(_fresh_nonce()),
        ]
        if sender_nonce is not None:
            attrs.append(scep_recipient_nonce_attr(sender_nonce))
        return attrs

    def success_response(
        self, signed_attrs, transaction_id, sender_nonce
    ) -> bytes:
        attrs = self._base_response_attrs(
            transaction_id, sender_nonce, STATUS_SUCCESS
        )
        # successful payload: a degenerate SignedData (certs-only) holding
        # the issued certificate, per RFC 8894 section 3.3.2
        payload = _encode_certs_only(self.target_cert)
        return self._wrap_response(attrs, payload)

    def pending_response(
        self, signed_attrs, transaction_id, sender_nonce
    ) -> bytes:
        attrs = self._base_response_attrs(
            transaction_id, sender_nonce, STATUS_PENDING
        )
        return self._wrap_response(attrs, b'')

    def failure_response(
        self,
        signed_attrs,
        transaction_id,
        sender_nonce,
        fail_info: int,
        message: str,
    ) -> bytes:
        logger.info(
            "SCEP failure for transaction %s: %s", transaction_id, message
        )
        attrs = self._base_response_attrs(
            transaction_id, sender_nonce, STATUS_FAILURE
        )
        attrs.append(scep_fail_info_attr(fail_info))
        payload = _encode_status_message(STATUS_FAILURE, fail_info)
        return self._wrap_response(attrs, payload)


# --------------------------------------------------------------------------- #
# module-level helpers
# --------------------------------------------------------------------------- #


def _fresh_nonce() -> bytes:
    # 16 bytes, per RFC 8894 section 3.2.1.4
    return secrets.token_bytes(16)


def _message_type_attr_value(attr) -> int:
    """Return the raw integer messageType, even when parsed as a name."""
    value = attr.native
    if isinstance(value, str):
        value = MessageType._reverse_map[value]
    return int(value)


def _same_cert(a: x509.Certificate, b: x509.Certificate) -> bool:
    return a.issuer == b.issuer and a.serial_number == b.serial_number


def _verify_csr_signature(csr_obj: csr.CertificationRequest) -> bool:
    from cryptography import x509 as cx509
    from cryptography.exceptions import InvalidSignature

    try:
        # cryptography validates the CSR self-signature while loading.
        cx509.load_der_x509_csr(csr_obj.dump())
        return True
    except (ValueError, InvalidSignature):
        return False


class _StatusMessage(core.Sequence):
    _fields = [
        ('status', PKIStatus),
        ('fail_info', FailInfo),
    ]


def _encode_status_message(status: int, fail_info: int) -> bytes:
    # A compact DER structure describing a failure; it travels as the
    # encrypted inner payload, while the authoritative status/failInfo
    # values are also exposed as SCEP authenticated attributes.
    return _StatusMessage(
        {'status': PKIStatus(status), 'fail_info': FailInfo(fail_info)}
    ).dump()


def _encode_certs_only(cert: x509.Certificate) -> bytes:
    # an empty collection still has to serialise, so give the SET OF an
    # explicit empty contents value
    digest_algorithms = cms.DigestAlgorithms()
    digest_algorithms.contents = b''
    signer_infos = cms.SignerInfos()
    signer_infos.contents = b''
    # a v1 SignedData uses the PKCS#7 EncapsulatedContentInfo (= ContentInfo)
    # shape for its encapContentInfo
    signed_data = cms.SignedData(
        {
            'version': 'v1',
            'digest_algorithms': digest_algorithms,
            'encap_content_info': cms.ContentInfo({'content_type': 'data'}),
            'certificates': [cert],
            'signer_infos': signer_infos,
        }
    )
    return cms.ContentInfo(
        {'content_type': 'signed_data', 'content': signed_data}
    ).dump()


def _double_wrap(
    inner_plaintext: bytes,
    *,
    responder_cert: x509.Certificate,
    responder_key,
    recipient_cert: x509.Certificate,
    authenticated_attributes,
) -> bytes:
    envelope = encrypt_enveloped_data(inner_plaintext, recipient_cert)
    outer = build_signed_data(
        envelope.dump(),
        signer_cert=responder_cert,
        signer_key=responder_key,
        authenticated_attributes=list(authenticated_attributes),
    )
    return outer.dump()
