"""
ASN.1 definitions for the SCEP (Simple Certificate Enrollment Protocol)
message types defined in RFC 8894.

asn1crypto ships without a SCEP module, so the protocol's attribute OIDs and
the small enumeration types used in PKCS#7 authenticated attributes are
declared here. These patches are idempotent so importing this module more
than once (or alongside another SCEP implementation) is harmless.
"""

from asn1crypto import cms, core, x509

# SCEP OID arc (RFC 8894 section 3.2.1)
OID_MESSAGE_TYPE = '2.16.840.1.113733.1.9.2'
OID_PKI_STATUS = '2.16.840.1.113733.1.9.3'
OID_FAIL_INFO = '2.16.840.1.113733.1.9.4'
OID_SENDER_NONCE = '2.16.840.1.113733.1.9.5'
OID_RECIPIENT_NONCE = '2.16.840.1.113733.1.9.6'
OID_TRANSACTION_ID = '2.16.840.1.113733.1.9.7'

SCEP_OID_NAMES = {
    OID_MESSAGE_TYPE: 'scep_message_type',
    OID_PKI_STATUS: 'scep_pki_status',
    OID_FAIL_INFO: 'scep_fail_info',
    OID_SENDER_NONCE: 'scep_sender_nonce',
    OID_RECIPIENT_NONCE: 'scep_recipient_nonce',
    OID_TRANSACTION_ID: 'scep_transaction_id',
}


class MessageType(core.Integer):
    """SCEP messageType values (RFC 8894 section 3.2.1.1)."""

    _map = {
        3: 'cert_rep',
        17: 'pkc_s_req',
        19: 'pkcs_req',
        20: 'cert_poll',
        21: 'get_cert',
        22: 'get_crl',
    }


class PKIStatus(core.Integer):
    """SCEP pkiStatus values (RFC 8894 section 3.2.1.2)."""

    _map = {
        0: 'success',
        2: 'pending',
        3: 'failure',
    }


class FailInfo(core.Integer):
    """SCEP failInfo values (RFC 8894 section 3.2.1.3)."""

    _map = {
        0: 'bad_alg',
        1: 'bad_message_check',
        2: 'bad_request',
        3: 'bad_time',
        4: 'bad_cert_id',
    }


class IssuerAndSubject(core.Sequence):
    """
    Payload of a CertPoll request (RFC 8894 section 4.4.2): the issuer name
    and subject name of the certificate being polled for.
    """

    _fields = [
        ('issuer', x509.Name),
        ('subject', x509.Name),
    ]


# CMSAttribute.values is a SET OF, so each registered OID needs a SetOf
# subclass as its value spec (not the bare scalar type).
class SetOfMessageType(core.SetOf):
    _child_spec = MessageType


class SetOfPKIStatus(core.SetOf):
    _child_spec = PKIStatus


class SetOfFailInfo(core.SetOf):
    _child_spec = FailInfo


class SetOfOctetString(core.SetOf):
    _child_spec = core.OctetString


class SetOfTransactionId(core.SetOf):
    _child_spec = core.PrintableString


def register_scep_oids():
    """
    Register the SCEP attribute OIDs with asn1crypto's CMS attribute map so
    that :class:`cms.CMSAttribute` values can be parsed by name.
    """
    attr_map = cms.CMSAttributeType._map
    reverse_map = cms.CMSAttributeType._reverse_map
    attr_specs = cms.CMSAttribute._oid_specs

    value_specs = {
        OID_MESSAGE_TYPE: SetOfMessageType,
        OID_PKI_STATUS: SetOfPKIStatus,
        OID_FAIL_INFO: SetOfFailInfo,
        OID_SENDER_NONCE: SetOfOctetString,
        OID_RECIPIENT_NONCE: SetOfOctetString,
        OID_TRANSACTION_ID: SetOfTransactionId,
    }
    for oid, name in SCEP_OID_NAMES.items():
        if oid not in attr_map:
            attr_map[oid] = name
            attr_specs[name] = value_specs[oid]
            if reverse_map is not None and name not in reverse_map:
                reverse_map[name] = oid


register_scep_oids()
