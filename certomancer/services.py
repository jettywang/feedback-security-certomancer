import abc
import hashlib
import os
import struct
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from asn1crypto import algos, cms, core, crl, keys, ocsp, tsp, x509
from asn1crypto.crl import TBSCertListExtension

from certomancer.crypto_utils import (
    generic_sign,
    generic_verify,
    optimal_pss_params,
)


class CertomancerServiceError(Exception):
    pass


class DeltaCRLError(CertomancerServiceError):
    """
    Raised when a delta CRL cannot be generated, validated or merged safely.

    The error message is suitable for diagnostic output; callers should treat
    it as an indication that the CRL data is inconsistent or untrustworthy.
    """

    pass


def _crl_extension(crl_obj: crl.CertificateList, extn_id: str):
    extensions = crl_obj['tbs_cert_list']['crl_extensions']
    if not extensions:
        return None
    for ext in extensions:
        if ext['extn_id'].native == extn_id:
            return ext
    return None


def _crl_number(crl_obj: crl.CertificateList) -> int:
    ext = _crl_extension(crl_obj, 'crl_number')
    if ext is None:
        raise DeltaCRLError("CRL does not carry a CRL number extension.")
    return ext['extn_value'].native


def _delta_crl_indicator(crl_obj: crl.CertificateList) -> Optional[int]:
    ext = _crl_extension(crl_obj, 'delta_crl_indicator')
    if ext is None:
        return None
    if not ext['critical'].native:
        raise DeltaCRLError(
            "The deltaCRLIndicator extension must be marked critical."
        )
    return ext['extn_value'].native


def _issuing_distribution_point(crl_obj: crl.CertificateList):
    ext = _crl_extension(crl_obj, 'issuing_distribution_point')
    if ext is None:
        return None
    if not ext['critical'].native:
        raise DeltaCRLError(
            "The issuingDistributionPoint extension must be marked critical."
        )
    return ext['extn_value'].parsed


def _authority_key_identifier(crl_obj: crl.CertificateList) -> Optional[bytes]:
    ext = _crl_extension(crl_obj, 'authority_key_identifier')
    if ext is None:
        return None
    return ext['extn_value'].native['key_identifier']


def _idp_scope(idp) -> tuple:
    if idp is None:
        return ()
    return (
        idp['distribution_point'].dump() if idp['distribution_point'] else None,
        bool(idp['only_contains_user_certs'].native),
        bool(idp['only_contains_ca_certs'].native),
        bool(idp['only_contains_attribute_certs'].native),
        bool(idp['indirect_crl'].native),
        idp['only_some_reasons'].native,
    )


def _check_crl_signature(
    crl_obj: crl.CertificateList,
    issuer_cert: x509.Certificate,
):
    tbs_sig_algo = crl_obj['tbs_cert_list']['signature']
    sig_algo = crl_obj['signature_algorithm']
    if tbs_sig_algo.native != sig_algo.native:
        raise DeltaCRLError(
            "The CRL signature algorithm does not match the TBS data."
        )
    try:
        generic_verify(
            issuer_cert.public_key,
            crl_obj['tbs_cert_list'].dump(),
            crl_obj['signature'].native,
            sig_algo,
        )
    except (ValueError, NotImplementedError) as e:
        raise DeltaCRLError(
            "The CRL signature is invalid for the supplied issuer certificate."
        ) from e


def _validate_delta_pair(
    base_crl: crl.CertificateList,
    delta_crl: crl.CertificateList,
    issuer_cert: Optional[x509.Certificate] = None,
    *,
    verify_signatures: bool = True,
    expected_base_crl_number: Optional[int] = None,
):
    """
    Check that a delta CRL can safely be applied to a base CRL.

    This is the strict validation path used by :func:`merge_delta_crl` and the
    service registry. It checks issuer, AKI, revocation scope, CRL numbers and
    the delta indicator before any entries are merged.

    :param base_crl:
        The base (full) CRL.
    :param delta_crl:
        The delta CRL to validate.
    :param issuer_cert:
        Issuer certificate used to verify both signatures.
    :param verify_signatures:
        Whether to verify the cryptographic signatures. When ``True``,
        ``issuer_cert`` is required.
    :param expected_base_crl_number:
        Optional expected base CRL number. If specified, the base CRL must
        carry exactly that number.
    :raises DeltaCRLError:
        If the CRLs are inconsistent or a signature is invalid.
    """
    if verify_signatures:
        if issuer_cert is None:
            raise DeltaCRLError(
                "An issuer certificate is required to verify CRL signatures."
            )
        _check_crl_signature(base_crl, issuer_cert)
        _check_crl_signature(delta_crl, issuer_cert)

    base_tbs = base_crl['tbs_cert_list']
    delta_tbs = delta_crl['tbs_cert_list']

    if base_tbs['issuer'].dump() != delta_tbs['issuer'].dump():
        raise DeltaCRLError("Delta CRL issuer does not match the base CRL.")

    base_aki = _authority_key_identifier(base_crl)
    delta_aki = _authority_key_identifier(delta_crl)
    if base_aki is not None or delta_aki is not None:
        if base_aki != delta_aki:
            raise DeltaCRLError(
                "Delta CRL authority key identifier does not match the "
                "base CRL."
            )

    if _idp_scope(_issuing_distribution_point(base_crl)) != _idp_scope(
        _issuing_distribution_point(delta_crl)
    ):
        raise DeltaCRLError(
            "Delta CRL issuing distribution point scope does not match "
            "the base CRL."
        )

    base_number = _crl_number(base_crl)
    delta_number = _crl_number(delta_crl)
    delta_indicator = _delta_crl_indicator(delta_crl)
    if delta_indicator is None:
        raise DeltaCRLError(
            "The supplied CRL is not a delta CRL (missing deltaCRLIndicator)."
        )
    if expected_base_crl_number is None:
        expected_base_crl_number = base_number
    if base_number != expected_base_crl_number:
        raise DeltaCRLError(
            f"Base CRL number {base_number} does not match expected base "
            f"CRL number {expected_base_crl_number}."
        )
    if delta_indicator != base_number:
        raise DeltaCRLError(
            f"Delta CRL indicator {delta_indicator} does not match base CRL "
            f"number {base_number}."
        )
    if delta_number <= base_number:
        raise DeltaCRLError(
            "Delta CRL number must be greater than the base CRL number."
        )

    base_this_update = base_tbs['this_update'].native
    delta_this_update = delta_tbs['this_update'].native
    if delta_this_update < base_this_update:
        raise DeltaCRLError(
            "Delta CRL thisUpdate precedes the base CRL thisUpdate."
        )

    return delta_number


def merge_delta_crl(
    base_crl: crl.CertificateList,
    delta_crl: crl.CertificateList,
    issuer_cert: Optional[x509.Certificate] = None,
    *,
    verify_signatures: bool = True,
    expected_base_crl_number: Optional[int] = None,
) -> crl.TbsCertList:
    """
    Merge a delta CRL into a base CRL, without signing the result.

    The returned TBS structure reflects the state of the base CRL after all
    new revocations in the delta have been applied. It carries the delta CRL's
    CRL number and update timestamps, and no longer has a
    ``deltaCRLIndicator``.

    Callers that need a signed CRL can pass the returned TBS structure to
    :meth:`CRLBuilder.sign_crl`, or use
    :meth:`~certomancer.registry.pki_arch.ServiceRegistry.merge_delta_crl`,
    which signs the merged result with the repository's configured key.

    Revocation removals (``removeFromCRL`` entries) are rejected, since
    Certomancer deliberately does not simulate certificate unrevocation.

    :param base_crl:
        The base (full) CRL.
    :param delta_crl:
        The delta CRL to apply.
    :param issuer_cert:
        Issuer certificate for signature verification. Required unless
        ``verify_signatures`` is ``False``.
    :param verify_signatures:
        Whether to verify both CRL signatures before merging.
    :param expected_base_crl_number:
        Optional expected base CRL number.
    :return:
        The merged, unsigned :class:`asn1crypto.crl.TbsCertList`.
    :raises DeltaCRLError:
        If the CRLs are inconsistent, contain unsupported entries, or carry
        invalid signatures.
    """
    _validate_delta_pair(
        base_crl,
        delta_crl,
        issuer_cert,
        verify_signatures=verify_signatures,
        expected_base_crl_number=expected_base_crl_number,
    )

    base_tbs = base_crl['tbs_cert_list']
    delta_tbs = delta_crl['tbs_cert_list']

    merged_entries: Dict[int, crl.RevokedCertificate] = {}
    for revo in base_tbs['revoked_certificates']:
        merged_entries[revo['user_certificate'].native] = revo

    base_this_update = base_tbs['this_update'].native
    for revo in delta_tbs['revoked_certificates']:
        if revo['revocation_date'].native < base_this_update:
            raise DeltaCRLError(
                "Delta CRL contains a revocation that predates the base CRL."
            )
        if any(
            ext['extn_id'].native == 'crl_reason'
            and ext['extn_value'].native == 'remove_from_crl'
            for ext in revo['crl_entry_extensions']
        ):
            raise DeltaCRLError(
                "Delta CRL contains a removeFromCRL entry, but revocation "
                "removal is not supported."
            )
        serial = revo['user_certificate'].native
        if serial in merged_entries:
            raise DeltaCRLError(
                f"Delta CRL re-revokes certificate serial {serial} already "
                f"present in the base CRL."
            )
        merged_entries[serial] = revo

    merged_tbs = base_tbs.copy()
    merged_tbs['this_update'] = delta_tbs['this_update']
    merged_tbs['next_update'] = delta_tbs['next_update']
    merged_tbs['revoked_certificates'] = crl.RevokedCertificates(
        list(merged_entries.values())
    )

    extensions = [
        ext
        for ext in merged_tbs['crl_extensions']
        if ext['extn_id'].native not in ('delta_crl_indicator', 'crl_number')
    ]
    extensions.insert(
        0,
        crl.TBSCertListExtension(
            {
                'extn_id': 'crl_number',
                'extn_value': core.Integer(_crl_number(delta_crl)),
            }
        ),
    )
    merged_tbs['crl_extensions'] = crl.TBSCertListExtensions(extensions)
    return merged_tbs


def get_nonce() -> int:
    """
    Generate a random 8-byte integer

    (For testing use only)
    """
    # we initialise it like this to guarantee a fixed width
    return struct.unpack('>q', b'\x01' + os.urandom(7))[0]


def simple_cms_attribute(attr_type, value):
    """
    Convenience method to quickly construct a CMS attribute object with
    one value.

    :param attr_type:
        The attribute type, as a string or OID.
    :param value:
        The value.
    :return:
        A :class:`.cms.CMSAttribute` object.
    """
    return cms.CMSAttribute(
        {'type': cms.CMSAttributeType(attr_type), 'values': (value,)}
    )


class TimeStamper:
    def __init__(
        self,
        tsa_cert: x509.Certificate,
        tsa_key: keys.PrivateKeyInfo,
        signature_algo: Optional[algos.SignedDigestAlgorithm] = None,
        certs_to_embed=None,
        fixed_dt: Optional[datetime] = None,
        policy=tsp.ObjectIdentifier('1.3.6.1.4.1.4146.2.3'),
        md_algorithm='sha256',
    ):
        self.tsa_cert = tsa_cert
        self.tsa_key = tsa_key
        self.certs_to_embed = list(certs_to_embed or ())
        self.fixed_dt = fixed_dt
        self.policy = policy
        self.md_algorithm = md_algorithm
        self.signature_algo = signature_algo or choose_signed_digest(
            md_algorithm, tsa_cert.public_key
        )

    def request_tsa_response(self, req: tsp.TimeStampReq) -> tsp.TimeStampResp:
        # We pretend that certReq is always true in the request

        status = tsp.PKIStatusInfo({'status': tsp.PKIStatus('granted')})
        message_imprint: tsp.MessageImprint = req['message_imprint']
        md_algorithm = self.md_algorithm
        digest_algorithm_obj = algos.DigestAlgorithm(
            {'algorithm': md_algorithm}
        )
        dt = self.fixed_dt or datetime.now(tz=timezone.utc)
        tst_info_dict = {
            'version': 'v1',
            'policy': self.policy,
            'message_imprint': message_imprint,
            'serial_number': get_nonce(),
            'gen_time': dt,
            'tsa': x509.GeneralName(
                name='directory_name', value=self.tsa_cert.subject
            ),
        }

        if isinstance(req['nonce'], core.Integer):
            tst_info_dict['nonce'] = req['nonce']

        tst_info: tsp.TSTInfo = tsp.TSTInfo(tst_info_dict)
        tst_info_data = tst_info.dump()
        message_digest = getattr(hashlib, md_algorithm)(tst_info_data).digest()
        signing_cert_id = tsp.ESSCertID(
            {'cert_hash': hashlib.sha1(self.tsa_cert.dump()).digest()}
        )
        signed_attrs = cms.CMSAttributes(
            [
                simple_cms_attribute('content_type', 'tst_info'),
                simple_cms_attribute(
                    'signing_time', cms.Time({'utc_time': core.UTCTime(dt)})
                ),
                simple_cms_attribute(
                    'signing_certificate',
                    tsp.SigningCertificate({'certs': [signing_cert_id]}),
                ),
                simple_cms_attribute('message_digest', message_digest),
            ]
        )
        signature = generic_sign(
            self.tsa_key, signed_attrs.dump(), self.signature_algo
        )
        sig_info = cms.SignerInfo(
            {
                'version': 'v1',
                'sid': cms.SignerIdentifier(
                    {
                        'issuer_and_serial_number': cms.IssuerAndSerialNumber(
                            {
                                'issuer': self.tsa_cert.issuer,
                                'serial_number': self.tsa_cert.serial_number,
                            }
                        )
                    }
                ),
                'digest_algorithm': digest_algorithm_obj,
                'signature_algorithm': self.signature_algo,
                'signed_attrs': signed_attrs,
                'signature': signature,
            }
        )
        certs = set(self.certs_to_embed)
        certs.add(self.tsa_cert)
        signed_data = {
            # must use v3 to get access to the EncapsulatedContentInfo construct
            'version': 'v3',
            'digest_algorithms': cms.DigestAlgorithms((digest_algorithm_obj,)),
            'encap_content_info': cms.EncapsulatedContentInfo(
                {
                    'content_type': cms.ContentType('tst_info'),
                    'content': cms.ParsableOctetString(tst_info_data),
                }
            ),
            'certificates': certs,
            'signer_infos': [sig_info],
        }
        tst = cms.ContentInfo(
            {
                'content_type': cms.ContentType('signed_data'),
                'content': cms.SignedData(signed_data),
            }
        )
        return tsp.TimeStampResp({'status': status, 'time_stamp_token': tst})


class CRLBuilder:
    def __init__(
        self,
        issuer_name: x509.Name,
        issuer_key: keys.PrivateKeyInfo,
        signature_algo: algos.SignedDigestAlgorithm,
        authority_key_identifier: core.OctetString,
        extra_crl_extensions: Optional[List[TBSCertListExtension]] = None,
    ):
        self.issuer_name = issuer_name
        self.issuer_key = issuer_key
        self.signature_algo = signature_algo
        self.authority_key_identifier = authority_key_identifier
        self.extra_crl_extensions = extra_crl_extensions or []

    def build_crl(
        self,
        crl_number: int,
        this_update: datetime,
        next_update: datetime,
        revoked_certs,
        distpoint: Optional[dict] = None,
        delta_crl_indicator: Optional[int] = None,
        freshest_crl: Optional[x509.CRLDistributionPoints] = None,
    ) -> crl.CertificateList:
        tbs_crl = self.format_tbs_crl(
            crl_number=crl_number,
            this_update=this_update,
            revoked_certs=revoked_certs,
            next_update=next_update,
            distpoint=distpoint,
            delta_crl_indicator=delta_crl_indicator,
            freshest_crl=freshest_crl,
        )
        return self.sign_crl(tbs_crl)

    def sign_crl(self, tbs_crl: crl.TbsCertList) -> crl.CertificateList:
        signature = generic_sign(
            self.issuer_key, tbs_crl.dump(), self.signature_algo
        )

        return crl.CertificateList(
            {
                'tbs_cert_list': tbs_crl,
                'signature_algorithm': self.signature_algo,
                'signature': signature,
            }
        )

    @staticmethod
    def format_revoked_cert(
        serial: int,
        reason: Optional[crl.CRLReason],
        revocation_date: datetime,
        extensions: Optional[List[crl.CRLEntryExtension]] = None,
    ) -> crl.RevokedCertificate:
        extensions = list(extensions or ())
        if reason is not None:
            extensions.append(
                crl.CRLEntryExtension(
                    {'extn_id': 'crl_reason', 'extn_value': reason}
                )
            )
        return crl.RevokedCertificate(
            {
                'user_certificate': serial,
                'revocation_date': x509.Time({'general_time': revocation_date}),
                'crl_entry_extensions': extensions,
            }
        )

    def format_tbs_crl(
        self,
        crl_number: int,
        this_update: datetime,
        revoked_certs,
        next_update: datetime,
        distpoint: Optional[dict] = None,
        delta_crl_indicator: Optional[int] = None,
        freshest_crl: Optional[x509.CRLDistributionPoints] = None,
    ) -> crl.TbsCertList:
        extensions = [
            crl.TBSCertListExtension(
                {
                    'extn_id': 'crl_number',
                    'extn_value': core.Integer(crl_number),
                }
            ),
            crl.TBSCertListExtension(
                {
                    'extn_id': 'authority_key_identifier',
                    'extn_value': x509.AuthorityKeyIdentifier(
                        {'key_identifier': self.authority_key_identifier}
                    ),
                }
            ),
        ]
        if delta_crl_indicator is not None:
            extensions.append(
                crl.TBSCertListExtension(
                    {
                        'extn_id': 'delta_crl_indicator',
                        'critical': True,
                        'extn_value': core.Integer(delta_crl_indicator),
                    }
                )
            )
        extensions.extend(self.extra_crl_extensions)
        if freshest_crl is not None:
            extensions.append(
                crl.TBSCertListExtension(
                    {
                        'extn_id': 'freshest_crl',
                        'extn_value': freshest_crl,
                    }
                )
            )
        if distpoint is not None:
            extn_value = crl.IssuingDistributionPoint(distpoint)
            extensions.append(
                crl.TBSCertListExtension(
                    {
                        'extn_id': 'issuing_distribution_point',
                        'critical': True,
                        'extn_value': core.ParsableOctetString(
                            extn_value.dump()
                        ),
                    }
                )
            )
        revoked = crl.RevokedCertificates(revoked_certs)
        return crl.TbsCertList(
            {
                'version': 'v2',
                'signature': self.signature_algo,
                'issuer': self.issuer_name,
                'this_update': x509.Time({'general_time': this_update}),
                'next_update': x509.Time({'general_time': next_update}),
                'revoked_certificates': revoked,
                'crl_extensions': crl.TBSCertListExtensions(extensions),
            }
        )


def urls_as_names(*urls):
    return [
        x509.GeneralName({'uniform_resource_identifier': url}) for url in urls
    ]


def choose_signed_digest(
    digest_algo: str,
    pub_key: keys.PublicKeyInfo,
    signature_algo: Optional[str] = None,
):
    key_algo = pub_key.algorithm
    if signature_algo is None:
        if key_algo == 'rsa':
            signature_algo = digest_algo + '_rsa'
        elif key_algo == 'dsa':
            signature_algo = digest_algo + '_dsa'
        elif key_algo == 'ec':
            signature_algo = digest_algo + '_ecdsa'
        elif key_algo == 'ed25519':
            signature_algo = 'ed25519'
        elif key_algo == 'ed448':
            signature_algo = 'ed448'

    signature_algo_obj = algos.SignedDigestAlgorithm(
        {'algorithm': signature_algo}
    )
    if signature_algo == 'rsassa_pss':
        parameters = None
        if parameters is None:
            parameters = optimal_pss_params(pub_key, digest_algo)
        signature_algo_obj['parameters'] = parameters

    return signature_algo_obj


def issuer_match(cid: ocsp.CertId, candidate: x509.Certificate):
    # FIXME this doesn't really scale
    hash_algo = cid['hash_algorithm']['algorithm'].native

    # TODO implement the general case
    if hash_algo not in ('sha1', 'sha256'):
        raise NotImplementedError
    iss_name_hash = cid['issuer_name_hash'].native
    iss_key_hash = cid['issuer_key_hash'].native
    name_digest = getattr(candidate.subject, hash_algo)
    if name_digest != iss_name_hash:
        return False
    key_digest = getattr(candidate.public_key, hash_algo)
    return key_digest == iss_key_hash


class RevocationInfoInterface(abc.ABC):
    def get_issuer_cert(self) -> x509.Certificate:
        raise NotImplementedError

    def check_revocation_status(
        self, cid: ocsp.CertId, at_time: datetime
    ) -> Tuple[ocsp.CertStatus, List[ocsp.SingleResponseExtension]]:
        raise NotImplementedError


class SimpleOCSPResponder:
    def __init__(
        self,
        responder_cert: x509.Certificate,
        responder_key: keys.PrivateKeyInfo,
        signature_algo: algos.SignedDigestAlgorithm,
        at_time: datetime,
        revinfo_interface: RevocationInfoInterface,
        validity: Optional[timedelta] = timedelta(minutes=10),
        response_extensions: Optional[List[ocsp.ResponseDataExtension]] = None,
    ):
        self.responder_cert = responder_cert
        self.responder_key = responder_key
        self.signature_algo = signature_algo
        self.at_time = at_time
        self.validity = validity
        self.revinfo_interface = revinfo_interface
        self.response_extensions = response_extensions or []

    @staticmethod
    def build_error_response(error_status):
        return ocsp.OCSPResponse({'response_status': error_status})

    def format_single_ocsp_response(
        self, cid: ocsp.CertId, issuer_cert: x509.Certificate
    ) -> ocsp.SingleResponse:
        if not issuer_match(cid, issuer_cert):
            raise CertomancerServiceError("Responder is not authorised")

        revinfo_interface = self.revinfo_interface
        cert_status, exts = revinfo_interface.check_revocation_status(
            cid, self.at_time
        )

        response_data = {
            'cert_id': cid,
            'cert_status': cert_status,
            'this_update': self.at_time,
            'single_extensions': exts or None,
        }
        if self.validity is not None:
            response_data['next_update'] = self.at_time + self.validity
        return ocsp.SingleResponse(response_data)

    def build_ocsp_response(self, req: ocsp.OCSPRequest) -> ocsp.OCSPResponse:
        nonce_asn1 = req.nonce_value
        if nonce_asn1 is not None:
            nonce = nonce_asn1.native
        else:
            nonce = None
        requests = req['tbs_request']['request_list']
        issuer_cert = self.revinfo_interface.get_issuer_cert()
        err = SimpleOCSPResponder.build_error_response

        if len(requests) == 0:
            return err('malformed_request')

        responses = []
        for req_item in requests:
            cid: ocsp.CertId = req_item['req_cert']

            try:
                simple_resp = self.format_single_ocsp_response(cid, issuer_cert)
            except NotImplementedError:
                return err('internal_error')
            except CertomancerServiceError:
                return err('unauthorized')

            responses.append(simple_resp)
        return self.assemble_simple_ocsp_responses(responses, nonce=nonce)

    def assemble_simple_ocsp_responses(
        self,
        responses: List[ocsp.SingleResponse],
        nonce: Optional[bytes] = None,
    ):
        rdata = ocsp.ResponseData(
            {
                'responder_id': ocsp.ResponderId(
                    name='by_key', value=self.responder_cert.public_key.sha1
                ),
                'produced_at': self.at_time,
                'responses': responses,
            }
        )
        response_extensions = list(self.response_extensions)
        if nonce is not None:
            nonce_extension = ocsp.ResponseDataExtension(
                {'extn_id': 'nonce', 'extn_value': nonce}
            )
            response_extensions.append(nonce_extension)
        if response_extensions:
            rdata['response_extensions'] = response_extensions

        signature = generic_sign(
            self.responder_key, rdata.dump(), signature_algo=self.signature_algo
        )
        basic_resp = ocsp.BasicOCSPResponse(
            {
                'tbs_response_data': rdata,
                'signature_algorithm': self.signature_algo,
                'signature': signature,
                'certs': [self.responder_cert],
            }
        )
        response_bytes = ocsp.ResponseBytes(
            {
                'response_type': 'basic_ocsp_response',
                'response': core.ParsableOctetString(basic_resp.dump()),
            }
        )
        return ocsp.OCSPResponse(
            {'response_status': 'successful', 'response_bytes': response_bytes}
        )
