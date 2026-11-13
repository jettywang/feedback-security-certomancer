"""Offline evaluation of RFC 5755 attribute certificates against holder PKCs.

The evaluator deliberately does *not* infer anything from the subject DN of a
candidate public-key certificate beyond what the holder syntax actually uses.
In particular, an ``entityName`` binding matches on the directory name, but a
``baseCertificateID`` / digest binding never inherits a role merely because two
certificates happen to carry the same subject string.

Decision pipeline (short-circuit on the first failure):

  1. cryptographic validity of the AC signature under the AA public key
  2. AC validity window at the reference time
  3. holder binding: *every* present holder component must match (AND)
  4. target restriction: the requested target must be in targetInformation

Only local files and standard crypto primitives are used; there is no network
access and no OCSP/CRL fetching.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from asn1crypto import cms, keys, x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

# Failure reason identifiers. They are stable strings so the expected-results
# table and any external harness can assert on them.
REASON_BAD_SIGNATURE = "bad_ac_signature"
REASON_EXPIRED = "outside_validity_window"
REASON_BASE_CERT_ID = "baseCertificateID_mismatch"
REASON_ENTITY_NAME = "entityName_mismatch"
REASON_SPKI_DIGEST = "spki_digest_mismatch"
REASON_CERT_DIGEST = "cert_digest_mismatch"
REASON_TARGET = "target_not_authorized"
REASON_NO_HOLDER_COMPONENT = "holder_has_no_recognized_component"

_RSA_PKCS1_ALGS = {
    "sha224_rsa": hashes.SHA224,
    "sha256_rsa": hashes.SHA256,
    "sha384_rsa": hashes.SHA384,
    "sha512_rsa": hashes.SHA512,
}
_ECDSA_ALGS = {
    "sha224_ecdsa": hashes.SHA224,
    "sha256_ecdsa": hashes.SHA256,
    "sha384_ecdsa": hashes.SHA384,
    "sha512_ecdsa": hashes.SHA512,
}


def _load_cryptography_public_key(public_key_info: keys.PublicKeyInfo):
    return load_der_public_key(public_key_info.dump())


@dataclass
class HolderMatchReport:
    """Detailed holder-binding outcome for one AC/candidate pair."""

    matches: bool
    checked_components: List[str] = field(default_factory=list)
    failures: List[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)


@dataclass
class AuthorizationDecision:
    ac_label: str
    candidate_label: str
    target: Optional[str]
    authorized: bool
    signature_valid: bool
    in_validity_window: bool
    holder_report: HolderMatchReport
    target_ok: Optional[bool]
    reasons: List[str] = field(default_factory=list)

    @property
    def primary_reason(self) -> Optional[str]:
        return self.reasons[0] if self.reasons else None


# --------------------------------------------------------------------------- #
# Signature verification
# --------------------------------------------------------------------------- #
def verify_ac_signature(ac: cms.AttributeCertificateV2, aa_cert: x509.Certificate) -> bool:
    """Verify the AC's signature against the AA certificate's public key."""
    algo_name = ac["signature_algorithm"]["algorithm"].native
    tbs_bytes = ac["ac_info"].dump()
    signature = ac["signature"].native
    public_key = _load_cryptography_public_key(aa_cert.public_key)

    try:
        if algo_name in _RSA_PKCS1_ALGS:
            public_key.verify(
                signature,
                tbs_bytes,
                padding.PKCS1v15(),
                _RSA_PKCS1_ALGS[algo_name](),
            )
        elif algo_name in _ECDSA_ALGS:
            public_key.verify(
                signature, tbs_bytes, ec.ECDSA(_ECDSA_ALGS[algo_name]())
            )
        else:
            raise NotImplementedError(f"unsupported AC signature algorithm {algo_name!r}")
    except (InvalidSignature, NotImplementedError):
        return False
    return True


# --------------------------------------------------------------------------- #
# Individual holder components
# --------------------------------------------------------------------------- #
def _match_base_certificate_id(holder: cms.Holder, candidate: x509.Certificate) -> bool:
    bci = holder["base_certificate_id"]
    if bci.native is None:
        return True  # component absent -> not evaluated
    if int(bci["serial"].native) != int(candidate.serial_number):
        return False
    # IssuerSerial.issuer is GeneralNames; RFC 5755: compare against the
    # candidate's issuer DN. At least one GeneralName must equal it. The
    # directoryName is implicitly tagged, so compare decoded Name values
    # (native) rather than raw DER bytes.
    candidate_issuer = candidate.issuer.native
    for general_name in bci["issuer"]:
        if general_name.name != "directory_name":
            continue
        if general_name.chosen.native == candidate_issuer:
            return True
    return False


def _match_entity_name(holder: cms.Holder, candidate: x509.Certificate) -> bool:
    entity_names = holder["entity_name"]
    if entity_names.native is None:
        return True
    candidate_subject = candidate.subject.native
    for general_name in entity_names:
        if general_name.name != "directory_name":
            continue
        if general_name.chosen.native == candidate_subject:
            return True
    return False


def _match_object_digest_info(holder: cms.Holder, candidate: x509.Certificate) -> Optional[str]:
    """Return None on match, otherwise the specific mismatch reason."""
    odi = holder["object_digest_info"]
    if odi.native is None:
        return None
    digest_algo = odi["digest_algorithm"]["algorithm"].native
    expected = odi["object_digest"].native
    object_type = odi["digested_object_type"].native

    if object_type == "public_key":
        # RFC 5755 section 7.3: hash the entire SubjectPublicKeyInfo DER.
        data = candidate.public_key.dump()
        mismatch = REASON_SPKI_DIGEST
    elif object_type == "public_key_cert":
        data = candidate.dump()
        mismatch = REASON_CERT_DIGEST
    else:
        raise NotImplementedError(f"unsupported DigestedObjectType {object_type!r}")

    actual = getattr(hashlib, digest_algo)(data).digest()
    return None if actual == expected else mismatch


def evaluate_holder(holder: cms.Holder, candidate: x509.Certificate) -> HolderMatchReport:
    """Apply RFC 5755 AND-semantics across every present holder component."""
    report = HolderMatchReport(matches=True)
    native = holder.native

    if native.get("base_certificate_id") is not None:
        report.checked_components.append("baseCertificateID")
        ok = _match_base_certificate_id(holder, candidate)
        report.details["baseCertificateID"] = ok
        if not ok:
            report.matches = False
            report.failures.append(REASON_BASE_CERT_ID)

    if native.get("entity_name") is not None:
        report.checked_components.append("entityName")
        ok = _match_entity_name(holder, candidate)
        report.details["entityName"] = ok
        if not ok:
            report.matches = False
            report.failures.append(REASON_ENTITY_NAME)

    if native.get("object_digest_info") is not None:
        object_type = holder["object_digest_info"]["digested_object_type"].native
        component = "objectDigestInfo:public_key" if object_type == "public_key" \
            else "objectDigestInfo:public_key_cert"
        report.checked_components.append(component)
        failure = _match_object_digest_info(holder, candidate)
        report.details[component] = failure is None
        if failure is not None:
            report.matches = False
            report.failures.append(failure)

    if not report.checked_components:
        report.matches = False
        report.failures.append(REASON_NO_HOLDER_COMPONENT)

    return report


# --------------------------------------------------------------------------- #
# Target restriction
# --------------------------------------------------------------------------- #
def _extract_targets(ac: cms.AttributeCertificateV2) -> List[x509.GeneralName]:
    names: List[x509.GeneralName] = []
    for ext in ac["ac_info"]["extensions"]:
        if ext["extn_id"].native != "target_information":
            continue
        for targets_group in ext["extn_value"].parsed:
            for target in targets_group:
                names.append(target.chosen)
    return names


def evaluate_target(ac: cms.AttributeCertificateV2, target_name: x509.Name) -> bool:
    """True when the target's directory name is listed in targetInformation.

    A target group is *not* expanded here: this suite only uses targetName
    entries, and silently treating a group as a name match would weaken the
    restriction.
    """
    target_value = target_name.native
    for general_name in _extract_targets(ac):
        if general_name.name != "directory_name":
            continue
        if general_name.chosen.native == target_value:
            return True
    return False


def ac_has_target_information(ac: cms.AttributeCertificateV2) -> bool:
    return any(
        ext["extn_id"].native == "target_information"
        for ext in ac["ac_info"]["extensions"]
    )


# --------------------------------------------------------------------------- #
# Top-level decision
# --------------------------------------------------------------------------- #
def _in_validity_window(ac: cms.AttributeCertificateV2, at_time: datetime) -> bool:
    period = ac["ac_info"]["att_cert_validity_period"].native
    not_before = period["not_before_time"]
    not_after = period["not_after_time"]
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    return not_before <= at_time <= not_after


def evaluate_authorization(
    ac: cms.AttributeCertificateV2,
    candidate: x509.Certificate,
    aa_cert: x509.Certificate,
    at_time: datetime,
    target_name: Optional[x509.Name] = None,
) -> AuthorizationDecision:
    reasons: List[str] = []

    signature_valid = verify_ac_signature(ac, aa_cert)
    if not signature_valid:
        reasons.append(REASON_BAD_SIGNATURE)

    in_window = _in_validity_window(ac, at_time)
    if not in_window:
        reasons.append(REASON_EXPIRED)

    holder_report = evaluate_holder(ac["ac_info"]["holder"], candidate)
    if not holder_report.matches:
        reasons.extend(holder_report.failures)

    target_ok: Optional[bool] = None
    if target_name is not None and ac_has_target_information(ac):
        target_ok = evaluate_target(ac, target_name)
        if not target_ok:
            reasons.append(REASON_TARGET)

    authorized = signature_valid and in_window and holder_report.matches and (
        target_ok is not False
    )
    return AuthorizationDecision(
        ac_label="",
        candidate_label="",
        target=target_name.human_friendly if target_name is not None else None,
        authorized=authorized,
        signature_valid=signature_valid,
        in_validity_window=in_window,
        holder_report=holder_report,
        target_ok=target_ok,
        reasons=reasons,
    )
