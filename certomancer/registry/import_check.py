"""
Preflight checks for certificates imported through ``certificate-file``.

Certomancer lets a certificate spec point at a pre-generated certificate.
That certificate is served verbatim wherever Certomancer would otherwise have
issued it. If the DER content disagrees with the spec, OCSP responders, CRL
repositories and other trust services keep answering questions based on the
spec, i.e. about a different certificate than the one clients actually see.

This module compares the DER content against the spec at load time, so that
such disagreements surface immediately instead of turning into trust service
responses about the wrong certificate.
"""

import hashlib
import logging
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from asn1crypto import keys, x509

from ..config_utils import ConfigurationError
from .common import CertLabel, EntityLabel

__all__ = [
    'ImportedCertificateCheck',
    'ImportedCertMismatch',
    'enforce_import_preflight',
    'run_import_preflight',
]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ImportedCertMismatch:
    """A single discrepancy between an imported certificate and its spec."""

    field: str
    """Certificate field or relationship that disagrees."""

    expected: str
    """Value implied by the Certomancer configuration."""

    actual: str
    """Value found in the imported certificate."""


class ImportedCertificateCheck:
    """
    Result of the preflight check for a single imported certificate.

    :attr:`mismatches` lists all discrepancies that were found.
    :attr:`affected_services` names the trust services in the architecture
    that answer queries based on the spec rather than the imported DER.
    :attr:`notes` records diagnostics for checks that could not be performed,
    e.g. because no corresponding key is available locally.
    """

    def __init__(
        self,
        label: CertLabel,
        certificate: x509.Certificate,
        mismatches: Iterable[ImportedCertMismatch],
        affected_services: Iterable[str],
        allow_mismatch: bool = False,
        notes: Iterable[str] = (),
    ):
        self.label = label
        self.certificate = certificate
        self.mismatches: List[ImportedCertMismatch] = list(mismatches)
        self.affected_services: List[str] = list(affected_services)
        self.allow_mismatch = allow_mismatch
        self.notes: List[str] = list(notes)

    @property
    def ok(self) -> bool:
        return not self.mismatches

    def describe(self) -> str:
        if self.ok:
            result = f"Imported certificate '{self.label}' matches its spec."
        else:
            lines = [
                f"Imported certificate '{self.label}' does not match its "
                f"certificate spec:"
            ]
            for m in self.mismatches:
                lines.append(
                    f"  - {m.field}: spec says {m.expected}, "
                    f"certificate has {m.actual}"
                )
            if self.affected_services:
                lines.append(
                    "  Trust services that answer based on the spec and would "
                    "therefore report on a different certificate: "
                    + "; ".join(self.affected_services)
                )
            lines.append(
                "  If the inconsistency is intentional (e.g. a negative test "
                "sample), set 'allow-import-mismatch: true' on the cert spec."
            )
            result = "\n".join(lines)
        if self.notes:
            result += "\n" + "\n".join(f"  Note: {n}" for n in self.notes)
        return result


def _format_name(name: x509.Name) -> str:
    try:
        return name.human_friendly
    except Exception:  # pragma: nocover
        return repr(name.native)


def _name_key(name: x509.Name):
    """
    Normalise a distinguished name for comparison.

    RFC 5280 defines name equality in terms of the *prepped* values of the
    attribute value assertions. ``asn1crypto`` exposes those via
    ``prepped_value``; comparing them lets an equivalent PrintableString
    encoding of an otherwise identical common name pass the check.
    """

    result = []
    for rdn in name.chosen:
        entries = []
        for tv in rdn:
            entries.append(
                (tv['type'].dotted, tv['type'].native, tv.prepped_value)
            )
        entries.sort()
        result.append(tuple(entries))
    return tuple(result)


def _spki_fingerprint(spki: keys.PublicKeyInfo):
    """
    Produce a stable fingerprint of a SubjectPublicKeyInfo value.

    The fingerprint covers the algorithm and the key material, while remaining
    insensitive to equivalent encodings of the same key.
    """

    algo = spki.algorithm
    parsed = None
    try:
        parsed = spki['public_key'].parsed
    except (ValueError, KeyError, AttributeError):  # pragma: nocover
        pass

    if algo == 'rsa' and isinstance(parsed, keys.RSAPublicKey):
        return (
            'rsa',
            parsed['modulus'].native,
            parsed['public_exponent'].native,
        )
    if algo == 'dsa' and isinstance(parsed, keys.DSAPublicKey):
        params = parsed['parameter']
        return (
            'dsa',
            params['p'].native,
            params['q'].native,
            params['g'].native,
            parsed['public_key'].native,
        )
    if algo == 'ec':
        params = spki['algorithm']['parameters']
        curve = params.native if params is not None else None
        return ('ec', curve, spki['public_key'].native)
    # Fallback: byte-for-byte comparison
    return ('raw', spki['algorithm'].dump(), spki['public_key'].dump())


def _describe_spki(spki: keys.PublicKeyInfo) -> str:
    """
    Produce a short, human-readable description of a key for diagnostics.
    """

    fingerprint = hashlib.sha256(spki.dump()).hexdigest()[:16]
    bits = ''
    try:
        bits = f" {spki.bit_size}-bit"
    except Exception:  # pragma: nocover
        pass
    curve = ''
    if spki.algorithm == 'ec':
        params = spki['algorithm']['parameters']
        if params is not None:
            curve = f" ({params.native})"
    return f"{spki.algorithm}{bits}{curve} key, SHA-256 {fingerprint}"


def _check_names(
    field: str, expected: x509.Name, actual: x509.Name
) -> Optional[ImportedCertMismatch]:
    if _name_key(expected) == _name_key(actual):
        return None
    return ImportedCertMismatch(
        field=field,
        expected=_format_name(expected),
        actual=_format_name(actual),
    )


def _check_signature(
    cert: x509.Certificate,
    candidates: Sequence[Tuple[keys.PublicKeyInfo, str]],
) -> Optional[ImportedCertMismatch]:
    """
    Verify that the imported certificate's signature was produced by one of
    the designated authority keys.

    Only the certificate's own ``tbsCertificate`` bytes and
    ``signatureAlgorithm`` are used, so this check does not depend on the rest
    of the spec being correct.
    """

    try:
        from cryptography import x509 as pyca_x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import (
            dsa,
            ec,
            ed448,
            ed25519,
            rsa,
        )
        from cryptography.hazmat.primitives.serialization import (
            load_der_public_key,
        )
    except ImportError:  # pragma: nocover
        logger.warning(
            "pyca/cryptography is unavailable; skipping signature preflight "
            "for imported certificate."
        )
        return None

    pyca_cert = pyca_x509.load_der_x509_certificate(cert.dump())
    signature = pyca_cert.signature
    tbs = pyca_cert.tbs_certificate_bytes
    sig_algo = pyca_cert.signature_algorithm_parameters
    hash_algo = pyca_cert.signature_hash_algorithm

    unexpected_errors = []
    for spki, source in candidates:
        try:
            public_key = load_der_public_key(spki.dump())
            if isinstance(public_key, rsa.RSAPublicKey):
                assert hash_algo is not None
                public_key.verify(signature, tbs, sig_algo, hash_algo)
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                if sig_algo is None:
                    assert hash_algo is not None
                    signature_algo_obj = ec.ECDSA(hash_algo)
                else:
                    signature_algo_obj = sig_algo
                public_key.verify(signature, tbs, signature_algo_obj)
            elif isinstance(public_key, dsa.DSAPublicKey):
                assert hash_algo is not None
                public_key.verify(signature, tbs, hash_algo)
            elif isinstance(
                public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)
            ):
                public_key.verify(signature, tbs)
            else:  # pragma: nocover
                unexpected_errors.append(
                    f"unsupported key type {type(public_key).__name__} "
                    f"({source})"
                )
                continue
        except InvalidSignature:
            continue
        except Exception as e:  # pragma: nocover
            unexpected_errors.append(f"{source}: {e}")
            continue
        return None

    expected = "a signature by " + " or ".join(
        source for _, source in candidates
    )
    if unexpected_errors:
        actual = (
            "an unverifiable signature (" + "; ".join(unexpected_errors) + ")"
        )
    else:
        actual = "a signature that does not verify against that key"
    return ImportedCertMismatch(
        field='signature', expected=expected, actual=actual
    )


def _services_for_issuer(arch, issuer: EntityLabel) -> List[str]:
    """
    Enumerate the trust services that answer queries using certificates
    issued by ``issuer``.
    """

    result = []
    registry = arch.service_registry
    for info in registry.list_ocsp_responders():
        if info.for_issuer == issuer and not info.is_aa_responder:
            result.append(f"OCSP responder '{info.label}'")
    for info in registry.list_crl_repos():
        if info.for_issuer == issuer:
            result.append(f"CRL repository '{info.label}'")
    for info in registry.list_cert_repos():
        if info.for_issuer == issuer:
            result.append(f"certificate repository '{info.label}'")
    return result


def _services_for_label(arch, label: CertLabel) -> List[str]:
    """
    Enumerate the trust services that directly reference ``label``, e.g. as a
    responder certificate or a TSA signing certificate.
    """

    result = []
    registry = arch.service_registry
    for info in registry.list_ocsp_responders():
        if label in (info.responder_cert, info.issuer_cert):
            result.append(f"OCSP responder '{info.label}'")
    for info in registry.list_crl_repos():
        if info.issuer_cert == label:
            result.append(f"CRL repository '{info.label}'")
    for info in registry.list_cert_repos():
        if info.issuer_cert == label:
            result.append(f"certificate repository '{info.label}'")
    for info in registry.list_time_stamping_services():
        if info.signing_cert == label or label in info.certs_to_embed:
            result.append(f"time stamping service '{info.label}'")
    return result


def _dedupe(items: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _resolve_expected_key(arch, key_label, notes: List[str], role: str):
    try:
        return arch.key_set[key_label].public_key_info
    except Exception as e:
        notes.append(
            f"the {role} key '{key_label}' is not available in the key set; "
            f"the corresponding check was skipped ({e})"
        )
        return None


def _issuer_spki(
    arch, issuer_label: CertLabel, notes: List[str]
) -> Optional[keys.PublicKeyInfo]:
    """
    Retrieve the public key of the certificate that serves as ``issuer_label``.

    Imported certificates are read from the certificate cache; for generated
    certificates we use the subject key of the corresponding spec. That avoids
    having to sign the issuer certificate during the preflight.
    """

    cached = arch._cert_cache.get(issuer_label)
    if cached is not None:
        return cached['tbs_certificate']['subject_public_key_info']

    try:
        issuer_spec = arch.get_cert_spec(issuer_label)
    except Exception as e:
        notes.append(
            f"issuer certificate spec '{issuer_label}' is unavailable; the "
            f"issuing relationship was only checked against the configured "
            f"authority key ({e})"
        )
        return None

    try:
        return arch.key_set[issuer_spec.subject_key].public_key_info
    except Exception as e:
        notes.append(
            f"the subject key of issuer cert '{issuer_label}' is not "
            f"available locally; the issuing relationship could not be "
            f"checked against it ({e})"
        )
        return None


def _find_serial_collisions(arch, label, issuer, actual_serial):
    """
    Look for other certificate specs whose effective issuer/serial pair
    coincides with the imported certificate's.

    OCSP's ``CertID`` lookup and CRL entries are keyed on the issuer and the
    serial number of the certificate actually served, so a collision makes
    Certomancer answer about a different certificate than the one a client
    asked about.
    """

    collisions = []
    for other_label, other_spec in arch._cert_specs.items():
        if other_label == label or other_spec.issuer != issuer:
            continue
        cached = arch._cert_cache.get(other_label)
        if cached is not None:
            other_serial = cached.serial_number
        else:
            other_serial = other_spec.serial
        if other_serial == actual_serial:
            collisions.append(other_label)
    return collisions


def run_import_preflight(
    arch,
    label: CertLabel,
    certificate: x509.Certificate,
    spec,
) -> ImportedCertificateCheck:
    """
    Compare a certificate imported through ``certificate-file`` with its
    spec.

    :param arch:
        The :class:`.PKIArchitecture` being built. Imported certificates have
        already been loaded into the certificate cache at this point.
    :param label:
        Label of the certificate spec.
    :param certificate:
        Certificate loaded from disk.
    :param spec:
        :class:`.CertificateSpec` describing the certificate.
    :return:
        An :class:`.ImportedCertificateCheck` describing the outcome.
    """

    mismatches: List[ImportedCertMismatch] = []
    notes: List[str] = []

    tbs = certificate['tbs_certificate']

    expected_subject = arch.entities[spec.subject]
    subject_mismatch = _check_names('subject', expected_subject, tbs['subject'])
    if subject_mismatch is not None:
        mismatches.append(subject_mismatch)

    expected_issuer = arch.entities[spec.issuer]
    issuer_mismatch = _check_names('issuer', expected_issuer, tbs['issuer'])
    if issuer_mismatch is not None:
        mismatches.append(issuer_mismatch)

    actual_serial = tbs['serial_number'].native
    if actual_serial != spec.serial:
        # A DER serial that matches some *other* spec's effective serial is
        # especially dangerous: a client looking at the imported DER would
        # map onto the other spec, so OCSP/CRL would report the other
        # certificate's status.
        other = _find_serial_collisions(arch, label, spec.issuer, actual_serial)
        detail = ''
        if other:
            detail = (
                f" (this DER serial belongs to "
                f"{', '.join(repr(c) for c in other)})"
            )
        mismatches.append(
            ImportedCertMismatch(
                field='serial number',
                expected=hex(spec.serial),
                actual=hex(actual_serial) + detail,
            )
        )
    else:
        collisions = _find_serial_collisions(
            arch, label, spec.issuer, actual_serial
        )
        if collisions:
            mismatches.append(
                ImportedCertMismatch(
                    field='serial number',
                    expected=f"a serial number unique within issuer "
                    f"'{spec.issuer}'",
                    actual=f"{hex(actual_serial)}, which is also used by "
                    f"{', '.join(repr(c) for c in collisions)}",
                )
            )

    actual_spki = tbs['subject_public_key_info']
    expected_spki = _resolve_expected_key(
        arch, spec.subject_key, notes, 'subject'
    )
    if expected_spki is not None and (
        _spki_fingerprint(actual_spki) != _spki_fingerprint(expected_spki)
    ):
        mismatches.append(
            ImportedCertMismatch(
                field='subject public key info',
                expected=_describe_spki(expected_spki),
                actual=_describe_spki(actual_spki),
            )
        )

    # Establish the signing relationship the spec selects.
    #
    # The authoritative check is against the configured authority key, since
    # that is the key Certomancer would have used to sign this certificate.
    # Only when no local key material exists (e.g. a fully external chain) do
    # we fall back to the imported issuer certificate, and then to a
    # self-signature for self-issued certificates.
    authority_spki = _resolve_expected_key(
        arch, spec.authority_key, notes, 'authority'
    )
    issuer_label = None
    try:
        issuer_label = spec.resolve_issuer_cert(arch)
    except Exception:
        issuer_label = None

    candidates = []
    if authority_spki is not None:
        candidates.append(
            (authority_spki, f"the authority key '{spec.authority_key}'")
        )
    else:
        issuer_spki = None
        if issuer_label is not None and issuer_label != label:
            issuer_spki = _issuer_spki(arch, issuer_label, notes)
        elif issuer_label == label or spec.self_issued:
            issuer_spki = actual_spki

        if issuer_spki is not None:
            source = (
                f"the subject key of issuer cert '{issuer_label}'"
                if issuer_label is not None and issuer_label != label
                else 'the imported certificate itself'
            )
            candidates.append((issuer_spki, source))

    if not candidates:
        notes.append(
            "no local authority key or imported issuer certificate was "
            "available; the signature/issuance relationship was not checked"
        )
    else:
        sig_mismatch = _check_signature(certificate, candidates)
        if sig_mismatch is not None:
            mismatches.append(sig_mismatch)

    # If an issuer certificate is configured and its subject key differs from
    # the authority key, the spec alleges an issuance relationship that
    # Certomancer's own issuer certificate contradicts. OCSP and CRL use the
    # issuer certificate's key hash, so report this explicitly.
    if (
        authority_spki is not None
        and issuer_label is not None
        and issuer_label != label
    ):
        issuer_spki = _issuer_spki(arch, issuer_label, notes)
        if issuer_spki is not None and (
            _spki_fingerprint(issuer_spki) != _spki_fingerprint(authority_spki)
        ):
            mismatches.append(
                ImportedCertMismatch(
                    field='issuer key relationship',
                    expected=f"issuer cert '{issuer_label}' to have the "
                    f"authority key '{spec.authority_key}' as its subject key",
                    actual=f"issuer cert '{issuer_label}' has "
                    f"{_describe_spki(issuer_spki)}, while the authority key "
                    f"is {_describe_spki(authority_spki)}",
                )
            )

    affected_services = _dedupe(
        _services_for_issuer(arch, spec.issuer)
        + _services_for_label(arch, label)
    )

    return ImportedCertificateCheck(
        label=label,
        certificate=certificate,
        mismatches=mismatches,
        affected_services=affected_services,
        allow_mismatch=spec.allow_import_mismatch,
        notes=notes,
    )


def enforce_import_preflight(check: ImportedCertificateCheck):
    """
    Raise a :class:`.ConfigurationError` when the preflight check failed,
    unless the spec explicitly tolerates mismatches. In the latter case the
    diagnostics are logged so the inconsistency remains visible.
    """

    if check.ok:
        return
    if check.allow_mismatch:
        logger.warning(
            "Imported certificate '%s' was accepted despite mismatches "
            "because allow-import-mismatch is set (%s). Run the "
            "'preflight' CLI command for details.",
            check.label,
            '; '.join(
                f"{m.field}: spec says {m.expected}, "
                f"certificate has {m.actual}"
                for m in check.mismatches
            ),
        )
        return
    raise ConfigurationError(check.describe())
