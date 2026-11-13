"""Response oracles for the OCSP / TSA structure fuzzer.

The central property under test is:

    a semantically contradictory (but ASN.1-parseable) request must never
    cause the service to emit a *signed* success response.

HTTP-level errors, framework exceptions and protocol-level rejection statuses
all count as safe refusals.  The oracle therefore inspects the decoded
protocol payload rather than treating every non-200 HTTP response as a pass.
"""

from dataclasses import dataclass
from typing import Optional

from asn1crypto import core, ocsp, tsp

# OCSP response statuses that explicitly refuse to produce a signed basic
# response (RFC 6960 section 4.2.1).
OCSP_REFUSAL_STATUSES = frozenset(
    (
        'malformed_request',
        'internal_error',
        'try_later',
        'sig_required',
        'unauthorized',
    )
)

# PKIStatus values that do not carry a signed timeStampToken (RFC 3161
# section 2.4.2).
TSA_REFUSAL_STATUSES = frozenset(('rejection', 'waiting'))


@dataclass(frozen=True)
class Verdict:
    kind: str  # one of 'signed', 'refused', 'parse_error', 'framework_error'
    detail: str
    signed: bool

    @property
    def ok(self) -> bool:
        return not self.signed


def _has_signature_bit_string(der: bytes) -> bool:
    """Cheap structural check: a signed token contains a BIT STRING payload.

    Used as a defence-in-depth signal alongside the schema-level status
    inspection.
    """
    try:
        core.BitString.load  # noqa: B018 (attribute probe for older runtimes)
    except AttributeError:  # pragma: no cover
        return False
    return b'\x03' in der


def classify_ocsp(
    http_status: int,
    body: Optional[bytes],
    exc: Optional[BaseException],
) -> Verdict:
    if exc is not None:
        return Verdict(
            'framework_error', f'{type(exc).__name__}: {exc}', signed=False
        )
    if body is None:
        return Verdict(
            'framework_error',
            f'HTTP {http_status} with empty body',
            signed=False,
        )
    try:
        response = ocsp.OCSPResponse.load(body)
    except ValueError as parse_exc:
        return Verdict(
            'parse_error', f'unparseable OCSPResponse: {parse_exc}', False
        )

    status = response['response_status'].native
    if status == 'successful':
        response_bytes = response['response_bytes']
        if response_bytes.native is None:
            return Verdict(
                'signed',
                'successful status without response_bytes (invalid)',
                True,
            )
        basic = response_bytes['response'].parsed
        signature = basic['signature'].native
        if not signature:
            return Verdict(
                'signed',
                'successful basic response with empty signature',
                True,
            )
        return Verdict(
            'signed',
            f'signed basic OCSP response ({len(signature)} byte signature)',
            True,
        )
    if status in OCSP_REFUSAL_STATUSES:
        return Verdict('refused', f'OCSP status {status}', False)
    return Verdict(
        'parse_error', f'unknown OCSP response status {status}', False
    )


def classify_tsa(
    http_status: int,
    body: Optional[bytes],
    exc: Optional[BaseException],
) -> Verdict:
    if exc is not None:
        return Verdict(
            'framework_error', f'{type(exc).__name__}: {exc}', signed=False
        )
    if body is None:
        return Verdict(
            'framework_error',
            f'HTTP {http_status} with empty body',
            signed=False,
        )
    try:
        response = tsp.TimeStampResp.load(body)
    except ValueError as parse_exc:
        return Verdict(
            'parse_error', f'unparseable TimeStampResp: {parse_exc}', False
        )

    status_info = response['status']
    status = status_info['status'].native
    token = response['time_stamp_token']
    has_signed_token = (
        token.native is not None
        and token['content_type'].native == 'signed_data'
    )
    if status in ('granted', 'granted_with_mods'):
        if not has_signed_token:
            return Verdict(
                'signed',
                f'{status} status without a signedData timeStampToken '
                '(invalid)',
                True,
            )
        signed_data = token['content']
        signer_infos = list(signed_data['signer_infos'])
        if not signer_infos or not signer_infos[0]['signature'].native:
            return Verdict(
                'signed',
                f'{status} token with empty SignerInfo signature',
                True,
            )
        sig_len = len(signer_infos[0]['signature'].native)
        return Verdict(
            'signed', f'signed TST token ({sig_len} byte signature)', True
        )
    if status in TSA_REFUSAL_STATUSES:
        if has_signed_token and _has_signature_bit_string(body):
            return Verdict(
                'signed',
                f'{status} response nevertheless carries a signedData '
                'timeStampToken',
                True,
            )
        failure_info = status_info['fail_info'].native
        return Verdict(
            'refused',
            f'TSA status {status} (fail_info={failure_info})',
            False,
        )
    return Verdict(
        'parse_error', f'unknown TSA PKIStatus {status}', False
    )
