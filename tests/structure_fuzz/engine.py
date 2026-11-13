"""Fuzzing engine: fixed-seed runs, violation artefacts and minimisation.

The engine is transport-agnostic.  An *adapter* is any callable matching
:data:`Driver` that accepts a raw request body and returns an
:class:`AdapterResult` (HTTP status, body, or raised exception).  The same
engine therefore drives both the Werkzeug WSGI adapter and the aiohttp
handler without binding any sockets.
"""

import json
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from asn1crypto import core, ocsp, tsp

from .mutators import MAX_RESOURCE_BYTES
from .oracle import Verdict

# Deterministic seed for the default run.  Overridable through the
# CERTOMANCER_FUZZ_SEED environment variable for exploratory runs.
DEFAULT_SEED = 20261113
# Small default budget so the suite stays fast.  Scaled via env for deeper
# offline campaigns.
DEFAULT_CASE_LIMIT = 120
DEFAULT_MAX_BYTES_PER_RESPONSE = MAX_RESOURCE_BYTES


@dataclass
class AdapterResult:
    http_status: int
    body: Optional[bytes]
    exc: Optional[BaseException] = None


# A driver sends raw DER to one service entry point and reports what came back.
Driver = Callable[[bytes], AdapterResult]

# A classifier turns a transport result into a protocol-level Verdict.
Classifier = Callable[
    [int, Optional[bytes], Optional[BaseException]], 'Verdict'
]


@dataclass
class CaseOutcome:
    case_id: str
    description: str
    request_len: int
    response_len: int
    elapsed_ms: float
    verdict: Verdict


@dataclass
class FuzzReport:
    service: str
    adapter: str
    seed: int
    cases: List[CaseOutcome] = field(default_factory=list)
    violations: List[CaseOutcome] = field(default_factory=list)
    resource_breaches: List[CaseOutcome] = field(default_factory=list)
    total_elapsed_ms: float = 0.0

    @property
    def total_request_bytes(self) -> int:
        return sum(c.request_len for c in self.cases)

    @property
    def total_response_bytes(self) -> int:
        return sum(c.response_len for c in self.cases)

    def summary(self) -> dict:
        return {
            'service': self.service,
            'adapter': self.adapter,
            'seed': self.seed,
            'cases_run': len(self.cases),
            'violations': [
                {
                    'case_id': c.case_id,
                    'description': c.description,
                    'request_bytes': c.request_len,
                    'response_bytes': c.response_len,
                    'verdict': c.verdict.kind,
                    'detail': c.verdict.detail,
                }
                for c in self.violations
            ],
            'resource_breaches': [
                {
                    'case_id': c.case_id,
                    'request_bytes': c.request_len,
                    'response_bytes': c.response_len,
                }
                for c in self.resource_breaches
            ],
            'total_request_bytes': self.total_request_bytes,
            'total_response_bytes': self.total_response_bytes,
            'elapsed_ms': round(self.total_elapsed_ms, 2),
        }


class ArtifactStore:
    """Persists raw DER and minimal reproducers for signed-response bugs."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def save_violation(
        self,
        report: FuzzReport,
        case_id: str,
        description: str,
        original_der: bytes,
        minimal_der: bytes,
        verdict: Verdict,
        classifier: str,
    ) -> Path:
        safe_id = case_id.replace('/', '_')
        case_dir = self.root / f'{report.service}-{report.adapter}-{safe_id}'
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / 'original.der').write_bytes(original_der)
        (case_dir / 'minimal.der').write_bytes(minimal_der)
        metadata = {
            'service': report.service,
            'adapter': report.adapter,
            'case_id': case_id,
            'description': description,
            'classifier': classifier,
            'seed': report.seed,
            'verdict': verdict.kind,
            'detail': verdict.detail,
            'original_bytes': len(original_der),
            'minimal_bytes': len(minimal_der),
            'original_hex': original_der.hex(),
            'minimal_hex': minimal_der.hex(),
        }
        (case_dir / 'metadata.json').write_text(
            json.dumps(metadata, indent=2, sort_keys=True)
        )
        return case_dir


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def make_rng(seed: Optional[int] = None) -> random.Random:
    return random.Random(
        DEFAULT_SEED if seed is None else seed
    )


def run_campaign(
    service: str,
    adapter: str,
    classifier: Classifier,
    driver: Driver,
    cases: List[Tuple[str, str, bytes]],
    *,
    seed: Optional[int] = None,
    case_limit: Optional[int] = None,
    max_response_bytes: Optional[int] = None,
    artifacts: Optional[ArtifactStore] = None,
    minimizer: Optional[Callable[[bytes, Driver, Verdict], bytes]] = None,
) -> FuzzReport:
    """Execute a deterministic campaign and return a :class:`FuzzReport`."""
    resolved_seed = _env_int(
        'CERTOMANCER_FUZZ_SEED', DEFAULT_SEED if seed is None else seed
    )
    limit = _env_int(
        'CERTOMANCER_FUZZ_CASES',
        DEFAULT_CASE_LIMIT if case_limit is None else case_limit,
    )
    response_budget = _env_int(
        'CERTOMANCER_FUZZ_MAX_RESPONSE_BYTES',
        DEFAULT_MAX_BYTES_PER_RESPONSE
        if max_response_bytes is None
        else max_response_bytes,
    )

    report = FuzzReport(service=service, adapter=adapter, seed=resolved_seed)
    selected = cases[:limit]
    campaign_start = time.perf_counter()

    # lookup of the original generated body for artefact persistence
    bodies = {case_id: der for case_id, _desc, der in selected}
    descriptions = {case_id: desc for case_id, desc, _der in selected}

    for case_id, description, der in selected:
        start = time.perf_counter()
        result = driver(der)
        elapsed = (time.perf_counter() - start) * 1000.0
        verdict = classifier(
            result.http_status, result.body, result.exc
        )
        response_len = len(result.body or b'')
        outcome = CaseOutcome(
            case_id=case_id,
            description=description,
            request_len=len(der),
            response_len=response_len,
            elapsed_ms=elapsed,
            verdict=verdict,
        )
        report.cases.append(outcome)

        if response_len > response_budget:
            report.resource_breaches.append(outcome)
        if not verdict.ok:
            report.violations.append(outcome)
            if artifacts is not None:
                minimal = (
                    minimizer(der, driver, verdict)
                    if minimizer is not None
                    else der
                )
                artifacts.save_violation(
                    report,
                    case_id,
                    description,
                    der,
                    minimal,
                    verdict,
                    classifier=classifier.__name__,
                )

    report.total_elapsed_ms = (
        time.perf_counter() - campaign_start
    ) * 1000.0
    return report


# ---------------------------------------------------------------------------
# Minimisation
# ---------------------------------------------------------------------------

def _parseable(service: str, der: bytes) -> bool:
    cls = ocsp.OCSPRequest if service == 'ocsp' else tsp.TimeStampReq
    try:
        cls.load(der)
    except ValueError:
        return False
    return True


def _still_violates(
    service: str,
    driver: Driver,
    classifier,
    candidate: bytes,
    original: Verdict,
) -> bool:
    if not _parseable(service, candidate) or candidate is None:
        return False
    result = driver(candidate)
    new_verdict = classifier(
        result.http_status, result.body, result.exc
    )
    return new_verdict.kind == original.kind and not new_verdict.ok


def minimize_der(
    service: str,
    driver: Driver,
    classifier,
    original_der: bytes,
    original_verdict: Verdict,
) -> bytes:
    """Greedily shrink a violating request while preserving the violation.

    The strategy alternates two DER-aware reductions:

    1. drop whole top-level / nested components by re-serialising parsed
       structures with optional fields removed;
    2. shorten length-bearing payloads (hashes, nonces, digests) one size
       class at a time.

    Each candidate is only accepted if it still parses and still triggers the
    same signed-response violation, which guarantees the reproducer remains
    valid.
    """
    current = bytes(original_der)

    def accept(candidate: bytes) -> bool:
        nonlocal current
        if len(candidate) >= len(current):
            return False
        if _still_violates(
            service, driver, classifier, candidate, original_verdict
        ):
            current = candidate
            return True
        return False

    # Pass A: component dropping via structural reloads.
    for _ in range(4):
        progressed = False
        if service == 'ocsp':
            progressed |= _shrink_ocsp(accept, current)
        else:
            progressed |= _shrink_tsa(accept, current)
        if not progressed:
            break

    # Pass B: raw length-field shrinkage of remaining OCTET STRING payloads.
    progressed = True
    while progressed:
        progressed = False
        for idx in range(len(current)):
            if current[idx] != 0x04:  # OCTET STRING tag
                continue
            end = _tlv_end(current, idx)
            if end is None:
                continue
            header_len, content_len = _read_length(current, idx + 1)
            if header_len is None or content_len <= 1:
                continue
            content_start = idx + 1 + header_len
            new_len = content_len // 2
            candidate = (
                current[: idx + 1]
                + _encode_length(new_len)
                + current[content_start : content_start + new_len]
                + current[end:]
            )
            # rebuild the enclosing DER length hierarchy by re-dumping the
            # parsed object so outer length bytes stay consistent
            candidate = _recanonicalize(service, candidate)
            if candidate is not None and accept(candidate):
                progressed = True
                break
    return current


def _recanonicalize(service: str, der: bytes) -> Optional[bytes]:
    cls = ocsp.OCSPRequest if service == 'ocsp' else tsp.TimeStampReq
    try:
        return cls.load(der).dump()
    except (ValueError, OverflowError):
        return None


def _shrink_ocsp(accept, der: bytes) -> bool:
    try:
        req = ocsp.OCSPRequest.load(der)
    except ValueError:
        return False
    tbs = req['tbs_request']
    progressed = False

    requests = list(tbs['request_list'])
    if len(requests) > 1:
        shrunk = ocsp.OCSPRequest.load(der)
        shrunk['tbs_request']['request_list'] = ocsp.Requests(
            requests[: max(1, len(requests) // 2)]
        )
        progressed |= accept(shrunk.dump())

    try:
        exts = list(tbs['request_extensions'])
    except (ValueError, KeyError):
        exts = []
    if len(exts) > 1:
        shrunk = ocsp.OCSPRequest.load(der)
        shrunk['tbs_request']['request_extensions'] = (
            ocsp.TBSRequestExtensions(exts[: max(1, len(exts) // 2)])
        )
        progressed |= accept(shrunk.dump())

    if exts:
        tbs_now = ocsp.OCSPRequest.load(der)['tbs_request']
        shrunk_tbs = ocsp.TBSRequest(
            {
                'version': tbs_now['version'],
                'request_list': tbs_now['request_list'],
            }
        )
        progressed |= accept(
            ocsp.OCSPRequest({'tbs_request': shrunk_tbs}).dump()
        )
    return progressed


def _shrink_tsa(accept, der: bytes) -> bool:
    try:
        req = tsp.TimeStampReq.load(der)
    except ValueError:
        return False
    progressed = False

    if isinstance(req['nonce'], core.Integer):
        shrunk = tsp.TimeStampReq.load(der)
        del shrunk['nonce']
        progressed |= accept(shrunk.dump())

    if req['extensions'].native is not None:
        shrunk = tsp.TimeStampReq.load(der)
        del shrunk['extensions']
        progressed |= accept(shrunk.dump())

    if req['req_policy'].native is not None:
        shrunk = tsp.TimeStampReq.load(der)
        del shrunk['req_policy']
        progressed |= accept(shrunk.dump())

    if req['cert_req'].native is not None:
        shrunk = tsp.TimeStampReq.load(der)
        del shrunk['cert_req']
        progressed |= accept(shrunk.dump())
    return progressed


def _read_length(der: bytes, offset: int):
    if offset >= len(der):
        return None, None
    first = der[offset]
    if first < 0x80:
        return 1, first
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + 1 + num_bytes > len(der):
        return None, None
    length = int.from_bytes(
        der[offset + 1 : offset + 1 + num_bytes], 'big'
    )
    return 1 + num_bytes, length


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


def _tlv_end(der: bytes, offset: int) -> Optional[int]:
    header_len, content_len = _read_length(der, offset + 1)
    if header_len is None:
        return None
    end = offset + 1 + header_len + content_len
    return end if end <= len(der) else None
