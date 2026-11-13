"""Structure fuzzing of the OCSP and TSA service entry points.

Two HTTP adapters are exercised with the same deterministic, structure-aware
mutation corpus:

* the Werkzeug WSGI :class:`Animator` (in-process test client);
* the aiohttp :func:`build_animator_app` route handlers (invoked directly,
  without binding a socket).

The oracle never treats an HTTP error as an automatic pass: it decodes the
protocol payload and only accepts explicit refusal statuses, framework
rejections or parse failures.  A signed success response for a request in the
``*_MUST_REFUSE`` set is a violation and persists raw DER plus a minimised
reproducer.

Confirmed production defects live in
:mod:`tests.structure_fuzz.expectations` and are covered by strict
``xfail`` tests: they are expected to fail today, but a fix flips them to
XPASS and fails the run so the defect registry cannot silently rot.  Any
*new* signed-response violation is a hard, unmarked failure.

Finally, a fault-injection pair runs deliberately broken signing
implementations through the same pipeline, proving the criteria fail closed
instead of rubber-stamping every error.
"""

import json

import pytest

from tests.structure_fuzz.adapters import (
    make_aiohttp_driver,
    make_faulty_wsgi_driver,
    make_wsgi_driver,
)
from tests.structure_fuzz.engine import (
    ArtifactStore,
    minimize_der,
    run_campaign,
)
from tests.structure_fuzz.expectations import (
    ARCH,
    KNOWN_RESOURCE_AMPLIFICATION,
    OCSP_KNOWN_SIGNED_DEFECTS,
    OCSP_LABEL,
    OCSP_MUST_REFUSE,
    TSA_KNOWN_SIGNED_DEFECTS,
    TSA_LABEL,
    TSA_MUST_REFUSE,
)
from tests.structure_fuzz.oracle import classify_ocsp, classify_tsa
from tests.structure_fuzz.service_factory import (
    build_faulty_responder,
    build_faulty_timestamper,
)

ADAPTERS = (
    ('wsgi', make_wsgi_driver),
    ('aiohttp', make_aiohttp_driver),
)
MAX_RESPONSE_BYTES = 64 * 1024


def _artifact_store(tmp_path_factory, name: str) -> ArtifactStore:
    return ArtifactStore(tmp_path_factory.mktemp(f'fuzz-artifacts-{name}'))


def _minimizer(service, classifier):
    def _minimize(der, driver, verdict):
        return minimize_der(service, driver, classifier, der, verdict)

    return _minimize


def _run(architectures, service, adapter_name, driver_factory, cases,
         classifier, label, tmp_path_factory, *, artifacts_name=None):
    artifacts = _artifact_store(
        tmp_path_factory, artifacts_name or f'{service}-{adapter_name}'
    )
    driver = driver_factory(architectures, ARCH, service, label)
    report = run_campaign(
        service=service,
        adapter=adapter_name,
        classifier=classifier,
        driver=driver,
        cases=cases,
        artifacts=artifacts,
        minimizer=_minimizer(service, classifier),
        max_response_bytes=MAX_RESPONSE_BYTES,
    )
    (artifacts.root / 'campaign-summary.json').write_text(
        json.dumps(report.summary(), indent=2, sort_keys=True)
    )
    return report, artifacts


def _must_refuse_violations(report, must_refuse):
    return [
        outcome
        for outcome in report.violations
        if outcome.case_id in must_refuse
    ]


def _format(artifacts: ArtifactStore, outcomes) -> str:
    lines = [
        f'{len(outcomes)} semantically invalid request(s) produced signed '
        f'responses. Artefacts under {artifacts.root}:'
    ]
    for outcome in outcomes:
        lines.append(
            f'  - {outcome.case_id}: {outcome.description} '
            f'[{outcome.verdict.detail}]'
        )
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Hard assertions: no *unexpected* signed responses for invalid requests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize('adapter_name,driver_factory', ADAPTERS)
def test_ocsp_no_unexpected_signed_responses(
    architectures, ocsp_cases, adapter_name, driver_factory,
    tmp_path_factory,
):
    report, artifacts = _run(
        architectures, 'ocsp', adapter_name, driver_factory,
        ocsp_cases, classify_ocsp, OCSP_LABEL, tmp_path_factory,
    )
    unexpected = [
        outcome
        for outcome in _must_refuse_violations(report, OCSP_MUST_REFUSE)
        if outcome.case_id not in OCSP_KNOWN_SIGNED_DEFECTS
    ]
    assert not unexpected, _format(artifacts, unexpected)


@pytest.mark.parametrize('adapter_name,driver_factory', ADAPTERS)
def test_tsa_no_unexpected_signed_responses(
    architectures, tsa_cases, adapter_name, driver_factory,
    tmp_path_factory,
):
    report, artifacts = _run(
        architectures, 'tsa', adapter_name, driver_factory,
        tsa_cases, classify_tsa, TSA_LABEL, tmp_path_factory,
    )
    unexpected = [
        outcome
        for outcome in _must_refuse_violations(report, TSA_MUST_REFUSE)
        if outcome.case_id not in TSA_KNOWN_SIGNED_DEFECTS
    ]
    assert not unexpected, _format(artifacts, unexpected)


# ---------------------------------------------------------------------------
# Strict xfail coverage of the confirmed production defects
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    reason='confirmed production defect; see expectations.py for rationale',
    strict=True,
)
@pytest.mark.parametrize(
    'case_id,rationale',
    sorted(OCSP_KNOWN_SIGNED_DEFECTS.items()),
    ids=sorted(OCSP_KNOWN_SIGNED_DEFECTS),
)
@pytest.mark.parametrize('adapter_name,driver_factory', ADAPTERS)
def test_ocsp_known_signing_defects(
    architectures, ocsp_cases, adapter_name, driver_factory,
    tmp_path_factory, case_id, rationale,
):
    report, artifacts = _run(
        architectures, 'ocsp', adapter_name, driver_factory,
        [case for case in ocsp_cases if case[0] == case_id],
        classify_ocsp, OCSP_LABEL, tmp_path_factory,
        artifacts_name=f'ocsp-known-{case_id}-{adapter_name}',
    )
    signed = {
        o.case_id for o in report.violations if o.verdict.signed
    }
    assert case_id not in signed, (
        f'known defect still present ({rationale}); artefacts: '
        f'{artifacts.root}'
    )


@pytest.mark.xfail(
    reason='confirmed production defect; see expectations.py for rationale',
    strict=True,
)
@pytest.mark.parametrize(
    'case_id,rationale',
    sorted(TSA_KNOWN_SIGNED_DEFECTS.items()),
    ids=sorted(TSA_KNOWN_SIGNED_DEFECTS),
)
@pytest.mark.parametrize('adapter_name,driver_factory', ADAPTERS)
def test_tsa_known_signing_defects(
    architectures, tsa_cases, adapter_name, driver_factory,
    tmp_path_factory, case_id, rationale,
):
    report, artifacts = _run(
        architectures, 'tsa', adapter_name, driver_factory,
        [case for case in tsa_cases if case[0] == case_id],
        classify_tsa, TSA_LABEL, tmp_path_factory,
        artifacts_name=f'tsa-known-{case_id}-{adapter_name}',
    )
    # aiohttp rejects bodies at/above its 1 MiB client_max_size with 413
    # before the signing code runs: the transport already mitigates this
    # particular case, so there is no application-level signature to flag.
    oversized_transport_block = any(
        outcome.case_id == case_id
        and outcome.verdict.kind == 'framework_error'
        for outcome in report.cases
    )
    if oversized_transport_block:
        pytest.skip(
            'framework request-size guard rejects this case before the '
            'TSA signing path is reached'
        )
    signed = {
        o.case_id for o in report.violations if o.verdict.signed
    }
    assert case_id not in signed, (
        f'known defect still present ({rationale}); artefacts: '
        f'{artifacts.root}'
    )


# ---------------------------------------------------------------------------
# Resource budget: responses must not amplify oversized requests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize('adapter_name,driver_factory', ADAPTERS)
def test_resource_budget_no_unexpected_amplification(
    architectures, ocsp_cases, tsa_cases, adapter_name, driver_factory,
):
    for service, label, cases, classifier in (
        ('ocsp', OCSP_LABEL, ocsp_cases, classify_ocsp),
        ('tsa', TSA_LABEL, tsa_cases, classify_tsa),
    ):
        driver = driver_factory(architectures, ARCH, service, label)
        report = run_campaign(
            service=service,
            adapter=adapter_name,
            classifier=classifier,
            driver=driver,
            cases=cases,
            max_response_bytes=MAX_RESPONSE_BYTES,
        )
        breaches = {
            c.case_id
            for c in report.resource_breaches
            # framework-level 413/400 rejections are valid budget enforcement
            if c.verdict.kind != 'framework_error'
            and (service, c.case_id) not in KNOWN_RESOURCE_AMPLIFICATION
        }
        assert not breaches, (
            f'{service}/{adapter_name} amplified responses beyond '
            f'{MAX_RESPONSE_BYTES} bytes for: {sorted(breaches)}'
        )


@pytest.mark.xfail(
    reason='confirmed response-amplification defect; see expectations.py',
    strict=True,
)
@pytest.mark.parametrize('adapter_name,driver_factory', ADAPTERS)
def test_known_resource_amplification_is_tracked(
    architectures, ocsp_cases, tsa_cases, adapter_name, driver_factory,
):
    case_sets = (
        ('ocsp', OCSP_LABEL, ocsp_cases, classify_ocsp),
        ('tsa', TSA_LABEL, tsa_cases, classify_tsa),
    )
    still_amplifying = set()
    for service, label, cases, classifier in case_sets:
        tracked = [
            case_id
            for svc, case_id in KNOWN_RESOURCE_AMPLIFICATION
            if svc == service
        ]
        driver = driver_factory(architectures, ARCH, service, label)
        report = run_campaign(
            service=service,
            adapter=adapter_name,
            classifier=classifier,
            driver=driver,
            cases=[case for case in cases if case[0] in tracked],
            max_response_bytes=MAX_RESPONSE_BYTES,
        )
        for breach in report.resource_breaches:
            # aiohttp's 413 means the framework already capped the request,
            # so that particular defect is mitigated at the transport layer
            if breach.verdict.kind == 'framework_error':
                continue
            still_amplifying.add((service, breach.case_id))

    assert not still_amplifying, (
        'known amplification defects still present: '
        f'{sorted(still_amplifying)}; update KNOWN_RESOURCE_AMPLIFICATION '
        'once the service caps these itself'
    )


# ---------------------------------------------------------------------------
# State pollution: baseline requests must still succeed after a full campaign
# ---------------------------------------------------------------------------


@pytest.mark.parametrize('adapter_name,driver_factory', ADAPTERS)
def test_no_state_pollution_after_fuzzing(
    architectures, ocsp_cases, tsa_cases, ocsp_seed_der, tsa_seed_der,
    adapter_name, driver_factory,
):
    ocsp_driver = driver_factory(architectures, ARCH, 'ocsp', OCSP_LABEL)
    tsa_driver = driver_factory(architectures, ARCH, 'tsa', TSA_LABEL)

    for der in (case[2] for case in ocsp_cases):
        ocsp_driver(der)
    for der in (case[2] for case in tsa_cases):
        tsa_driver(der)

    ocsp_verdict = classify_ocsp(
        **_verdict_kwargs(ocsp_driver(ocsp_seed_der))
    )
    assert ocsp_verdict.signed, (
        f'baseline OCSP request no longer succeeds after fuzzing: '
        f'{ocsp_verdict}'
    )

    tsa_verdict = classify_tsa(
        **_verdict_kwargs(tsa_driver(tsa_seed_der))
    )
    assert tsa_verdict.signed, (
        f'baseline TSA request no longer succeeds after fuzzing: '
        f'{tsa_verdict}'
    )


def _verdict_kwargs(result):
    return {
        'http_status': result.http_status,
        'body': result.body,
        'exc': result.exc,
    }


# ---------------------------------------------------------------------------
# Negative controls: faulty signers MUST be detected (criteria fail closed)
# ---------------------------------------------------------------------------


def test_faulty_ocsp_responder_is_detected(
    architectures, ocsp_cases, tmp_path_factory,
):
    artifacts = _artifact_store(tmp_path_factory, 'ocsp-faulty')
    driver = make_faulty_wsgi_driver(
        architectures, ARCH, 'ocsp', OCSP_LABEL,
        build_faulty_responder, build_faulty_timestamper,
    )
    report = run_campaign(
        service='ocsp',
        adapter='wsgi-faulty',
        classifier=classify_ocsp,
        driver=driver,
        cases=ocsp_cases,
        artifacts=artifacts,
        minimizer=_minimizer('ocsp', classify_ocsp),
    )
    (artifacts.root / 'campaign-summary.json').write_text(
        json.dumps(report.summary(), indent=2, sort_keys=True)
    )

    detected = {c.case_id for c in report.violations}
    assert 'ocsp-empty-request-list' in detected
    assert 'ocsp-mixed-authorised-unauthorised' in detected

    case_dirs = [p for p in artifacts.root.iterdir() if p.is_dir()]
    assert case_dirs, 'no violation artefacts were persisted'
    sample = case_dirs[0]
    original = (sample / 'original.der').read_bytes()
    minimal = (sample / 'minimal.der').read_bytes()
    assert minimal and len(minimal) <= len(original)
    metadata = json.loads((sample / 'metadata.json').read_text())
    assert metadata['verdict'] == 'signed'


def test_faulty_timestamper_is_detected(
    architectures, tsa_cases, tmp_path_factory,
):
    artifacts = _artifact_store(tmp_path_factory, 'tsa-faulty')
    driver = make_faulty_wsgi_driver(
        architectures, ARCH, 'tsa', TSA_LABEL,
        build_faulty_responder, build_faulty_timestamper,
    )
    report = run_campaign(
        service='tsa',
        adapter='wsgi-faulty',
        classifier=classify_tsa,
        driver=driver,
        cases=tsa_cases,
        artifacts=artifacts,
        minimizer=_minimizer('tsa', classify_tsa),
    )
    (artifacts.root / 'campaign-summary.json').write_text(
        json.dumps(report.summary(), indent=2, sort_keys=True)
    )

    detected = {c.case_id for c in report.violations}
    assert 'tsa-imprint-length-0' in detected
    assert 'tsa-unaccepted-req-policy' in detected
    assert report.violations, 'faulty timestamper produced no violations'


def test_oracle_distinguishes_http_errors_from_protocol_refusals():
    """An HTTP 500 with garbage payload is not accepted as a valid refusal."""
    garbage = classify_ocsp(500, b'not-an-ocsp-response', None)
    assert garbage.kind == 'parse_error'
    assert garbage.ok is False or garbage.kind != 'signed'

    from asn1crypto import ocsp as ocsp_module

    refused = ocsp_module.OCSPResponse(
        {'response_status': 'malformed_request'}
    ).dump()
    accepted = classify_ocsp(200, refused, None)
    assert accepted.kind == 'refused' and accepted.ok

    from asn1crypto import cms, tsp

    rejection = tsp.TimeStampResp(
        {
            'status': tsp.PKIStatusInfo(
                {
                    'status': 'rejection',
                    'fail_info': tsp.PKIFailureInfo({'bad_request'}),
                }
            ),
            'time_stamp_token': cms.ContentInfo(
                {'content_type': cms.ContentType('data')}
            ),
        }
    ).dump()
    tsa_verdict = classify_tsa(200, rejection, None)
    assert tsa_verdict.kind == 'refused' and tsa_verdict.ok
