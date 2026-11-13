from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from asn1crypto import core, crl, x509

from certomancer.config_utils import ConfigurationError
from certomancer.integrations.animator import Animator, AnimatorArchStore
from certomancer.registry import (
    ArchLabel,
    CertomancerConfig,
    EntityLabel,
    ServiceLabel,
)
from certomancer.services import (
    CertomancerServiceError,
    DeltaCRLError,
    _authority_key_identifier,
    _crl_extension,
    _crl_number,
    _delta_crl_indicator,
    merge_delta_crl,
)

CFG_FILE = 'tests/data/with-delta-crls.yml'
ARCH_LABEL = ArchLabel('testing-ca')
REPO_LABEL = ServiceLabel('interm')
BASE_NUMBER = 253


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


def _setup():
    cfg = CertomancerConfig.from_file(CFG_FILE, 'tests/data')
    arch = cfg.get_pki_arch(ARCH_LABEL)
    return cfg, arch


def _serials(crl_obj: crl.CertificateList):
    return [
        r['user_certificate'].native
        for r in crl_obj['tbs_cert_list']['revoked_certificates']
    ]


@pytest.fixture(scope='module')
def setup():
    return _setup()


def _base_and_delta(arch, at_time):
    base = arch.service_registry.get_crl(REPO_LABEL, number=BASE_NUMBER)
    delta = arch.service_registry.get_crl(
        REPO_LABEL, at_time=at_time, delta=True
    )
    return base, delta


def test_delta_config_parses(setup):
    _, arch = setup
    info = arch.service_registry.get_crl_repo_info(REPO_LABEL)
    delta_cfg = info.delta_crl
    assert delta_cfg is not None
    assert delta_cfg.base_crl_number == BASE_NUMBER
    assert delta_cfg.issuance_period == timedelta(days=10)
    assert info.delta_latest_external_url.endswith(
        '/testing-ca/crls/interm/delta-latest.crl'
    )


def test_full_crl_unchanged(setup):
    _, arch = setup
    # The legacy full CRL service still works and includes revocations.
    full = arch.service_registry.get_crl(REPO_LABEL, number=254)
    assert _crl_number(full) == 254
    assert _delta_crl_indicator(full) is None
    assert _serials(full) == [4097]


def test_delta_only_new_revocations(setup):
    _, arch = setup
    at_time = _dt('2020-12-11')
    base, delta = _base_and_delta(arch, at_time)

    # signer2 revoked on 2020-10-20, before the base CRL's thisUpdate
    # (2020-10-12). signer3 revoked on 2020-11-20, after it.
    assert _serials(base) == []
    assert _serials(delta) == [4097, 4098]

    indicator = _crl_extension(delta, 'delta_crl_indicator')
    assert indicator is not None
    assert indicator['critical'].native is True
    assert _delta_crl_indicator(delta) == BASE_NUMBER
    assert _crl_number(delta) > BASE_NUMBER
    # Delta number 257 is issued at 2020-10-22 + 20 days = 2020-12-11.
    assert delta['tbs_cert_list']['this_update'].native == _dt('2020-12-11')

    # Delta entries only carry revocations newer than the base thisUpdate.
    base_this_update = base['tbs_cert_list']['this_update'].native
    for revo in delta['tbs_cert_list']['revoked_certificates']:
        assert revo['revocation_date'].native > base_this_update


def test_delta_scope_and_freshest_crl(setup):
    _, arch = setup
    base, delta = _base_and_delta(arch, _dt('2020-12-01'))

    base_idp = _crl_extension(base, 'issuing_distribution_point')
    delta_idp = _crl_extension(delta, 'issuing_distribution_point')
    assert base_idp is not None and delta_idp is not None
    assert base_idp['critical'].native is True
    assert (
        base_idp['extn_value'].parsed.dump()
        == delta_idp['extn_value'].parsed.dump()
    )
    assert (
        _authority_key_identifier(base)
        == _authority_key_identifier(delta)
        is not None
    )

    freshest = _crl_extension(base, 'freshest_crl')
    assert freshest is not None
    urls = [
        name.chosen.native
        for name in freshest['extn_value']
        .parsed[0]['distribution_point']
        .chosen
        if name.name == 'uniform_resource_identifier'
    ]
    assert urls == ['http://test.test/testing-ca/crls/interm/delta-latest.crl']


def test_delta_timeline_alignment(setup):
    _, arch = setup
    # At 2020-12-11, the latest full CRL is #255 (2020-12-11).
    full = arch.service_registry.get_crl(REPO_LABEL, at_time=_dt('2020-12-11'))
    delta = arch.service_registry.get_crl(
        REPO_LABEL, at_time=_dt('2020-12-11'), delta=True
    )
    assert _crl_number(full) == 255
    assert full['tbs_cert_list']['this_update'].native == _dt('2020-12-11')
    assert delta['tbs_cert_list']['this_update'].native == _dt('2020-12-11')
    assert delta['tbs_cert_list']['next_update'].native == _dt('2020-12-21')


def test_delta_merge_matches_full_crl(setup):
    _, arch = setup
    # 2020-12-11 is a full CRL update and a delta CRL update, so the merged
    # state must match the full CRL issued on the same timeline.
    at_time = _dt('2020-12-11')
    base, delta = _base_and_delta(arch, at_time)
    full = arch.service_registry.get_crl(REPO_LABEL, at_time=at_time)
    assert _serials(delta) == _serials(full)

    merged = arch.service_registry.merge_delta_crl(REPO_LABEL, base, delta)
    assert _serials(merged) == _serials(full)
    assert _delta_crl_indicator(merged) is None
    assert _crl_number(merged) == _crl_number(delta)
    assert (
        merged['tbs_cert_list']['this_update'].native
        == delta['tbs_cert_list']['this_update'].native
    )

    issuer_cert = arch.get_cert(EntityLabel('interm'))
    from certomancer.crypto_utils import generic_verify

    # The registry's merge result is freshly signed and independently
    # verifiable.
    generic_verify(
        issuer_cert.public_key,
        merged['tbs_cert_list'].dump(),
        merged['signature'].native,
        merged['signature_algorithm'],
    )

    # Re-merge using the standalone offline helper, with explicit signature
    # verification. It returns an unsigned TBS structure.
    offline_tbs = merge_delta_crl(
        base, delta, issuer_cert, expected_base_crl_number=BASE_NUMBER
    )
    offline_serials = [
        r['user_certificate'].native
        for r in offline_tbs['revoked_certificates']
    ]
    assert offline_serials == _serials(full)

    # The full CRL is independently signed; verify it too.
    generic_verify(
        issuer_cert.public_key,
        full['tbs_cert_list'].dump(),
        full['signature'].native,
        full['signature_algorithm'],
    )


def test_latest_delta_merge(setup):
    _, arch = setup
    issuer_cert = arch.get_cert(EntityLabel('interm'))

    base = arch.service_registry.get_crl(REPO_LABEL, number=BASE_NUMBER)
    delta1 = arch.service_registry.get_crl(
        REPO_LABEL, at_time=_dt('2020-11-21'), delta=True
    )
    delta2 = arch.service_registry.get_crl(
        REPO_LABEL, at_time=_dt('2020-12-11'), delta=True
    )
    # Both revocations postdate the base CRL's thisUpdate, so each delta in
    # the series carries the full set of changes relative to the base.
    assert _serials(delta1) == [4097, 4098]
    assert _serials(delta2) == [4097, 4098]

    # A client applies the latest delta it has to the base CRL, not to an
    # already-merged view.
    merged_tbs = merge_delta_crl(
        base, delta2, issuer_cert, expected_base_crl_number=BASE_NUMBER
    )
    serials = [
        revo['user_certificate'].native
        for revo in merged_tbs['revoked_certificates']
    ]
    assert serials == [4097, 4098]
    crl_number_exts = [
        ext
        for ext in merged_tbs['crl_extensions']
        if ext['extn_id'].native == 'crl_number'
    ]
    assert len(crl_number_exts) == 1


def test_delta_signatures_verified(setup):
    _, arch = setup
    base, delta = _base_and_delta(arch, _dt('2020-12-01'))
    issuer_cert = arch.get_cert(EntityLabel('interm'))
    from certomancer.crypto_utils import generic_verify

    for crl_obj in (base, delta):
        generic_verify(
            issuer_cert.public_key,
            crl_obj['tbs_cert_list'].dump(),
            crl_obj['signature'].native,
            crl_obj['signature_algorithm'],
        )

    # Tamper with the delta signature.
    tampered = crl.CertificateList.load(delta.dump())
    sig = bytearray(tampered['signature'].native)
    sig[0] ^= 0xFF
    tampered['signature'] = bytes(sig)
    with pytest.raises(DeltaCRLError, match='signature'):
        merge_delta_crl(
            base, tampered, issuer_cert, expected_base_crl_number=BASE_NUMBER
        )


def test_delta_rejects_issuer_mismatch(setup):
    _, arch = setup
    base, delta = _base_and_delta(arch, _dt('2020-12-01'))
    issuer_cert = arch.get_cert(EntityLabel('interm'))

    bad = crl.CertificateList.load(delta.dump())
    bad['tbs_cert_list']['issuer'] = arch.entities[EntityLabel('root')]
    with pytest.raises(DeltaCRLError, match='issuer'):
        merge_delta_crl(base, bad, issuer_cert, verify_signatures=False)


def test_delta_rejects_aki_mismatch(setup):
    _, arch = setup
    base, delta = _base_and_delta(arch, _dt('2020-12-01'))
    issuer_cert = arch.get_cert(EntityLabel('interm'))

    bad = crl.CertificateList.load(delta.dump())
    for ext in bad['tbs_cert_list']['crl_extensions']:
        if ext['extn_id'].native == 'authority_key_identifier':
            ext['extn_value'] = x509.AuthorityKeyIdentifier(
                {'key_identifier': b'\x00' * 20}
            )
    with pytest.raises(DeltaCRLError, match='authority key identifier'):
        merge_delta_crl(base, bad, issuer_cert, verify_signatures=False)


def test_delta_rejects_scope_mismatch(setup):
    _, arch = setup
    base, delta = _base_and_delta(arch, _dt('2020-12-01'))
    issuer_cert = arch.get_cert(EntityLabel('interm'))

    bad = crl.CertificateList.load(delta.dump())
    for ext in bad['tbs_cert_list']['crl_extensions']:
        if ext['extn_id'].native == 'issuing_distribution_point':
            idp = ext['extn_value'].parsed
            idp['only_contains_ca_certs'] = True
            ext['extn_value'] = core.ParsableOctetString(idp.dump())
    with pytest.raises(DeltaCRLError, match='scope'):
        merge_delta_crl(base, bad, issuer_cert, verify_signatures=False)


def test_delta_rejects_wrong_base_number(setup):
    _, arch = setup
    base, delta = _base_and_delta(arch, _dt('2020-12-01'))
    issuer_cert = arch.get_cert(EntityLabel('interm'))

    with pytest.raises(DeltaCRLError, match='expected base CRL number'):
        merge_delta_crl(
            base,
            delta,
            issuer_cert,
            verify_signatures=False,
            expected_base_crl_number=BASE_NUMBER + 1,
        )

    # A full CRL is not a delta CRL.
    with pytest.raises(DeltaCRLError, match='not a delta CRL'):
        merge_delta_crl(base, base, issuer_cert, verify_signatures=False)


def test_delta_rejects_noncritical_indicator(setup):
    _, arch = setup
    base, delta = _base_and_delta(arch, _dt('2020-12-01'))
    issuer_cert = arch.get_cert(EntityLabel('interm'))

    bad = crl.CertificateList.load(delta.dump())
    for ext in bad['tbs_cert_list']['crl_extensions']:
        if ext['extn_id'].native == 'delta_crl_indicator':
            ext['critical'] = False
    with pytest.raises(DeltaCRLError, match='critical'):
        merge_delta_crl(base, bad, issuer_cert, verify_signatures=False)


def test_delta_rejects_remove_from_crl(setup):
    _, arch = setup
    base, delta = _base_and_delta(arch, _dt('2020-12-01'))
    issuer_cert = arch.get_cert(EntityLabel('interm'))

    bad = crl.CertificateList.load(delta.dump())
    revo = bad['tbs_cert_list']['revoked_certificates'][0]
    exts = [
        ext
        for ext in revo['crl_entry_extensions']
        if ext['extn_id'].native != 'crl_reason'
    ]
    exts.append(
        crl.CRLEntryExtension(
            {
                'extn_id': 'crl_reason',
                'extn_value': crl.CRLReason('remove_from_crl'),
            }
        )
    )
    revo['crl_entry_extensions'] = crl.CRLEntryExtensions(exts)
    with pytest.raises(DeltaCRLError, match='removeFromCRL'):
        merge_delta_crl(base, bad, issuer_cert, verify_signatures=False)


def test_delta_requires_configuration(setup):
    cfg, _ = setup
    import yaml

    config_dict = yaml.safe_load(open(CFG_FILE))
    del config_dict['pki-architectures']['testing-ca']['services']['crl-repo'][
        'interm'
    ]['delta-crl']
    cfg_no_delta = CertomancerConfig(
        config_dict,
        key_search_dir='tests/data',
        config_search_dir='tests/data',
    )
    arch_no_delta = cfg_no_delta.get_pki_arch(ARCH_LABEL)
    with pytest.raises(CertomancerServiceError, match='not enabled'):
        arch_no_delta.service_registry.get_crl(
            REPO_LABEL, at_time=_dt('2020-12-11'), delta=True
        )


@pytest.mark.parametrize(
    'delta_config',
    [
        {
            'base-crl-number': 253,
            'issuance-period': 'P10D',
            'crl-type': 'ca-only',
        },
        {
            'base-crl-number': 253,
            'issuance-period': 'P10D',
            'covered-reasons': ['key_compromise'],
        },
        {
            'base-crl-number': 253,
            'issuance-period': 'P0D',
        },
    ],
)
def test_delta_config_rejects_inconsistent_scope(delta_config):
    with open(CFG_FILE) as f:
        raw = f.read()
    import yaml

    config_dict = yaml.safe_load(raw)
    arch_cfg = config_dict['pki-architectures']['testing-ca']
    arch_cfg['services']['crl-repo']['interm']['delta-crl'] = delta_config

    with pytest.raises(ConfigurationError):
        CertomancerConfig(
            config_dict,
            key_search_dir='tests/data',
            config_search_dir='tests/data',
        )


def test_delta_http_endpoint(setup):
    _, arch = setup
    from werkzeug.test import Client
    from werkzeug.wrappers import Response

    client = Client(
        Animator(AnimatorArchStore({ARCH_LABEL: arch}), with_web_ui=False),
        Response,
    )
    response = client.get(
        '/testing-ca/crls/interm/delta-latest.crl',
        headers={'X-Certomancer-Fake-Time': '2020-12-11T00:00:00+0000'},
    )
    assert response.status_code == 200
    delta = crl.CertificateList.load(response.data)

    response = client.get(
        '/testing-ca/crls/interm/latest.crl',
        headers={'X-Certomancer-Fake-Time': '2020-12-11T00:00:00+0000'},
    )
    assert response.status_code == 200
    full = crl.CertificateList.load(response.data)

    assert _delta_crl_indicator(delta) == BASE_NUMBER
    assert _delta_crl_indicator(full) is None

    response = client.get('/testing-ca/crls/interm/delta-archive-255.crl')
    assert response.status_code == 200
    archived_delta = crl.CertificateList.load(response.data)
    assert _delta_crl_indicator(archived_delta) == BASE_NUMBER


def test_delta_illusionist_endpoint(setup):
    import requests
    import requests_mock

    from certomancer.integrations.illusionist import Illusionist

    _, arch = setup
    with requests_mock.Mocker() as mocker:
        Illusionist(arch, at_time=_dt('2020-12-11')).register(mocker)
        response = requests.get(
            'http://test.test/testing-ca/crls/interm/delta-latest.crl'
        )
    assert response.status_code == 200
    delta = crl.CertificateList.load(response.content)
    assert _delta_crl_indicator(delta) == BASE_NUMBER


@pytest.mark.asyncio
async def test_delta_async_illusionist_handler(setup):
    from certomancer.integrations.aiohttp_illusionist import AsyncIllusionist

    _, arch = setup
    illusionist = AsyncIllusionist(arch, at_time=_dt('2020-12-11'))
    handler = illusionist._make_crl_handler(REPO_LABEL, delta=True)
    response = await handler(None)
    delta = crl.CertificateList.load(response.body)
    assert _delta_crl_indicator(delta) == BASE_NUMBER


def test_delta_config_rejects_reserved_extension():
    import yaml

    config_dict = yaml.safe_load(open(CFG_FILE))
    delta_cfg = config_dict['pki-architectures']['testing-ca']['services'][
        'crl-repo'
    ]['interm']['delta-crl']
    delta_cfg['crl-extensions'] = [{'id': 'delta_crl_indicator'}]
    with pytest.raises(ConfigurationError, match='delta_crl_indicator'):
        CertomancerConfig(
            config_dict,
            key_search_dir='tests/data',
            config_search_dir='tests/data',
        )
