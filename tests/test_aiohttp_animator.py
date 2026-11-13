"""
Async integration tests for aiohttp_animator.

Mirrors tests/test_animator.py, adapted for aiohttp's test utilities.
"""

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from io import BytesIO
from zipfile import ZipFile

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from asn1crypto import algos, cms, core, crl, ocsp, tsp, x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from freezegun import freeze_time

from certomancer import CertomancerConfig
from certomancer.integrations._animator_shared import FAKE_TIME_HEADER
from certomancer.integrations.aiohttp_animator import build_animator_app
from certomancer.registry import ArchLabel, CertLabel, KeyLabel, ServiceLabel

CFG = CertomancerConfig.from_file('tests/data/with-services.yml', 'tests/data')


@pytest_asyncio.fixture
async def client():
    app = build_animator_app(CFG.pki_archs)
    async with TestClient(TestServer(app)) as c:
        yield c


@pytest_asyncio.fixture
async def client_no_ui():
    app = build_animator_app(CFG.pki_archs, with_web_ui=False)
    async with TestClient(TestServer(app)) as c:
        yield c


@pytest.mark.asyncio
@freeze_time('2020-11-01')
async def test_timestamp(client):
    hashed_bytes = hashlib.sha256(b'test').digest()
    req = tsp.TimeStampReq(
        {
            'version': 'v2',
            'message_imprint': tsp.MessageImprint(
                {
                    'hash_algorithm': algos.DigestAlgorithm(
                        {'algorithm': 'sha256'}
                    ),
                    'hashed_message': hashed_bytes,
                }
            ),
            'nonce': core.Integer(0x1337),
            'cert_req': True,
        }
    )
    resp = await client.post(
        '/testing-ca/tsa/tsa',
        data=req.dump(),
        headers={'Content-Type': 'application/timestamp-query'},
    )
    assert resp.status == 200
    body = await resp.read()
    ts_resp: tsp.TimeStampResp = tsp.TimeStampResp.load(body)
    sd = ts_resp['time_stamp_token']['content']
    tst_info: tsp.TSTInfo = sd['encap_content_info']['content'].parsed
    assert tst_info['nonce'].native == 0x1337
    assert tst_info['gen_time'].native == datetime.now().replace(
        tzinfo=timezone.utc
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "time, expected",
    [('2020-11-05', 'good'), ('2020-12-05', 'revoked')],
)
async def test_ocsp(client, time, expected):
    with open('tests/data/signer2-ocsp-req.der', 'rb') as req_in:
        req_data = req_in.read()
    with freeze_time(time):
        resp = await client.post(
            '/testing-ca/ocsp/interm',
            data=req_data,
            headers={'Content-Type': 'application/ocsp-request'},
        )
        assert resp.status == 200
        body = await resp.read()
        ocsp_resp: ocsp.OCSPResponse = ocsp.OCSPResponse.load(body)
        assert ocsp_resp['response_status'].native == 'successful'
        rdata = ocsp_resp['response_bytes']['response'].parsed[
            'tbs_response_data'
        ]
        status = rdata['responses'][0]['cert_status'].name
        assert status == expected


@pytest.mark.asyncio
async def test_no_plugins_loaded(client):
    endpoint = '/testing-ca/plugin/encrypt-echo/test-endpoint'
    resp = await client.post(endpoint, data=b'bleh')
    assert resp.status == 404


@pytest.mark.asyncio
async def test_demo_plugin():
    with_plugin_cfg = CertomancerConfig.from_file(
        'tests/data/with-plugin.yml', 'tests/data'
    )
    app = build_animator_app(with_plugin_cfg.pki_archs, with_web_ui=False)
    async with TestClient(TestServer(app)) as c:
        endpoint = '/testing-ca/plugin/encrypt-echo/test-endpoint'
        payload = b'test test test'
        resp = await c.post(endpoint, data=payload)
        assert resp.status == 200
        body = await resp.read()

    # decrypt it
    env_data = cms.ContentInfo.load(body)['content']
    arch = with_plugin_cfg.get_pki_arch(ArchLabel('testing-ca'))
    key_info = arch.key_set.get_private_key(KeyLabel('signer1'))
    ktri = env_data['recipient_infos'][0].chosen
    encrypted_key = ktri['encrypted_key'].native

    key: RSAPrivateKey = serialization.load_der_private_key(
        key_info.dump(), password=None
    )
    decrypted_key = key.decrypt(encrypted_key, padding.PKCS1v15())
    eci = env_data['encrypted_content_info']
    cea = eci['content_encryption_algorithm']
    assert cea['algorithm'].native == 'aes256_cbc'
    iv = cea['parameters'].native
    encrypted_content_bytes = eci['encrypted_content'].native

    cipher = Cipher(algorithms.AES(decrypted_key), modes.CBC(iv))
    dec = cipher.decryptor()
    decrypted_payload = dec.update(encrypted_content_bytes) + dec.finalize()
    unpadder = PKCS7(128).unpadder()
    result = unpadder.update(decrypted_payload) + unpadder.finalize()
    assert result == payload


@pytest.mark.asyncio
async def test_crl(client):
    from tests.test_services import _check_crl_cardinality

    resp = await client.get(
        '/testing-ca/crls/interm/latest.crl',
        headers={FAKE_TIME_HEADER: "2020-11-01T00:00:00+0000"},
    )
    assert resp.status == 200
    body = await resp.read()
    _check_crl_cardinality(crl.CertificateList.load(body), expected_revoked=0)

    resp = await client.get(
        '/testing-ca/crls/interm/latest.crl',
        headers={FAKE_TIME_HEADER: "2020-12-02T00:00:00+0000"},
    )
    assert resp.status == 200
    body = await resp.read()
    _check_crl_cardinality(crl.CertificateList.load(body), expected_revoked=0)

    resp = await client.get(
        '/testing-ca/crls/interm/latest.crl',
        headers={FAKE_TIME_HEADER: "2020-12-29T00:00:00+0000"},
    )
    assert resp.status == 200
    body = await resp.read()
    some_crl3 = crl.CertificateList.load(body)
    _check_crl_cardinality(some_crl3, expected_revoked=1)
    revo = some_crl3['tbs_cert_list']['revoked_certificates'][0]
    rev_time = datetime(2020, 12, 1, tzinfo=timezone.utc)
    assert revo['revocation_date'].native == rev_time

    reason = next(
        ext['extn_value'].native
        for ext in revo['crl_entry_extensions']
        if ext['extn_id'].native == 'crl_reason'
    )
    assert reason == 'key_compromise'

    invalidity_date = next(
        ext['extn_value'].native
        for ext in revo['crl_entry_extensions']
        if ext['extn_id'].native == 'invalidity_date'
    )
    assert invalidity_date == datetime(2020, 11, 30, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_crl_archive(client):
    from tests.test_services import _check_crl_cardinality

    resp = await client.get('/testing-ca/crls/interm/archive-1.crl')
    assert resp.status == 200
    body = await resp.read()
    _check_crl_cardinality(crl.CertificateList.load(body), expected_revoked=0)

    resp = await client.get('/testing-ca/crls/interm/archive-1000.crl')
    assert resp.status == 200
    body = await resp.read()
    _check_crl_cardinality(crl.CertificateList.load(body), expected_revoked=1)


@pytest.mark.asyncio
async def test_cert_repo(client):
    resp = await client.get('/testing-ca/certs/root/issued/interm.crt')
    assert resp.status == 200
    body1 = await resp.read()
    cert1 = x509.Certificate.load(body1)

    resp = await client.get('/testing-ca/certs/interm/ca.crt')
    assert resp.status == 200
    body2 = await resp.read()
    cert2 = x509.Certificate.load(body2)

    resp = await client.get('/_certomancer/any-cert/testing-ca/interm.crt')
    assert resp.status == 200
    body3 = await resp.read()
    cert3 = x509.Certificate.load(body3)

    assert cert1.dump() == cert2.dump() == cert3.dump()


@pytest.mark.asyncio
async def test_zip(client):
    resp = await client.get('/_certomancer/cert-bundle/testing-ca')
    assert resp.status == 200
    body = await resp.read()
    z = ZipFile(BytesIO(body))
    dumped = set(z.namelist())
    assert dumped == set(
        map(
            lambda n: 'testing-ca/' + n,
            {
                'interm/signer1-long.cert.pem',
                'interm/signer1.cert.pem',
                'interm/signer2.cert.pem',
                'interm/interm-ocsp.cert.pem',
                'root/interm.cert.pem',
                'root/tsa.cert.pem',
                'root/tsa2.cert.pem',
                'root/root.cert.pem',
            },
        )
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('pw', [None, b'', b'secret'])
async def test_pkcs12(client, pw):
    data = {'cert': 'signer1'}
    if pw is not None:
        data['passphrase'] = pw.decode('ascii')
    resp = await client.post('/_certomancer/pfx-download/testing-ca', data=data)
    assert resp.status == 200
    package = await resp.read()
    from cryptography.hazmat.primitives.serialization import pkcs12

    key, cert, chain = pkcs12.load_key_and_certificates(package, password=pw)
    assert key is not None
    assert len(chain) == 2


@pytest.mark.asyncio
async def test_index(client):
    resp = await client.get('/')
    assert resp.status == 200
    body = await resp.read()
    assert b'testing-ca' in body


@pytest.mark.asyncio
async def test_fake_time_override(client):
    """X-Certomancer-Fake-Time header should influence CRL generation."""
    from tests.test_services import _check_crl_cardinality

    resp = await client.get(
        '/testing-ca/crls/interm/latest.crl',
        headers={FAKE_TIME_HEADER: "2020-12-29T00:00:00+0000"},
    )
    assert resp.status == 200
    body = await resp.read()
    # After revocation date of signer2, CRL should have 1 revoked entry
    _check_crl_cardinality(crl.CertificateList.load(body), expected_revoked=1)


@pytest.mark.asyncio
async def test_unknown_arch(client):
    resp = await client.get('/nonexistent-arch/certs/root/ca.crt')
    assert resp.status == 404


@pytest.mark.asyncio
async def test_no_web_ui(client_no_ui):
    resp = await client_no_ui.get('/')
    assert resp.status == 404

    resp = await client_no_ui.get(
        '/_certomancer/any-cert/testing-ca/interm.crt'
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_attr_cert_repo_aa(client):
    resp = await client.get('/testing-ca-with-aa/attr-certs/role-aa/aa.crt')
    assert resp.status == 200
    body = await resp.read()
    cert = x509.Certificate.load(body)
    assert cert is not None


@pytest.mark.asyncio
async def test_attr_cert_repo_issued(client):
    resp = await client.get(
        '/testing-ca-with-aa/attr-certs/role-aa/issued/test-ac.attr.crt'
    )
    assert resp.status == 200
    body = await resp.read()
    ac = cms.AttributeCertificateV2.load(body)
    assert ac is not None


@pytest.mark.asyncio
async def test_attr_cert_repo_by_holder(client):
    resp = await client.get(
        '/testing-ca-with-aa/attr-certs/role-aa/by-holder/signer2-all.attr.cert.pem'
    )
    assert resp.status == 200
    body = await resp.read()
    assert b'ATTRIBUTE CERTIFICATE' in body


@pytest.mark.asyncio
async def test_any_attr_cert(client):
    resp = await client.get(
        '/_certomancer/any-attr-cert/testing-ca-with-aa/test-ac.attr.crt'
    )
    assert resp.status == 200
    body = await resp.read()
    ac = cms.AttributeCertificateV2.load(body)
    assert ac is not None


@pytest.mark.asyncio
async def test_attr_certs_of(client):
    resp = await client.get(
        '/_certomancer/attr-certs-of/testing-ca-with-aa/signer2-all.attr.cert.pem'
    )
    assert resp.status == 200
    body = await resp.read()
    assert b'ATTRIBUTE CERTIFICATE' in body


@pytest.mark.asyncio
async def test_attr_cert_not_found(client):
    resp = await client.get(
        '/testing-ca-with-aa/attr-certs/role-aa/issued/nonexistent.attr.crt'
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_attr_cert_wrong_arch(client):
    resp = await client.get(
        '/nonexistent-arch/attr-certs/role-aa/issued/test-ac.attr.crt'
    )
    assert resp.status == 404


# --- concurrent timeline isolation tests ---
#
# signer2 is revoked since 2020-12-01T00:00:00Z, so these two fixed
# timelines observe different revocation states for the same certificate.
# All requests carry their own X-Certomancer-Fake-Time header; the server
# must never mix the two timelines up, no matter how requests interleave.

T_BEFORE_REVOCATION = datetime(2020, 11, 5, tzinfo=timezone.utc)
T_AFTER_REVOCATION = datetime(2020, 12, 29, tzinfo=timezone.utc)
SIGNER2_REVOKED_SINCE = datetime(2020, 12, 1, tzinfo=timezone.utc)


def _fake_time_headers(at_time):
    if at_time is None:
        return {}
    return {FAKE_TIME_HEADER: at_time.strftime('%Y-%m-%dT%H:%M:%S%z')}


async def _fetch_ocsp_rdata(client, at_time):
    with open('tests/data/signer2-ocsp-req.der', 'rb') as req_in:
        req_data = req_in.read()
    resp = await client.post(
        '/testing-ca/ocsp/interm',
        data=req_data,
        headers={
            'Content-Type': 'application/ocsp-request',
            **_fake_time_headers(at_time),
        },
    )
    assert resp.status == 200
    body = await resp.read()
    ocsp_resp = ocsp.OCSPResponse.load(body)
    assert ocsp_resp['response_status'].native == 'successful'
    return ocsp_resp['response_bytes']['response'].parsed['tbs_response_data']


async def _fetch_tsa_gen_time(client, at_time):
    hashed_bytes = hashlib.sha256(b'timeline-test').digest()
    req = tsp.TimeStampReq(
        {
            'version': 'v2',
            'message_imprint': tsp.MessageImprint(
                {
                    'hash_algorithm': algos.DigestAlgorithm(
                        {'algorithm': 'sha256'}
                    ),
                    'hashed_message': hashed_bytes,
                }
            ),
            'cert_req': True,
        }
    )
    resp = await client.post(
        '/testing-ca/tsa/tsa',
        data=req.dump(),
        headers={
            'Content-Type': 'application/timestamp-query',
            **_fake_time_headers(at_time),
        },
    )
    assert resp.status == 200
    body = await resp.read()
    ts_resp = tsp.TimeStampResp.load(body)
    sd = ts_resp['time_stamp_token']['content']
    return sd['encap_content_info']['content'].parsed['gen_time'].native


async def _fetch_latest_crl(client, at_time):
    resp = await client.get(
        '/testing-ca/crls/interm/latest.crl',
        headers=_fake_time_headers(at_time),
    )
    assert resp.status == 200
    return crl.CertificateList.load(await resp.read())


def _expected_crl_schedule(at_time):
    # Mirror the documented semantics of ServiceRegistry.get_crl:
    # the CRL number counts update periods since the issuer cert's
    # notBefore, and thisUpdate sits at the start of the current period.
    arch = CFG.get_pki_arch(ArchLabel('testing-ca'))
    svc_reg = arch.service_registry
    crl_info = svc_reg.get_crl_repo_info(ServiceLabel('interm'))
    time_origin = arch.get_cert(CertLabel('interm')).not_valid_before
    time_delta = crl_info.simulated_update_schedule
    number = (at_time - time_origin) // time_delta
    return number, time_origin + number * time_delta


def _check_ocsp_timeline(rdata, at_time):
    produced_at = rdata['produced_at'].native
    # producedAt must reflect this request's own timeline, never the
    # other request's one
    assert produced_at == at_time
    single = rdata['responses'][0]
    assert single['this_update'].native == at_time
    assert single['next_update'].native == at_time + timedelta(minutes=10)
    expected_status = (
        'good' if at_time < SIGNER2_REVOKED_SINCE else 'revoked'
    )
    assert single['cert_status'].name == expected_status


def _check_crl_timeline(cert_list, at_time):
    tbs = cert_list['tbs_cert_list']
    expected_number, expected_this_update = _expected_crl_schedule(at_time)
    crl_number = next(
        ext['extn_value'].native
        for ext in tbs['crl_extensions']
        if ext['extn_id'].native == 'crl_number'
    )
    assert crl_number == expected_number
    assert tbs['this_update'].native == expected_this_update
    expected_revoked = 0 if at_time < SIGNER2_REVOKED_SINCE else 1
    assert len(tbs['revoked_certificates']) == expected_revoked


@pytest.mark.asyncio
async def test_interleaved_timelines_ocsp(client):
    timelines = [T_BEFORE_REVOCATION, T_AFTER_REVOCATION] * 4
    rdatas = await asyncio.gather(
        *(_fetch_ocsp_rdata(client, at_time) for at_time in timelines)
    )
    for at_time, rdata in zip(timelines, rdatas):
        _check_ocsp_timeline(rdata, at_time)


@pytest.mark.asyncio
async def test_interleaved_timelines_tsa(client):
    timelines = [T_BEFORE_REVOCATION, T_AFTER_REVOCATION] * 4
    gen_times = await asyncio.gather(
        *(_fetch_tsa_gen_time(client, at_time) for at_time in timelines)
    )
    assert list(gen_times) == timelines


@pytest.mark.asyncio
async def test_interleaved_timelines_crl(client):
    timelines = [T_BEFORE_REVOCATION, T_AFTER_REVOCATION] * 4
    cert_lists = await asyncio.gather(
        *(_fetch_latest_crl(client, at_time) for at_time in timelines)
    )
    for at_time, cert_list in zip(timelines, cert_lists):
        _check_crl_timeline(cert_list, at_time)


@pytest.mark.asyncio
async def test_interleaved_timelines_repeatable(client):
    # Repeating the same interleaved batch must yield exactly the same
    # producedAt/genTime values: results are fully explained by the
    # per-request time context, not by wall-clock or shared state.
    timelines = [T_BEFORE_REVOCATION, T_AFTER_REVOCATION] * 2

    async def _run_batch():
        ocsp_rdatas, gen_times = await asyncio.gather(
            asyncio.gather(
                *(_fetch_ocsp_rdata(client, t) for t in timelines)
            ),
            asyncio.gather(
                *(_fetch_tsa_gen_time(client, t) for t in timelines)
            ),
        )
        produced = [rd['produced_at'].native for rd in ocsp_rdatas]
        return produced, list(gen_times)

    first = await _run_batch()
    second = await _run_batch()
    assert first == second
    assert first[0] == timelines
    assert first[1] == timelines


@pytest.mark.asyncio
async def test_cancelled_request_does_not_leak_time(client):
    # Cancel a request on the post-revocation timeline; the concurrent
    # pre-revocation request must still complete on its own timeline,
    # and the service must remain consistent afterwards.
    before_task = asyncio.ensure_future(
        _fetch_ocsp_rdata(client, T_BEFORE_REVOCATION)
    )
    after_task = asyncio.ensure_future(
        _fetch_ocsp_rdata(client, T_AFTER_REVOCATION)
    )
    await asyncio.sleep(0)
    after_task.cancel()
    try:
        rdata = await after_task
    except asyncio.CancelledError:
        pass
    else:
        # the server finished before the cancellation landed; even then
        # the result must carry the cancelled request's own timeline
        _check_ocsp_timeline(rdata, T_AFTER_REVOCATION)

    rdata = await before_task
    _check_ocsp_timeline(rdata, T_BEFORE_REVOCATION)

    # the cancelled timeline is still served correctly afterwards
    rdata_after = await _fetch_ocsp_rdata(client, T_AFTER_REVOCATION)
    _check_ocsp_timeline(rdata_after, T_AFTER_REVOCATION)
    gen_time = await _fetch_tsa_gen_time(client, T_AFTER_REVOCATION)
    assert gen_time == T_AFTER_REVOCATION


@pytest.mark.asyncio
async def test_fixed_time_app_still_honoured():
    # The original fixed-time usage is unchanged: without the override
    # header every request uses the app's fixed time, and the header
    # still takes precedence when allowed.
    fixed = datetime(2020, 11, 5, tzinfo=timezone.utc)
    app = build_animator_app(
        CFG.pki_archs, at_time=fixed, with_web_ui=False
    )
    async with TestClient(TestServer(app)) as fixed_client:
        rdata1, rdata2, gen_time = await asyncio.gather(
            _fetch_ocsp_rdata(fixed_client, None),
            _fetch_ocsp_rdata(fixed_client, None),
            _fetch_tsa_gen_time(fixed_client, None),
        )
        _check_ocsp_timeline(rdata1, fixed)
        _check_ocsp_timeline(rdata2, fixed)
        assert gen_time == fixed

        # per-request override still wins over the fixed time
        rdata = await _fetch_ocsp_rdata(fixed_client, T_AFTER_REVOCATION)
        _check_ocsp_timeline(rdata, T_AFTER_REVOCATION)
