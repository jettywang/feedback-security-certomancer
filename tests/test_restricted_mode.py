"""
Tests for public-only restricted mode.

The restricted policy must:
  * keep certificate, OCSP, CRL and TSA services working;
  * deny every private key export path explicitly (not just hide UI links);
  * fail closed on configuration errors.
"""

import asyncio
import hashlib
import os
from io import BytesIO
from zipfile import ZipFile

import pytest
from aiohttp import streams
from aiohttp.test_utils import make_mocked_request
from asn1crypto import algos, core, crl, ocsp, tsp, x509
from click.testing import CliRunner
from werkzeug.test import Client
from werkzeug.wrappers import Response

from certomancer import CertomancerConfig
from certomancer.cli import cli_root
from certomancer.config_utils import ConfigurationError
from certomancer.integrations.aiohttp_animator import build_animator_app
from certomancer.integrations.animator import (
    Animator,
    AnimatorArchStore,
    LazyAnimator,
)
from certomancer.policy import ServicePolicy
from certomancer.registry import ArchLabel, CertLabel, PluginLabel, ServiceLabel
from certomancer.services import (
    PrivateKeyExportDisabled,
    RestrictedServiceError,
)
from tests.conftest import TEST_DATA_PATH, collect_files


def _restricted_config():
    return CertomancerConfig.from_file(
        'tests/data/with-services.yml',
        'tests/data',
        service_policy=ServicePolicy(restricted=True),
    )


@pytest.fixture(scope='module')
def restricted_cfg():
    return _restricted_config()


@pytest.fixture(scope='module')
def wsgi_client(restricted_cfg):
    animator = Animator(
        AnimatorArchStore(restricted_cfg.pki_archs),
        with_web_ui=True,
        service_policy=restricted_cfg.service_policy,
    )
    return Client(animator, Response)


@pytest.fixture(scope='module')
def wsgi_client_no_ui(restricted_cfg):
    animator = Animator(
        AnimatorArchStore(restricted_cfg.pki_archs),
        with_web_ui=False,
        service_policy=restricted_cfg.service_policy,
    )
    return Client(animator, Response)


class _FakeProtocol:
    def resume_reading(self, **kwargs):
        pass

    def pause_reading(self):
        pass


def _run_aiohttp(coro):
    return asyncio.run(coro)


def _aiohttp_request(app, method, path, body=b'', headers=None):
    async def _do():
        loop = asyncio.get_running_loop()
        payload = streams.StreamReader(
            protocol=_FakeProtocol(), limit=2 ** 20, loop=loop
        )
        payload.feed_data(body)
        payload.feed_eof()
        request = make_mocked_request(
            method,
            path,
            app=app,
            payload=payload,
            headers=headers or {},
        )
        try:
            resp = await app._handle(request)
        except Exception as e:  # noqa: BLE001 - surfaced to the test
            return e
        return resp

    app.freeze()
    return _run_aiohttp(_do())


def _aiohttp_status(result):
    if isinstance(result, Exception):
        if hasattr(result, 'status'):
            return result.status
        raise result
    return result.status


def _aiohttp_body(result):
    if isinstance(result, Exception):
        return b''
    return result.body or b''


# ---------------------------------------------------------------------------
# Allowed services
# ---------------------------------------------------------------------------


def test_crl_still_served(wsgi_client):
    resp = wsgi_client.get('/testing-ca/crls/interm/latest.crl')
    assert resp.status_code == 200
    assert crl.CertificateList.load(resp.data) is not None


def test_cert_repo_still_served(wsgi_client):
    resp = wsgi_client.get('/testing-ca/certs/root/issued/interm.crt')
    assert resp.status_code == 200
    cert = x509.Certificate.load(resp.data)
    assert 'Intermediate CA' in cert.subject.human_friendly


def test_ocsp_still_served(wsgi_client):
    with open('tests/data/signer2-ocsp-req.der', 'rb') as req_in:
        req_data = req_in.read()
    resp = wsgi_client.post('/testing-ca/ocsp/interm', data=req_data)
    assert resp.status_code == 200
    parsed = ocsp.OCSPResponse.load(resp.data)
    assert parsed['response_status'].native == 'successful'


def test_tsa_still_served(wsgi_client):
    req = tsp.TimeStampReq(
        {
            'version': 'v2',
            'message_imprint': tsp.MessageImprint(
                {
                    'hash_algorithm': algos.DigestAlgorithm(
                        {'algorithm': 'sha256'}
                    ),
                    'hashed_message': hashlib.sha256(b'test').digest(),
                }
            ),
            'nonce': core.Integer(0x1337),
            'cert_req': True,
        }
    )
    resp = wsgi_client.post('/testing-ca/tsa/tsa', data=req.dump())
    assert resp.status_code == 200
    parsed = tsp.TimeStampResp.load(resp.data)
    assert parsed['time_stamp_token'] is not None


# ---------------------------------------------------------------------------
# Denied private key export paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize('client_fixture', ['wsgi_client', 'wsgi_client_no_ui'])
def test_pfx_endpoint_is_explicitly_forbidden(
    request, client_fixture, restricted_cfg
):
    client = request.getfixturevalue(client_fixture)
    resp = client.post(
        '/_certomancer/pfx-download/testing-ca', data={'cert': 'signer1'}
    )
    assert resp.status_code == 403
    assert b'private key' in resp.data.lower()

    # Even a bogus/empty request must not succeed in restricted mode.
    resp = client.post('/_certomancer/pfx-download/testing-ca', data={})
    assert resp.status_code == 403


def test_zip_has_no_pfx(wsgi_client, restricted_cfg):
    resp = wsgi_client.get('/_certomancer/cert-bundle/testing-ca')
    assert resp.status_code == 200
    names = ZipFile(BytesIO(resp.data)).namelist()
    assert names
    assert not [n for n in names if n.endswith('.pfx')]
    assert not [n for n in names if not n.endswith('.cert.pem')]


def test_plugin_endpoint_is_forbidden(wsgi_client):
    resp = wsgi_client.post(
        '/testing-ca/plugin/encrypt-echo/test-endpoint', data=b'x'
    )
    assert resp.status_code == 403


def test_index_still_lists_services(wsgi_client):
    resp = wsgi_client.get('/')
    assert resp.status_code == 200
    assert b'testing-ca' in resp.data
    assert b'pfx-download' not in resp.data


def test_architecture_level_export_guard(restricted_cfg):
    arch = restricted_cfg.get_pki_arch(ArchLabel('testing-ca'))
    with pytest.raises(PrivateKeyExportDisabled):
        arch.package_pkcs12(CertLabel('signer1'))
    with pytest.raises(PrivateKeyExportDisabled):
        arch.zip_certs(BytesIO(), include_pkcs12=True)
    with pytest.raises(PrivateKeyExportDisabled):
        arch.dump_certs(os.path.join(os.getcwd(), 'should-not-exist'),
                        include_pkcs12=True)
    # public-only exports remain usable
    buf = BytesIO()
    arch.zip_certs(buf, include_pkcs12=False)


def test_plugin_guard_at_service_layer():
    cfg = CertomancerConfig.from_file(
        'tests/data/with-plugin.yml',
        'tests/data',
        service_policy=ServicePolicy(restricted=True),
    )
    arch = cfg.get_pki_arch(ArchLabel('testing-ca'))
    with pytest.raises(RestrictedServiceError, match='disabled'):
        arch.service_registry.invoke_plugin(
            PluginLabel('encrypt-echo'),
            ServiceLabel('test-endpoint'),
            b'x',
        )


def test_plugin_allowed_when_reviewed():
    cfg = CertomancerConfig.from_file(
        'tests/data/with-plugin.yml',
        'tests/data',
        service_policy=ServicePolicy(
            restricted=True, allow_plugin_endpoints=True
        ),
    )
    animator = Animator(
        AnimatorArchStore(cfg.pki_archs),
        with_web_ui=False,
        service_policy=cfg.service_policy,
    )
    client = Client(animator, Response)
    resp = client.post(
        '/testing-ca/plugin/encrypt-echo/test-endpoint', data=b'payload'
    )
    assert resp.status_code == 200

    # Allowing plugins is narrowly scoped: PFX stays denied.
    animator_with_ui = Animator(
        AnimatorArchStore(cfg.pki_archs),
        with_web_ui=True,
        service_policy=cfg.service_policy,
    )
    resp = Client(animator_with_ui, Response).post(
        '/_certomancer/pfx-download/testing-ca', data={'cert': 'signer1'}
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# aiohttp parity
# ---------------------------------------------------------------------------


def test_aiohttp_allowed_services(restricted_cfg):
    app = build_animator_app(
        restricted_cfg.pki_archs,
        service_policy=restricted_cfg.service_policy,
    )
    result = _aiohttp_request(app, 'GET', '/testing-ca/crls/interm/latest.crl')
    assert _aiohttp_status(result) == 200


def test_aiohttp_pfx_forbidden(restricted_cfg):
    app = build_animator_app(
        restricted_cfg.pki_archs,
        service_policy=restricted_cfg.service_policy,
    )
    result = _aiohttp_request(
        app,
        'POST',
        '/_certomancer/pfx-download/testing-ca',
        b'cert=signer1',
        {'Content-Type': 'application/x-www-form-urlencoded'},
    )
    assert _aiohttp_status(result) == 403
    assert 'private key' in result.text.lower()


def test_aiohttp_zip_has_no_pfx(restricted_cfg):
    app = build_animator_app(
        restricted_cfg.pki_archs,
        service_policy=restricted_cfg.service_policy,
    )
    result = _aiohttp_request(
        app, 'GET', '/_certomancer/cert-bundle/testing-ca'
    )
    assert _aiohttp_status(result) == 200
    names = ZipFile(BytesIO(_aiohttp_body(result))).namelist()
    assert names
    assert not [n for n in names if n.endswith('.pfx')]


def test_aiohttp_plugin_forbidden(restricted_cfg):
    app = build_animator_app(
        restricted_cfg.pki_archs,
        service_policy=restricted_cfg.service_policy,
    )
    result = _aiohttp_request(
        app,
        'POST',
        '/testing-ca/plugin/encrypt-echo/test-endpoint',
        b'x',
        {'Content-Type': 'application/octet-stream'},
    )
    assert _aiohttp_status(result) == 403


def test_aiohttp_no_ui_pfx_forbidden(restricted_cfg):
    app = build_animator_app(
        restricted_cfg.pki_archs,
        with_web_ui=False,
        service_policy=restricted_cfg.service_policy,
    )
    result = _aiohttp_request(
        app,
        'POST',
        '/_certomancer/pfx-download/testing-ca',
        b'cert=signer1',
        {'Content-Type': 'application/x-www-form-urlencoded'},
    )
    assert _aiohttp_status(result) == 403


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'bad_policy',
    ['yes', 1, {'enabled': 'yes'}, {'enabled': True, 'unknown': 1}],
)
def test_bad_restricted_policy_config(bad_policy):
    with pytest.raises(ConfigurationError):
        ServicePolicy.from_config(bad_policy)


def test_malformed_yaml_is_configuration_error(tmp_path):
    with pytest.raises(ConfigurationError):
        CertomancerConfig.from_yaml('a: [', key_search_dir=str(tmp_path))


def test_restricted_mode_from_config_file(tmp_path):
    cfg = CertomancerConfig.from_yaml(
        """
restricted-mode: true
keysets:
  k:
    keys: {}
pki-architectures: {}
""",
        key_search_dir=str(tmp_path),
    )
    assert cfg.service_policy.restricted


def test_cli_policy_cannot_be_weakened(tmp_path):
    cfg = CertomancerConfig.from_yaml(
        """
restricted-mode: true
keysets:
  k:
    keys: {}
pki-architectures: {}
""",
        key_search_dir=str(tmp_path),
        service_policy=ServicePolicy(restricted=False),
    )
    assert cfg.service_policy.restricted


def test_env_flag_rejects_typo(monkeypatch):
    monkeypatch.setenv('CERTOMANCER_CONFIG', 'tests/data/with-services.yml')
    monkeypatch.setenv('CERTOMANCER_KEY_DIR', 'tests/data')
    monkeypatch.setenv('CERTOMANCER_RESTRICTED', 'yes')
    with pytest.raises(ConfigurationError):
        LazyAnimator()._load()


def test_env_flag_rejects_empty_value(monkeypatch):
    monkeypatch.setenv('CERTOMANCER_CONFIG', 'tests/data/with-services.yml')
    monkeypatch.setenv('CERTOMANCER_KEY_DIR', 'tests/data')
    monkeypatch.setenv('CERTOMANCER_RESTRICTED', '')
    with pytest.raises(ConfigurationError):
        LazyAnimator()._load()


def test_env_flag_enables_restricted(monkeypatch):
    monkeypatch.setenv('CERTOMANCER_CONFIG', 'tests/data/with-services.yml')
    monkeypatch.setenv('CERTOMANCER_KEY_DIR', 'tests/data')
    monkeypatch.setenv('CERTOMANCER_RESTRICTED', '1')
    animator = LazyAnimator()
    animator._load()
    assert animator.animator.service_policy.restricted


# ---------------------------------------------------------------------------
# CLI export paths
# ---------------------------------------------------------------------------


@pytest.fixture
def cli_runner():
    with CliRunner().isolated_filesystem():
        yield CliRunner()


def test_cli_mass_summon_pfx_denied(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        ['--config', str(TEST_DATA_PATH / 'with-services.yml'),
         '--key-root', str(TEST_DATA_PATH),
         '--restricted', 'mass-summon', 'testing-ca', 'outdir'],
    )
    assert result.exit_code != 0
    assert 'private key' in result.output.lower()


def test_cli_mass_summon_no_pfx_allowed(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        ['--config', str(TEST_DATA_PATH / 'with-services.yml'),
         '--key-root', str(TEST_DATA_PATH),
         '--restricted', 'mass-summon', '--no-pfx', 'testing-ca', 'outdir'],
    )
    assert result.exit_code == 0, result.output
    assert 'interm/signer1.cert.pem' in set(collect_files('outdir'))
    assert not [f for f in collect_files('outdir') if f.endswith('.pfx')]


def test_cli_summon_as_pfx_denied(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        ['--config', str(TEST_DATA_PATH / 'with-services.yml'),
         '--key-root', str(TEST_DATA_PATH),
         '--restricted', 'summon', '--as-pfx', 'testing-ca', 'signer1',
         'out.pfx'],
    )
    assert result.exit_code != 0
    assert 'private key' in result.output.lower()


# ---------------------------------------------------------------------------
# Applying the shipped example and library-construction defaults
# ---------------------------------------------------------------------------

EXAMPLE_CFG = CertomancerConfig.from_file('example-restricted.yml')


def test_example_config_allows_public_services():
    animator = Animator(
        AnimatorArchStore(EXAMPLE_CFG.pki_archs),
        with_web_ui=True,
        service_policy=EXAMPLE_CFG.service_policy,
    )
    client = Client(animator, Response)

    resp = client.get('/testing-ca/crls/interm/latest.crl')
    assert resp.status_code == 200

    resp = client.get('/testing-ca/certs/root/issued/interm.crt')
    assert resp.status_code == 200
    assert x509.Certificate.load(resp.data) is not None

    resp = client.get('/_certomancer/cert-bundle/testing-ca')
    assert resp.status_code == 200
    names = ZipFile(BytesIO(resp.data)).namelist()
    assert names and not [n for n in names if n.endswith('.pfx')]

    resp = client.post(
        '/_certomancer/pfx-download/testing-ca', data={'cert': 'signer1'}
    )
    assert resp.status_code == 403


def test_adapter_derives_policy_from_architectures():
    # No explicit service_policy: the Animator must still respect the
    # restriction recorded on the PKI architecture.
    animator = Animator(
        AnimatorArchStore(EXAMPLE_CFG.pki_archs), with_web_ui=True
    )
    client = Client(animator, Response)
    resp = client.post(
        '/_certomancer/pfx-download/testing-ca', data={'cert': 'signer1'}
    )
    assert resp.status_code == 403


def test_aiohttp_adapter_derives_policy_from_architectures():
    app = build_animator_app(EXAMPLE_CFG.pki_archs)
    result = _aiohttp_request(
        app,
        'POST',
        '/_certomancer/pfx-download/testing-ca',
        b'cert=signer1',
        {'Content-Type': 'application/x-www-form-urlencoded'},
    )
    assert _aiohttp_status(result) == 403


# ---------------------------------------------------------------------------
# Fail-closed behaviour on bad configuration
# ---------------------------------------------------------------------------


def test_wsgi_entrypoint_fails_closed_on_bad_config(
    tmp_path, monkeypatch
):
    bad_cfg = tmp_path / 'bad.yml'
    bad_cfg.write_text('restricted-mode: definitely-not-a-bool\n')
    monkeypatch.setenv('CERTOMANCER_CONFIG', str(bad_cfg))
    monkeypatch.setenv('CERTOMANCER_KEY_DIR', str(tmp_path))
    client = Client(LazyAnimator(), Response)
    resp = client.get('/testing-ca/crls/interm/latest.crl')
    assert resp.status_code == 500
    assert b'configuration error' in resp.data.lower()


def test_wsgi_entrypoint_fails_closed_on_missing_env(monkeypatch):
    monkeypatch.delenv('CERTOMANCER_CONFIG', raising=False)
    monkeypatch.delenv('CERTOMANCER_KEY_DIR', raising=False)
    client = Client(LazyAnimator(), Response)
    resp = client.get('/')
    assert resp.status_code == 500


def test_cli_bad_restricted_config_exits_with_error(tmp_path, cli_runner):
    bad_cfg = tmp_path / 'bad.yml'
    bad_cfg.write_text('restricted-mode: 42\n')
    result = cli_runner.invoke(
        cli_root,
        ['--config', str(bad_cfg), 'summon', 'arch', 'cert'],
    )
    assert result.exit_code != 0
    assert 'Configuration problem' in result.output


def test_allow_plugins_flag_does_not_affect_public_services(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        ['--config', str(TEST_DATA_PATH / 'with-services.yml'),
         '--key-root', str(TEST_DATA_PATH),
         '--restricted', '--allow-plugin-endpoints',
         'summon', 'testing-ca', 'signer1'],
    )
    assert result.exit_code == 0, result.output


def test_cli_summon_public_cert_allowed(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        ['--config', str(TEST_DATA_PATH / 'with-services.yml'),
         '--key-root', str(TEST_DATA_PATH),
         '--restricted', 'summon', 'testing-ca', 'signer1'],
    )
    assert result.exit_code == 0, result.output
    assert b'CERTIFICATE' in result.stdout_bytes
