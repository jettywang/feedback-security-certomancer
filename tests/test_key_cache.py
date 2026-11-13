"""
Tests for the bounded, content-addressed private key cache in the PyCA
backend, and for per-request signature parameter handling.
"""

import importlib
from datetime import datetime, timezone

import pytest
from asn1crypto import algos, crl, keys, ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from certomancer.crypto_utils import (
    PrivateKeyCache,
    PycaCryptographyBackend,
)
from certomancer.registry import (
    ArchLabel,
    CertLabel,
    CertomancerConfig,
    ServiceLabel,
)

importlib.import_module('certomancer.default_plugins')


RSA_KEY_SIZE = 2048


def _rsa_private_key():
    return rsa.generate_private_key(
        public_exponent=65537, key_size=RSA_KEY_SIZE
    )


def _ec_private_key():
    return ec.generate_private_key(ec.SECP256R1())


def _private_key_info(priv_key) -> keys.PrivateKeyInfo:
    der = priv_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return keys.PrivateKeyInfo.load(der)


def _public_der(priv_key) -> bytes:
    return priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _pkcs1v15_algo(hash_name='sha256') -> algos.SignedDigestAlgorithm:
    return algos.SignedDigestAlgorithm({'algorithm': f'{hash_name}_rsa'})


def _pss_algo(
    hash_name='sha256', mgf_name='sha256', salt_length=32
) -> algos.SignedDigestAlgorithm:
    return algos.SignedDigestAlgorithm(
        {
            'algorithm': 'rsassa_pss',
            'parameters': algos.RSASSAPSSParams(
                {
                    'hash_algorithm': algos.DigestAlgorithm(
                        {'algorithm': hash_name}
                    ),
                    'mask_gen_algorithm': algos.MaskGenAlgorithm(
                        {
                            'algorithm': 'mgf1',
                            'parameters': algos.DigestAlgorithm(
                                {'algorithm': mgf_name}
                            ),
                        }
                    ),
                    'salt_length': salt_length,
                }
            ),
        }
    )


def _verify_pkcs1v15(pub_key, signature, data, hash_name):
    pub_key.verify(
        signature,
        data,
        padding.PKCS1v15(),
        getattr(hashes, hash_name.upper())(),
    )


def _verify_pss(pub_key, signature, data, hash_name, salt_length):
    pub_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(getattr(hashes, hash_name.upper())()),
            salt_length=salt_length,
        ),
        getattr(hashes, hash_name.upper())(),
    )


@pytest.fixture
def backend():
    return PycaCryptographyBackend()


def test_cache_stats_and_load_count(backend):
    priv_key = _rsa_private_key()
    priv_key_info = _private_key_info(priv_key)
    data = b'certomancer batch signing workload'

    stats_before = backend.private_key_cache.stats()
    assert stats_before.loads == 0

    # First call parses the key; every subsequent call with the same key
    # material must be served from the cache.
    backend.generic_sign(priv_key_info, data, _pkcs1v15_algo())
    stats = backend.private_key_cache.stats()
    assert stats.loads == 1
    assert stats.misses == 1
    assert stats.hits == 0
    assert stats.size == 1

    for _ in range(9):
        backend.generic_sign(priv_key_info, data, _pkcs1v15_algo())
    stats = backend.private_key_cache.stats()
    assert stats.loads == 1
    assert stats.hits == 9
    assert stats.size == 1


def test_interleaved_algorithms_share_single_loaded_key(backend):
    priv_key = _rsa_private_key()
    pub_key = priv_key.public_key()
    priv_key_info = _private_key_info(priv_key)

    # Interleave PKCS#1 v1.5 with PSS using different salt lengths and
    # different digests, reusing one key object throughout.
    requests = [
        ('pkcs1v15', _pkcs1v15_algo('sha256')),
        ('pss-max', _pss_algo('sha256', 'sha256', 222)),
        ('pkcs1v15-sha512', _pkcs1v15_algo('sha512')),
        ('pss-zero', _pss_algo('sha256', 'sha256', 0)),
        ('pss-sha512', _pss_algo('sha512', 'sha512', 64)),
        ('pss-default', _pss_algo('sha256', 'sha256', 32)),
    ]

    signatures = []
    for index, (_, sd_algo) in enumerate(requests):
        data = f'payload-{index}'.encode()
        signatures.append(
            (data, sd_algo, backend.generic_sign(priv_key_info, data, sd_algo))
        )

    stats = backend.private_key_cache.stats()
    assert stats.loads == 1
    assert stats.hits == len(requests) - 1

    # Every signature must verify under the exact algorithm, digest and PSS
    # parameters of the request that produced it.
    for data, sd_algo, signature in signatures:
        if sd_algo.signature_algo == 'rsassa_pkcs1v15':
            _verify_pkcs1v15(pub_key, signature, data, sd_algo.hash_algo)
        else:
            salt_len = sd_algo['parameters']['salt_length'].native
            _verify_pss(
                pub_key,
                signature,
                data,
                sd_algo.hash_algo,
                salt_len,
            )

    # Parameters are per-request: a PSS signature with zero-length salt must
    # not verify when checked against a non-zero expected salt length.
    zero_salt_data, _, zero_salt_sig = signatures[3]
    with pytest.raises(Exception):
        _verify_pss(pub_key, zero_salt_sig, zero_salt_data, 'sha256', 32)

    # Signatures are randomised: two PSS calls over identical input differ.
    sig_a = backend.generic_sign(
        priv_key_info, b'same', _pss_algo(salt_length=32)
    )
    sig_b = backend.generic_sign(
        priv_key_info, b'same', _pss_algo(salt_length=32)
    )
    assert sig_a != sig_b
    _verify_pss(pub_key, sig_a, b'same', 'sha256', 32)
    _verify_pss(pub_key, sig_b, b'same', 'sha256', 32)


def test_same_label_distinct_keys_do_not_collide(backend):
    # The cache must recognise keys by their content, not by any label: two
    # completely different RSA keys presented under the same label each get
    # their own cache entry, and signatures only verify with the matching
    # public key.
    key_a = _rsa_private_key()
    key_b = _rsa_private_key()
    info_a = _private_key_info(key_a)
    info_b = _private_key_info(key_b)
    assert _public_der(key_a) != _public_der(key_b)

    algo = _pkcs1v15_algo()
    sig_a = backend.generic_sign(info_a, b'shared-label-payload', algo)
    sig_b = backend.generic_sign(info_b, b'shared-label-payload', algo)
    assert sig_a != sig_b

    _verify_pkcs1v15(
        key_a.public_key(), sig_a, b'shared-label-payload', 'sha256'
    )
    _verify_pkcs1v15(
        key_b.public_key(), sig_b, b'shared-label-payload', 'sha256'
    )
    with pytest.raises(Exception):
        _verify_pkcs1v15(
            key_b.public_key(), sig_a, b'shared-label-payload', 'sha256'
        )
    with pytest.raises(Exception):
        _verify_pkcs1v15(
            key_a.public_key(), sig_b, b'shared-label-payload', 'sha256'
        )

    stats = backend.private_key_cache.stats()
    assert stats.loads == 2
    assert stats.size == 2

    # Going back to the first key hits the cache instead of reparsing it.
    backend.generic_sign(info_a, b'again', algo)
    assert backend.private_key_cache.stats().loads == 2
    assert backend.private_key_cache.stats().hits >= 1


def test_cache_is_bounded_and_evicts_lru():
    backend = PycaCryptographyBackend(private_key_cache_size=2)
    key_infos = [_private_key_info(_rsa_private_key()) for _ in range(4)]
    algo = _pkcs1v15_algo()

    for info in key_infos:
        backend.generic_sign(info, b'data', algo)
    stats = backend.private_key_cache.stats()
    assert stats.size == 2
    assert stats.loads == 4
    assert stats.evictions == 2

    # The two most recently used keys stay cached; touching one again is a hit.
    backend.generic_sign(key_infos[-1], b'data', algo)
    assert backend.private_key_cache.stats().loads == 4

    # The evicted key has to be parsed again, and its re-entry pushes the
    # current LRU entry out.
    backend.generic_sign(key_infos[0], b'data', algo)
    stats = backend.private_key_cache.stats()
    assert stats.loads == 5
    assert stats.size == 2
    assert stats.evictions == 3


def test_cache_can_be_disabled_and_cleared():
    backend = PycaCryptographyBackend(private_key_cache_size=0)
    assert backend.private_key_cache.enabled is False
    info = _private_key_info(_rsa_private_key())
    algo = _pkcs1v15_algo()

    for _ in range(3):
        backend.generic_sign(info, b'data', algo)
    stats = backend.private_key_cache.stats()
    assert stats.size == 0
    assert stats.loads == 3
    assert stats.hits == 0

    enabled_backend = PycaCryptographyBackend(private_key_cache_size=4)
    enabled_backend.generic_sign(info, b'data', algo)
    assert enabled_backend.private_key_cache.stats().size == 1
    enabled_backend.private_key_cache.clear()
    cleared = enabled_backend.private_key_cache.stats()
    assert cleared.size == 0
    assert cleared.loads == 0
    assert cleared.hits == 0


def test_invalid_cache_capacity_rejected():
    with pytest.raises(ValueError):
        PrivateKeyCache(-1)


def test_key_algorithm_mismatch_fails_explicitly(backend):
    ec_info = _private_key_info(_ec_private_key())

    with pytest.raises(TypeError, match='requires an RSA key'):
        backend.generic_sign(ec_info, b'data', _pkcs1v15_algo())
    with pytest.raises(TypeError, match='requires an RSA key'):
        backend.generic_sign(ec_info, b'data', _pss_algo())

    rsa_info = _private_key_info(_rsa_private_key())
    ecdsa_algo = algos.SignedDigestAlgorithm({'algorithm': 'sha256_ecdsa'})
    with pytest.raises(TypeError, match='requires an EC key'):
        backend.generic_sign(rsa_info, b'data', ecdsa_algo)


def test_pss_requires_explicit_parameters(backend):
    rsa_info = _private_key_info(_rsa_private_key())
    bare_pss = algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pss'})
    with pytest.raises(ValueError, match='explicit PSS parameters'):
        backend.generic_sign(rsa_info, b'data', bare_pss)


def test_unsupported_digest_fails_explicitly(backend):
    with pytest.raises(ValueError, match="Unsupported digest algorithm"):
        backend._build_hash_named('not-a-real-digest')


def test_load_private_key_warms_signing_cache(backend):
    priv_key = _rsa_private_key()
    pem_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_key_info, _ = backend.load_private_key(pem_bytes, None)
    assert backend.private_key_cache.stats().loads == 1

    # Signing with the loaded key reuses the exact same cached object.
    backend.generic_sign(priv_key_info, b'data', _pkcs1v15_algo())
    stats = backend.private_key_cache.stats()
    assert stats.loads == 1
    assert stats.hits == 1


def test_batch_cert_crl_ocsp_reuses_loaded_keys(monkeypatch):
    # End-to-end proof: batch-generating certificates, CRLs and OCSP
    # responses for one architecture must not reparse the same private key
    # from DER on every signing call.
    backend = PycaCryptographyBackend()
    # The module-level wrappers resolve CRYPTO_BACKEND at call time, so
    # swapping the module attribute redirects all key loads/signs to our
    # instrumented backend.
    from certomancer import crypto_utils

    monkeypatch.setattr(crypto_utils, 'CRYPTO_BACKEND', backend)

    cfg = CertomancerConfig.from_file(
        'tests/data/with-services.yml', 'tests/data'
    )
    arch = cfg.get_pki_arch(ArchLabel('testing-ca'))

    parse_calls = 0
    original = backend._deserialise_private_key

    def counting_parse(key_der):
        nonlocal parse_calls
        parse_calls += 1
        return original(key_der)

    backend.private_key_cache.clear()
    monkeypatch.setattr(backend, '_deserialise_private_key', counting_parse)

    # Sign a mix of artefacts: certificates, a CRL and OCSP responses.
    arch.get_cert(CertLabel('interm'))
    arch.get_cert(CertLabel('signer1'))
    arch.get_cert(CertLabel('signer2'))
    some_crl: crl.CertificateList = arch.service_registry.get_crl(
        ServiceLabel('interm'),
        at_time=datetime(2020, 11, 1, tzinfo=timezone.utc),
    )
    assert some_crl['signature_algorithm'].signature_algo in (
        'rsassa_pkcs1v15',
        'rsassa_pss',
    )

    with open('tests/data/signer2-ocsp-req.der', 'rb') as req_in:
        ocsp_request = ocsp.OCSPRequest.load(req_in.read())
    responder = arch.service_registry.summon_responder(
        ServiceLabel('interm'),
        at_time=datetime(2020, 11, 5, tzinfo=timezone.utc),
    )
    ocsp_response = responder.build_ocsp_response(ocsp_request)
    assert ocsp_response['response_status'].native == 'successful'

    stats = backend.private_key_cache.stats()
    distinct_keys = stats.size + stats.evictions
    # Each distinct key was parsed at most once even though several signing
    # operations share the same key.
    assert parse_calls == stats.loads == distinct_keys
    assert stats.hits > 0
    # The same intermediate key signed a cert, the CRL and an OCSP response,
    # so there were strictly more signing operations than key parses.
    assert stats.hits + stats.misses > parse_calls
    # The cache never retains more objects than its capacity.
    assert stats.size <= stats.capacity
