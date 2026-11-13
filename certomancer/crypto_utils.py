import hashlib
import logging
import threading
from collections import OrderedDict
from typing import NamedTuple, Optional, Tuple

from asn1crypto import algos, keys, pem, x509
from asn1crypto.keys import PublicKeyInfo
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
)

logger = logging.getLogger(__name__)


class PrivateKeyCacheStats(NamedTuple):
    """Usage statistics for a :class:`PrivateKeyCache`."""

    hits: int
    misses: int
    evictions: int
    loads: int
    size: int
    capacity: int


class PrivateKeyCache:
    """
    Bounded, content-addressed cache of deserialised pyca private keys.

    Cache entries are keyed on a hash of the DER-encoded PKCS#8
    :class:`asn1crypto.keys.PrivateKeyInfo`, never on a user-supplied label.
    Two distinct keys with the same label therefore never collide, while the
    same key material presented repeatedly (e.g. when batch-generating OCSP
    responses, CRLs and certificates) is only parsed once.

    The cache holds at most ``capacity`` entries: when it is full, the least
    recently used key is evicted, so private key objects cannot accumulate
    without bound. Set ``capacity`` to ``0`` to disable caching altogether.
    """

    def __init__(self, capacity: int = 16):
        if capacity < 0:
            raise ValueError("Private key cache capacity cannot be negative")
        self._capacity = capacity
        self._entries: 'OrderedDict[str, object]' = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._loads = 0
        self._lock = threading.RLock()

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def enabled(self) -> bool:
        return self._capacity > 0

    @staticmethod
    def cache_key(private_key: keys.PrivateKeyInfo) -> str:
        """Return the content-derived cache key for ``private_key``."""
        return hashlib.sha256(private_key.dump()).hexdigest()

    def get_or_load(
        self,
        private_key: keys.PrivateKeyInfo,
        load_fn,
    ):
        """
        Return the cached pyca private key for ``private_key``, parsing it
        with ``load_fn`` on a cache miss.

        ``load_fn`` receives the DER-encoded PKCS#8 bytes and must return the
        deserialised pyca private key object.
        """
        if self._capacity == 0:
            self._misses += 1
            self._loads += 1
            return load_fn(private_key.dump())

        key_id = self.cache_key(private_key)
        with self._lock:
            try:
                cached = self._entries.pop(key_id)
            except KeyError:
                self._misses += 1
                self._loads += 1
                loaded = load_fn(private_key.dump())
                self._entries[key_id] = loaded
                while len(self._entries) > self._capacity:
                    self._entries.popitem(last=False)
                    self._evictions += 1
                return loaded
            self._hits += 1
            self._entries[key_id] = cached
            return cached

    def clear(self) -> None:
        """Drop all cached private key objects and reset statistics."""
        with self._lock:
            self._entries.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0
            self._loads = 0

    def stats(self) -> PrivateKeyCacheStats:
        with self._lock:
            return PrivateKeyCacheStats(
                hits=self._hits,
                misses=self._misses,
                evictions=self._evictions,
                loads=self._loads,
                size=len(self._entries),
                capacity=self._capacity,
            )


class CryptoBackend:
    def load_private_key(
        self, key_bytes: bytes, password: Optional[bytes]
    ) -> Tuple[keys.PrivateKeyInfo, keys.PublicKeyInfo]:
        raise NotImplementedError

    def load_public_key(self, key_bytes: bytes) -> keys.PublicKeyInfo:
        raise NotImplementedError

    def generic_sign(
        self,
        private_key: keys.PrivateKeyInfo,
        tbs_bytes: bytes,
        sd_algo: algos.SignedDigestAlgorithm,
    ) -> bytes:
        raise NotImplementedError

    def optimal_pss_params(
        self, key: PublicKeyInfo, digest_algo: str
    ) -> algos.RSASSAPSSParams:
        raise NotImplementedError


def _load_private_key_from_pemder_data(
    key_bytes: bytes, passphrase: Optional[bytes]
) -> keys.PrivateKeyInfo:
    load_fun = (
        serialization.load_pem_private_key
        if pem.detect(key_bytes)
        else serialization.load_der_private_key
    )

    private_key = load_fun(key_bytes, password=passphrase)
    return keys.PrivateKeyInfo.load(
        private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


class PycaCryptographyBackend(CryptoBackend):
    def __init__(self, private_key_cache_size: int = 16):
        # Bounded cache of deserialised pyca private keys, shared across all
        # calls to load_private_key() and generic_sign(). The cache is keyed
        # on the key material itself, so callers do not need to coordinate
        # labels, and at most ``private_key_cache_size`` key objects are
        # retained at any time.
        self.private_key_cache = PrivateKeyCache(private_key_cache_size)

    @staticmethod
    def _deserialise_private_key(key_der: bytes):
        return serialization.load_der_private_key(key_der, password=None)

    def _get_private_key(self, private_key: keys.PrivateKeyInfo):
        return self.private_key_cache.get_or_load(
            private_key, self._deserialise_private_key
        )

    def load_private_key(
        self, key_bytes: bytes, password: Optional[bytes]
    ) -> Tuple[keys.PrivateKeyInfo, keys.PublicKeyInfo]:
        priv_key_info = _load_private_key_from_pemder_data(key_bytes, password)
        assert isinstance(priv_key_info, keys.PrivateKeyInfo)

        # Reuse the same deserialised object that generic_sign() will use
        # later, so loading a key also warms the signing cache.
        priv_key = self._get_private_key(priv_key_info)
        pub_key_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_key_info = keys.PublicKeyInfo.load(pub_key_bytes)
        return priv_key_info, pub_key_info

    def load_public_key(self, key_bytes: bytes) -> keys.PublicKeyInfo:
        if key_bytes.startswith(b'----'):
            key_bytes = pem.unarmor(key_bytes)[2]
        return keys.PublicKeyInfo.load(key_bytes)

    def generic_sign(
        self,
        private_key: keys.PrivateKeyInfo,
        tbs_bytes: bytes,
        sd_algo: algos.SignedDigestAlgorithm,
    ) -> bytes:
        from cryptography.hazmat.primitives.asymmetric import padding

        # The cache lookup is the only DER parse; the returned object is
        # reused across all requests that present the same key material.
        priv_key = self._get_private_key(private_key)

        # Padding, digest and PSS parameters are constructed fresh from the
        # algorithm object of *this* request on every call, so reusing the
        # key object never leaks parameters between signatures.
        sig_algo = sd_algo.signature_algo
        if sig_algo == 'rsassa_pkcs1v15':
            if not isinstance(priv_key, rsa.RSAPrivateKey):
                raise TypeError(
                    f"Signature algorithm {sig_algo} requires an RSA key, "
                    f"got {type(priv_key).__name__}"
                )
            return priv_key.sign(
                tbs_bytes,
                padding.PKCS1v15(),
                self._build_hash(sd_algo),
            )
        elif sig_algo == 'rsassa_pss':
            if not isinstance(priv_key, rsa.RSAPrivateKey):
                raise TypeError(
                    f"Signature algorithm {sig_algo} requires an RSA key, "
                    f"got {type(priv_key).__name__}"
                )
            try:
                parameters = sd_algo['parameters']
                # asn1crypto represents absent CHOICE parameters as Void
                if not isinstance(parameters, algos.RSASSAPSSParams):
                    raise ValueError
            except (KeyError, ValueError, TypeError):
                raise ValueError(
                    "rsassa_pss signatures require explicit PSS parameters"
                )

            mga: algos.MaskGenAlgorithm = parameters['mask_gen_algorithm']
            if mga['algorithm'].native != 'mgf1':
                raise NotImplementedError(
                    f"Unsupported PSS mask generation algorithm "
                    f"{mga['algorithm'].native}; only MGF1 is supported"
                )

            mgf_md_name = mga['parameters']['algorithm'].native
            salt_len: int = parameters['salt_length'].native
            pss_padding = padding.PSS(
                mgf=padding.MGF1(algorithm=self._build_hash_named(mgf_md_name)),
                salt_length=salt_len,
            )
            return priv_key.sign(
                tbs_bytes, pss_padding, self._build_hash(sd_algo)
            )
        elif sig_algo == 'dsa':
            if not isinstance(priv_key, dsa.DSAPrivateKey):
                raise TypeError(
                    f"Signature algorithm {sig_algo} requires a DSA key, "
                    f"got {type(priv_key).__name__}"
                )
            return priv_key.sign(tbs_bytes, self._build_hash(sd_algo))
        elif sig_algo == 'ecdsa':
            if not isinstance(priv_key, ec.EllipticCurvePrivateKey):
                raise TypeError(
                    f"Signature algorithm {sig_algo} requires an EC key, "
                    f"got {type(priv_key).__name__}"
                )
            return priv_key.sign(
                tbs_bytes,
                signature_algorithm=ec.ECDSA(self._build_hash(sd_algo)),
            )
        elif sig_algo == 'ed25519':
            if not isinstance(priv_key, ed25519.Ed25519PrivateKey):
                raise TypeError(
                    f"Signature algorithm {sig_algo} requires an Ed25519 key, "
                    f"got {type(priv_key).__name__}"
                )
            return priv_key.sign(tbs_bytes)
        elif sig_algo == 'ed448':
            if not isinstance(priv_key, ed448.Ed448PrivateKey):
                raise TypeError(
                    f"Signature algorithm {sig_algo} requires an Ed448 key, "
                    f"got {type(priv_key).__name__}"
                )
            return priv_key.sign(tbs_bytes)
        else:
            raise NotImplementedError(
                f"The signature algorithm {sig_algo} is unsupported"
            )

    @staticmethod
    def _build_hash_named(hash_algo: str):
        from cryptography.hazmat.primitives import hashes

        try:
            hash_cls = getattr(hashes, hash_algo.upper())
        except AttributeError as e:
            raise ValueError(
                f"Unsupported digest algorithm '{hash_algo}'"
            ) from e
        return hash_cls()

    def _build_hash(self, sd_algo: algos.SignedDigestAlgorithm):
        return self._build_hash_named(sd_algo.hash_algo)

    def optimal_pss_params(
        self, key: keys.PublicKeyInfo, digest_algo: str
    ) -> algos.RSASSAPSSParams:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        digest_algo = digest_algo.lower()

        loaded_key = serialization.load_der_public_key(key.dump())
        assert isinstance(loaded_key, rsa.RSAPublicKey)
        md = getattr(hashes, digest_algo.upper())
        # the PSS salt calculation function is not in the .pyi file, apparently.
        # noinspection PyUnresolvedReferences
        optimal_salt_len = padding.calculate_max_pss_salt_length(
            loaded_key, md()
        )
        return algos.RSASSAPSSParams(
            {
                'hash_algorithm': algos.DigestAlgorithm(
                    {'algorithm': digest_algo}
                ),
                'mask_gen_algorithm': algos.MaskGenAlgorithm(
                    {
                        'algorithm': 'mgf1',
                        'parameters': algos.DigestAlgorithm(
                            {'algorithm': digest_algo}
                        ),
                    }
                ),
                'salt_length': optimal_salt_len,
            }
        )


CRYPTO_BACKEND: CryptoBackend = PycaCryptographyBackend()


def generic_sign(
    private_key: keys.PrivateKeyInfo,
    tbs_bytes: bytes,
    signature_algo: algos.SignedDigestAlgorithm,
) -> bytes:
    return CRYPTO_BACKEND.generic_sign(private_key, tbs_bytes, signature_algo)


def load_private_key(
    key_bytes: bytes, password: Optional[bytes]
) -> Tuple[keys.PrivateKeyInfo, keys.PublicKeyInfo]:
    return CRYPTO_BACKEND.load_private_key(key_bytes, password)


def load_public_key(key_bytes: bytes) -> keys.PublicKeyInfo:
    return CRYPTO_BACKEND.load_public_key(key_bytes)


def optimal_pss_params(
    key_algo: keys.PublicKeyInfo, digest_algo: str
) -> algos.RSASSAPSSParams:
    return CRYPTO_BACKEND.optimal_pss_params(key_algo, digest_algo)


def load_certs_from_pemder(cert_files):
    """
    A convenience function to load PEM/DER-encoded certificates from files.

    :param cert_files:
        An iterable of file names.
    :return:
        A generator producing :class:`.asn1crypto.x509.Certificate` objects.
    """

    for cert_file in cert_files:
        with open(cert_file, 'rb') as f:
            ca_chain_bytes = f.read()
        # use the pattern from the asn1crypto docs
        # to distinguish PEM/DER and read multiple certs
        # from one PEM file (if necessary)
        if pem.detect(ca_chain_bytes):
            pems = pem.unarmor(ca_chain_bytes, multiple=True)
            for type_name, _, der in pems:
                if type_name is None or type_name.lower() == 'certificate':
                    yield x509.Certificate.load(der)
                else:  # pragma: nocover
                    logger.debug(
                        f'Skipping PEM block of type {type_name} in '
                        f'certificate file.'
                    )
        else:
            # no need to unarmor, just try to load it immediately
            yield x509.Certificate.load(ca_chain_bytes)


def load_cert_from_pemder(cert_file):
    """
    A convenience function to load a single PEM/DER-encoded certificate
    from a file.

    :param cert_file:
        A file name.
    :return:
        An :class:`.asn1crypto.x509.Certificate` object.
    """
    certs = list(load_certs_from_pemder([cert_file]))
    if len(certs) != 1:
        raise ValueError(f"Number of certs in {cert_file} should be exactly 1")
    return certs[0]
