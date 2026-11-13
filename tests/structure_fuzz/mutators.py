"""Deterministic, structure-aware DER mutators for OCSP and TSA requests.

The mutators deliberately stay *above* the byte-fuzzing layer: every output
is rebuilt through asn1crypto so that the resulting blob remains parseable
ASN.1.  That keeps the fuzzer focused on the interesting failure mode for a
signing service -- requests that decode cleanly but carry contradictory or
out-of-spec semantics -- instead of wasting budget on BER/DER decoder errors.

A small seeded :class:`~random.Random` instance drives all length choices so
runs are fully reproducible.
"""

import hashlib
import random

from asn1crypto import algos, core, ocsp, tsp

# Hard resource ceiling used by the length mutations.  Kept deliberately
# modest so the fixed-seed run stays fast; the fuzzer never approaches it with
# a correctly budgeted service.
MAX_RESOURCE_BYTES = 1 << 20  # 1 MiB
# Lengths exercised by the resource-budget mutations.  The first entries stay
# small (cheap, still semantically meaningful) and the last one probes the
# service's request-size guard.
BUDGET_LENGTHS = (0, 1, 7, 20, 32, 64, 255, 4096, 65537, MAX_RESOURCE_BYTES)

OCSP_SEED_FILE = 'tests/data/signer2-ocsp-req.der'


def build_tsa_seed_der() -> bytes:
    """Build the canonical TSA request used as the offline seed.

    There is no captured TSA sample under ``tests/data``, so we generate the
    same well-formed request that the existing tests post.
    """
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
    return req.dump()


def _reload(cls, der: bytes):
    return cls.load(der)


def _nonce_extension(value: bytes) -> ocsp.TBSRequestExtension:
    return ocsp.TBSRequestExtension(
        {
            'extn_id': 'nonce',
            'extn_value': core.ParsableOctetString(
                core.OctetString(value).dump()
            ),
        }
    )


def _acceptable_responses_extension() -> ocsp.TBSRequestExtension:
    return ocsp.TBSRequestExtension(
        {
            'extn_id': 'acceptable_responses',
            'extn_value': core.ParsableOctetString(
                ocsp.AcceptableResponses(
                    ['1.3.6.1.5.5.7.48.1.1']
                ).dump()
            ),
        }
    )


def _unknown_extension(critical: bool) -> ocsp.TBSRequestExtension:
    return ocsp.TBSRequestExtension(
        {
            'extn_id': ocsp.TBSRequestExtensionId('1.2.3.4.5.6.7.1'),
            'critical': critical,
            'extn_value': core.ParsableOctetString(b'\x04\x03abc'),
        }
    )


def _cert_id_with(
    template: ocsp.CertId,
    *,
    hash_algorithm=None,
    name_hash=None,
    key_hash=None,
    serial=None,
) -> ocsp.CertId:
    return ocsp.CertId(
        {
            'hash_algorithm': algos.DigestAlgorithm(
                {'algorithm': hash_algorithm}
            )
            if hash_algorithm is not None
            else template['hash_algorithm'],
            'issuer_name_hash': template['issuer_name_hash'].native
            if name_hash is None
            else name_hash,
            'issuer_key_hash': template['issuer_key_hash'].native
            if key_hash is None
            else key_hash,
            'serial_number': core.Integer(
                template['serial_number'].native if serial is None else serial
            ),
        }
    )


def mutate_ocsp(seed_der: bytes, rng: random.Random):
    """Yield ``(case_id, description, der_bytes)`` OCSP mutations.

    Every emitted blob re-parses as :class:`ocsp.OCSPRequest`.
    """
    base = _reload(ocsp.OCSPRequest, seed_der)
    tbs = base['tbs_request']
    first_request = tbs['request_list'][0]
    cert_id: ocsp.CertId = first_request['req_cert']
    nonce_ext = tbs['request_extensions'][0]

    def emit(case_id, description, request_obj):
        der = request_obj.dump()
        # round-trip guarantee: every case must be valid ASN.1
        assert ocsp.OCSPRequest.load(der) is not None
        return case_id, description, der

    # --- CertID semantics -------------------------------------------------
    for length in BUDGET_LENGTHS:
        mutated = ocsp.OCSPRequest.load(seed_der)
        cid = mutated['tbs_request']['request_list'][0]['req_cert']
        cid_new = _cert_id_with(
            cid, name_hash=b'\x00' * length, key_hash=b'\x11' * length
        )
        mutated['tbs_request']['request_list'][0]['req_cert'] = cid_new
        yield emit(
            f'ocsp-certid-hashlen-{length}',
            f'CertID issuer hashes both {length} bytes long',
            mutated,
        )

    for algo in ('md5', 'sha256', 'sha512'):
        mutated = ocsp.OCSPRequest.load(seed_der)
        width = 16 if algo == 'md5' else (32 if algo == 'sha256' else 64)
        cid = mutated['tbs_request']['request_list'][0]['req_cert']
        mutated['tbs_request']['request_list'][0]['req_cert'] = _cert_id_with(
            cid,
            hash_algorithm=algo,
            name_hash=b'\x22' * width,
            key_hash=b'\x33' * width,
        )
        yield emit(
            f'ocsp-certid-algo-{algo}',
            f'CertID hash algorithm switched to {algo}',
            mutated,
        )

    # mismatched algorithm vs. hash widths (parseable but internally
    # contradictory: sha256 OID paired with sha1-width digests)
    mutated = ocsp.OCSPRequest.load(seed_der)
    cid = mutated['tbs_request']['request_list'][0]['req_cert']
    mutated['tbs_request']['request_list'][0]['req_cert'] = _cert_id_with(
        cid,
        hash_algorithm='sha256',
        name_hash=cert_id['issuer_name_hash'].native,
        key_hash=cert_id['issuer_key_hash'].native,
    )
    yield emit(
        'ocsp-certid-sha256-oid-sha1-width',
        'sha256 CertID OID with 20-byte (sha1-width) hashes',
        mutated,
    )

    for serial in (0, 1, 2 ** 63, 2 ** 127):
        mutated = ocsp.OCSPRequest.load(seed_der)
        cid = mutated['tbs_request']['request_list'][0]['req_cert']
        mutated['tbs_request']['request_list'][0]['req_cert'] = _cert_id_with(
            cid, serial=serial
        )
        yield emit(
            f'ocsp-certid-serial-{serial}',
            f'CertID serial number replaced with {serial}',
            mutated,
        )

    # --- request list cardinality ----------------------------------------
    empty_tbs = ocsp.TBSRequest(
        {
            'version': 'v1',
            'request_list': ocsp.Requests([]),
            'request_extensions': ocsp.TBSRequestExtensions([nonce_ext]),
        }
    )
    yield emit(
        'ocsp-empty-request-list',
        'TBSRequest.request_list is an empty SEQUENCE OF',
        ocsp.OCSPRequest({'tbs_request': empty_tbs}),
    )

    for copies in (2, 3, 8):
        dup_tbs = ocsp.TBSRequest.load(tbs.dump())
        dup_tbs['request_list'] = ocsp.Requests(
            [first_request] * copies
        )
        yield emit(
            f'ocsp-duplicate-requests-{copies}',
            f'same CertID repeated {copies} times in request_list',
            ocsp.OCSPRequest({'tbs_request': dup_tbs}),
        )

    # two *different* CertIDs, only one of which can be answered
    other_cid = _cert_id_with(
        cert_id, name_hash=b'\x44' * 20, key_hash=b'\x55' * 20
    )
    mixed_tbs = ocsp.TBSRequest.load(tbs.dump())
    mixed_tbs['request_list'] = ocsp.Requests(
        [
            first_request,
            ocsp.Request({'req_cert': other_cid}),
        ]
    )
    yield emit(
        'ocsp-mixed-authorised-unauthorised',
        'one answerable CertID followed by one unanswerable CertID',
        ocsp.OCSPRequest({'tbs_request': mixed_tbs}),
    )

    # --- request extensions ----------------------------------------------
    for copies in (2, 3):
        dup_ext_tbs = ocsp.TBSRequest.load(tbs.dump())
        dup_ext_tbs['request_extensions'] = ocsp.TBSRequestExtensions(
            [nonce_ext] * copies
        )
        yield emit(
            f'ocsp-duplicate-nonce-{copies}',
            f'nonce request extension repeated {copies} times',
            ocsp.OCSPRequest({'tbs_request': dup_ext_tbs}),
        )

    ar_ext = _acceptable_responses_extension()
    combo_tbs = ocsp.TBSRequest.load(tbs.dump())
    combo_tbs['request_extensions'] = ocsp.TBSRequestExtensions(
        [nonce_ext, ar_ext, nonce_ext]
    )
    yield emit(
        'ocsp-nonce-and-acceptable-responses',
        'duplicate nonce alongside acceptable_responses extension',
        ocsp.OCSPRequest({'tbs_request': combo_tbs}),
    )

    for critical in (False, True):
        unk_tbs = ocsp.TBSRequest.load(tbs.dump())
        unk_tbs['request_extensions'] = ocsp.TBSRequestExtensions(
            [nonce_ext, _unknown_extension(critical)]
        )
        yield emit(
            f'ocsp-unknown-extension-critical-{critical}'.lower(),
            f'unknown OID request extension (critical={critical})',
            ocsp.OCSPRequest({'tbs_request': unk_tbs}),
        )

    # oversized nonce value (resource budget via extension payload)
    for length in (255, 4096, 65537):
        big_tbs = ocsp.TBSRequest.load(tbs.dump())
        big_tbs['request_extensions'] = ocsp.TBSRequestExtensions(
            [_nonce_extension(rng.randbytes(length))]
        )
        yield emit(
            f'ocsp-nonce-payload-{length}',
            f'nonce extension carrying {length} random bytes',
            ocsp.OCSPRequest({'tbs_request': big_tbs}),
        )

    # version field is the only explicit tag in TBSRequest; try the other
    # legal integer value that the schema accepts
    weird_version_tbs = ocsp.TBSRequest.load(tbs.dump())
    weird_version_tbs['version'] = ocsp.Version(1)
    yield emit(
        'ocsp-version-v1-explicit',
        'explicit version encoding retained but re-emitted',
        ocsp.OCSPRequest({'tbs_request': weird_version_tbs}),
    )


def _message_imprint(algorithm: str, digest: bytes) -> tsp.MessageImprint:
    return tsp.MessageImprint(
        {
            'hash_algorithm': algos.DigestAlgorithm(
                {'algorithm': algorithm}
            ),
            'hashed_message': digest,
        }
    )


def mutate_tsa(seed_der: bytes, rng: random.Random):
    """Yield ``(case_id, description, der_bytes)`` TSA mutations."""
    base = _reload(tsp.TimeStampReq, seed_der)
    imprint: tsp.MessageImprint = base['message_imprint']
    sha256_digest = imprint['hashed_message'].native

    def emit(case_id, description, request_obj):
        der = request_obj.dump()
        assert tsp.TimeStampReq.load(der) is not None
        return case_id, description, der

    # --- messageImprint length semantics ---------------------------------
    for length in BUDGET_LENGTHS:
        req = tsp.TimeStampReq.load(seed_der)
        req['message_imprint'] = _message_imprint(
            'sha256', rng.randbytes(length)
        )
        yield emit(
            f'tsa-imprint-length-{length}',
            f'sha256 messageImprint digest truncated/expanded to {length} B',
            req,
        )

    # duplicated content inside the imprint (still 32 bytes, but semantically
    # a different message than the seed)
    req = tsp.TimeStampReq.load(seed_der)
    req['message_imprint'] = _message_imprint(
        'sha256', hashlib.sha256(b'completely-different-message').digest()
    )
    yield emit(
        'tsa-imprint-different-message',
        'valid-length digest over a different preimage',
        req,
    )

    # --- algorithm / width contradictions --------------------------------
    for algo, width in (('md5', 16), ('sha1', 20), ('sha512', 64)):
        req = tsp.TimeStampReq.load(seed_der)
        req['message_imprint'] = _message_imprint(
            algo, rng.randbytes(width)
        )
        yield emit(
            f'tsa-imprint-algo-{algo}',
            f'messageImprint using {algo} ({width}-byte digest)',
            req,
        )

    req = tsp.TimeStampReq.load(seed_der)
    req['message_imprint'] = _message_imprint('sha256', rng.randbytes(20))
    yield emit(
        'tsa-imprint-sha256-oid-sha1-width',
        'sha256 imprint OID with a 20-byte (sha1-width) digest',
        req,
    )

    req = tsp.TimeStampReq.load(seed_der)
    req['message_imprint'] = _message_imprint(
        '1.2.840.113549.2.5', rng.randbytes(16)
    )
    yield emit(
        'tsa-imprint-unknown-algo-oid',
        'messageImprint carrying an unrecognised digest algorithm OID',
        req,
    )

    # empty algorithm parameters vs. absent, and NULL params explicitly
    req = tsp.TimeStampReq.load(seed_der)
    req['message_imprint']['hash_algorithm']['parameters'] = core.Null()
    yield emit(
        'tsa-imprint-explicit-null-params',
        'messageImprint algorithm with explicit NULL parameters',
        req,
    )

    # --- scalar fields ----------------------------------------------------
    for version in ('v1', 'v2', 'v3'):
        req = tsp.TimeStampReq.load(seed_der)
        req['version'] = tsp.Version(version)
        yield emit(
            f'tsa-version-{version}',
            f'TimeStampReq.version set to {version}',
            req,
        )

    for cert_req in (True, False):
        req = tsp.TimeStampReq.load(seed_der)
        req['cert_req'] = cert_req
        yield emit(
            f'tsa-cert-req-{str(cert_req).lower()}',
            f'certReq={cert_req}',
            req,
        )

    for nonce in (0, 1, 2 ** 63, 2 ** 127):
        req = tsp.TimeStampReq.load(seed_der)
        req['nonce'] = core.Integer(nonce)
        yield emit(
            f'tsa-nonce-{nonce}',
            f'nonce replaced with {nonce}',
            req,
        )

    for length in (255, 4096, 65537):
        req = tsp.TimeStampReq.load(seed_der)
        # INTEGER tag with that many content bytes: prepend a zero pad byte
        req['nonce'] = core.Integer(
            int.from_bytes(b'\x00' + rng.randbytes(length), 'big')
        )
        yield emit(
            f'tsa-nonce-width-{length}',
            f'nonce INTEGER spanning {length + 1} content bytes',
            req,
        )

    # reqPolicy: a policy the TimeStamper was not configured with
    req = tsp.TimeStampReq.load(seed_der)
    req['req_policy'] = tsp.ObjectIdentifier('1.2.3.4.5.6.7.8.9')
    yield emit(
        'tsa-unaccepted-req-policy',
        'reqPolicy OID that the responder never advertises',
        req,
    )

    # extensions slot, including duplicated / critical unknown extensions
    unknown_tsa_ext = tsp.Extension(
        {
            'extn_id': core.ObjectIdentifier('1.2.3.4.5.6.7.2'),
            'critical': True,
            'extn_value': core.OctetString(b'\x04\x03xyz'),
        }
    )
    req = tsp.TimeStampReq.load(seed_der)
    req['extensions'] = tsp.Extensions(
        [unknown_tsa_ext, unknown_tsa_ext]
    )
    yield emit(
        'tsa-duplicate-critical-extension',
        'two identical critical unknown extensions in TimeStampReq',
        req,
    )
