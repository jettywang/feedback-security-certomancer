"""Semantics-based expectations shared by the fuzzing test module.

Only *unambiguously* contradictory requests belong here -- inputs that decode
as valid ASN.1 but violate the RFC 6960 / RFC 3161 request rules. Policy
dependent cases (e.g. an unrelated but well-formed certificate) are excluded
so the suite stays an honest spec conformance check rather than encoding
arbitrary product choices.
"""

from certomancer.registry import ArchLabel, ServiceLabel

ARCH = ArchLabel('testing-ca')
OCSP_LABEL = ServiceLabel('interm')
TSA_LABEL = ServiceLabel('tsa')

OCSP_MUST_REFUSE = frozenset(
    {
        # empty request list -> malformedRequest (RFC 6960 4.1.1)
        'ocsp-empty-request-list',
        # CertID hash widths that contradict the algorithm OID
        'ocsp-certid-hashlen-0',
        'ocsp-certid-hashlen-1',
        'ocsp-certid-hashlen-7',
        'ocsp-certid-hashlen-32',
        'ocsp-certid-hashlen-64',
        'ocsp-certid-hashlen-255',
        'ocsp-certid-hashlen-4096',
        'ocsp-certid-hashlen-65537',
        'ocsp-certid-hashlen-1048576',
        # weak digest and OID/width mismatch
        'ocsp-certid-algo-md5',
        'ocsp-certid-sha256-oid-sha1-width',
        # an unanswerable CertID inside a multi-CertID request
        'ocsp-mixed-authorised-unauthorised',
        # duplicated / conflicting request extensions
        'ocsp-duplicate-nonce-2',
        'ocsp-duplicate-nonce-3',
        'ocsp-nonce-and-acceptable-responses',
        # critical unknown extension must be refused
        'ocsp-unknown-extension-critical-true',
        # resource-budget probes carried by extension payloads
        'ocsp-nonce-payload-4096',
        'ocsp-nonce-payload-65537',
    }
)

TSA_MUST_REFUSE = frozenset(
    {
        # messageImprint digest width must match the algorithm (RFC 3161
        # 2.4.1): every non-32-byte sha256 digest is contradictory
        'tsa-imprint-length-0',
        'tsa-imprint-length-1',
        'tsa-imprint-length-7',
        'tsa-imprint-length-20',
        'tsa-imprint-length-64',
        'tsa-imprint-length-255',
        'tsa-imprint-length-4096',
        'tsa-imprint-length-65537',
        'tsa-imprint-length-1048576',
        'tsa-imprint-sha256-oid-sha1-width',
        # weak / unsupported digest algorithms
        'tsa-imprint-algo-md5',
        'tsa-imprint-algo-sha1',
        'tsa-imprint-unknown-algo-oid',
        # the responder never advertises this policy (RFC 3161 2.4.2)
        'tsa-unaccepted-req-policy',
        # duplicated critical extension is structurally contradictory
        'tsa-duplicate-critical-extension',
        # absurd nonce widths are a resource-budget / sanity violation
        'tsa-nonce-width-4096',
        'tsa-nonce-width-65537',
    }
)

# Confirmed defects in the current production signing path, recorded as
# strict expected failures.  Each entry maps a case id to a short root-cause
# note.  Once the service validates the relevant field, the corresponding
# xfail flips to XPASS and fails the run, forcing this registry (and the
# rationale) to be updated.  Everything in *_MUST_REFUSE but *not* listed here
# is still hard-asserted, so newly introduced regressions cannot hide.
OCSP_KNOWN_SIGNED_DEFECTS = {
    'ocsp-duplicate-nonce-2': (
        'SimpleOCSPResponder reads req.nonce_value without rejecting a '
        'duplicate nonce extension (RFC 6960 4.1.2)'
    ),
    'ocsp-duplicate-nonce-3': (
        'SimpleOCSPResponder reads req.nonce_value without rejecting a '
        'duplicate nonce extension (RFC 6960 4.1.2)'
    ),
    'ocsp-nonce-and-acceptable-responses': (
        'duplicate nonce coexisting with acceptable_responses is accepted '
        'and echoed in the signed response'
    ),
    'ocsp-unknown-extension-critical-true': (
        'critical unknown request extensions are not rejected with '
        'malformedRequest (RFC 6960 4.1.2)'
    ),
    'ocsp-nonce-payload-4096': (
        'oversized nonce value is echoed into the signed response, allowing '
        'request/response size amplification'
    ),
    'ocsp-nonce-payload-65537': (
        'oversized nonce value is echoed into the signed response, allowing '
        'request/response size amplification'
    ),
}

TSA_KNOWN_SIGNED_DEFECTS = {
    case_id: (
        'TimeStamper.request_tsa_response performs no RFC 3161 request '
        'validation and always returns a granted, signed token'
    )
    for case_id in (
        'tsa-imprint-length-0',
        'tsa-imprint-length-1',
        'tsa-imprint-length-7',
        'tsa-imprint-length-20',
        'tsa-imprint-length-64',
        'tsa-imprint-length-255',
        'tsa-imprint-length-4096',
        'tsa-imprint-length-65537',
        'tsa-imprint-length-1048576',
        'tsa-imprint-algo-md5',
        'tsa-imprint-algo-sha1',
        'tsa-imprint-sha256-oid-sha1-width',
        'tsa-imprint-unknown-algo-oid',
        'tsa-nonce-width-4096',
        'tsa-nonce-width-65537',
        'tsa-unaccepted-req-policy',
        'tsa-duplicate-critical-extension',
    )
}

# Resource-amplification defects: a request that large is answered with a
# comparably large *signed* body instead of being capped or refused.  The TSA
# entries reflect that TimeStamper copies the caller-supplied messageImprint
# verbatim into the signed TSTInfo, so oversized digests inflate the token;
# the OCSP entry reflects the nonce being echoed into response extensions.
KNOWN_RESOURCE_AMPLIFICATION = frozenset(
    {
        ('ocsp', 'ocsp-nonce-payload-65537'),
        ('tsa', 'tsa-nonce-width-65537'),
        ('tsa', 'tsa-imprint-length-65537'),
        ('tsa', 'tsa-imprint-length-1048576'),
    }
)
