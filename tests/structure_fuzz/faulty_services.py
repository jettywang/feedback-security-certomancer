"""Deliberately misimplemented signing services.

These subclasses mimic the exact shape of the production responders but
contain an intentionally introduced review-defect: they keep producing a
*signed* response for requests that the specification says must be refused.

The fuzzer's negative test runs the same oracle against these implementations
and asserts that violations are reported.  This guards against the vacuous
pass where a test harness simply accepts every HTTP error (or every raised
exception) as a correct refusal.
"""

from asn1crypto import algos, ocsp, tsp

from certomancer.services import (
    SimpleOCSPResponder,
    TimeStamper,
)


class FaultyOCSPResponder(SimpleOCSPResponder):
    """Signs successful responses even for malformed/contradictory requests.

    Two defects are injected on purpose:

    * an empty request list still yields a signed response instead of
      ``malformed_request``;
    * responder-authorisation failures are swallowed and a response is
      assembled anyway instead of returning ``unauthorized``.
    """

    def build_ocsp_response(self, req: ocsp.OCSPRequest) -> ocsp.OCSPResponse:
        nonce_asn1 = req.nonce_value
        nonce = nonce_asn1.native if nonce_asn1 is not None else None
        requests = req['tbs_request']['request_list']
        issuer_cert = self.revinfo_interface.get_issuer_cert()

        responses = []
        for req_item in requests:
            cid: ocsp.CertId = req_item['req_cert']
            try:
                simple_resp = self.format_single_ocsp_response(
                    cid, issuer_cert
                )
            except Exception:
                # BUG: forge a well-formed SingleResponse from the offending
                # CertID instead of refusing.
                simple_resp = ocsp.SingleResponse(
                    {
                        'cert_id': cid,
                        'cert_status': ocsp.CertStatus(
                            name='good', value=None
                        ),
                        'this_update': self.at_time,
                        'next_update': self.at_time + self.validity
                        if self.validity is not None
                        else None,
                    }
                )
            responses.append(simple_resp)

        if not responses:
            # BUG: empty request list must be malformed_request, but this
            # implementation signs an empty-response success envelope.
            cid = ocsp.CertId(
                {
                    'hash_algorithm': algos.DigestAlgorithm(
                        {'algorithm': 'sha1'}
                    ),
                    'issuer_name_hash': b'\x00' * 20,
                    'issuer_key_hash': b'\x00' * 20,
                    'serial_number': 0,
                }
            )
            responses.append(
                ocsp.SingleResponse(
                    {
                        'cert_id': cid,
                        'cert_status': ocsp.CertStatus(
                            name='good', value=None
                        ),
                        'this_update': self.at_time,
                    }
                )
            )
        return self.assemble_simple_ocsp_responses(
            responses, nonce=nonce
        )


class FaultyTimeStamper(TimeStamper):
    """Signs TST tokens without validating the request semantics.

    The production :class:`TimeStamper` already skips most RFC 3161 input
    checks; this subclass goes further and never returns a rejection PKIStatus
    at all.  It exists so the TSA oracle has a concrete misimplementation to
    flag: every mutated request (including contradictory messageImprint
    widths and unsupported policies) is answered with ``granted`` plus a
    freshly signed token.
    """

    def request_tsa_response(
        self, req: tsp.TimeStampReq
    ) -> tsp.TimeStampResp:
        # Deliberately no validation of version, algorithm, imprint width or
        # reqPolicy: delegate straight to the signing path.
        return super().request_tsa_response(req)
