# Structure fuzzing for the OCSP / TSA entry points

This package fuzzes the two Certomancer service adapter entry points:

- the Werkzeug WSGI `Animator` (`certomancer.integrations.animator`);
- the aiohttp `build_animator_app`
  (`certomancer.integrations.aiohttp_animator`).

The goal is **not** random byte fuzzing. Every request is rebuilt through
`asn1crypto`, so each emitted blob is valid, parseable ASN.1. The fuzzer
instead concentrates on requests that *decode fine but carry contradictory
semantics* — the class of input most likely to trick a signing service into
emitting a signed success response it should have refused.

## Layout

- `mutators.py` — deterministic, structure-aware mutators for OCSP requests
  (CertID hashes/serials, request-list cardinality, request extensions,
  nonce payload sizes) and TSA requests (messageImprint width/algorithm,
  version, nonce, reqPolicy, extensions, resource sizes).
- `oracle.py` — classifies a transport result as `signed`, `refused`,
  `parse_error` or `framework_error` by decoding the protocol payload. An
  HTTP error with an unparseable body is **not** treated as a valid refusal.
- `engine.py` — fixed-seed campaign runner, response-size budget checks,
  violation artefact persistence and DER-aware greedy minimisation.
- `adapters.py` — uniform in-process drivers for the WSGI client and the
  aiohttp handlers (the latter run without binding a socket).
- `faulty_services.py` / `service_factory.py` — deliberately misimplemented
  OCSP/TSA signers used as negative controls.
- `expectations.py` — the RFC-based must-refuse case registry plus the list
  of confirmed production defects (strict `xfail`).

## Running

```sh
# fixed-seed, small, fast run (default: 32 cases per service, ~30 s total)
.venv/bin/python -m pytest tests/test_structure_fuzz_adapters.py -q

# corpus invariants (parseability, determinism, registry consistency)
.venv/bin/python -m pytest tests/test_structure_fuzz_corpus.py -q
```

Deeper offline campaigns use environment overrides:

- `CERTOMANCER_FUZZ_SEED` — RNG seed (default `20261113`);
- `CERTOMANCER_FUZZ_CASES` — cap on mutations per campaign;
- `CERTOMANCER_FUZZ_MAX_RESPONSE_BYTES` — response-size budget;
- `CERTOMANCER_FUZZ_ARTIFACTS` — directory for persisted artefacts.

## Artefacts

Every detected signed-response violation writes a per-case directory
containing `original.der`, a greedily minimised `minimal.der` (still
parseable and still triggering the same violation) and `metadata.json`.
Each campaign also writes `campaign-summary.json`.

## Why the negative controls matter

`test_faulty_ocsp_responder_is_detected` and
`test_faulty_timestamper_is_detected` run intentionally broken signers that
sign requests they ought to reject. The tests assert the oracle flags them,
proving the criteria fail closed rather than accepting every HTTP error as a
pass.
