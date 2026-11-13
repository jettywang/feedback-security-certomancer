# Holder-binding regression suite (RFC 5755 attribute certificates)

A self-contained, fully offline Certomancer sample set for authorization-policy
testing. It produces attribute certificates (ACs) that exercise every RFC 5755
holder identifier against two control groups, with explicit target
restrictions, and ships a runnable matcher that returns the expected
authorization decision for each combination.

The central property under test: **a matching subject string must never, by
itself, cause a role to be inherited.** Whether an AC applies to a presented
public-key certificate (PKC) depends entirely on which holder component the AC
uses and what that component actually identifies.

## Layout

| Path | Purpose |
| --- | --- |
| `generate_keys.py` | Generates five fresh, local RSA-2048 key pairs (no network). |
| `certomancer.yml` | PKI architecture, holder PKCs, and the nine attribute certificates. |
| `materialize.py` | Builds all certs/ACs, writes PEMs to `certs/`, and computes `manifest.json`. |
| `manifest.json` | Real serials, SPKI digests, whole-cert digests, holder fields, targets. |
| `checks/matcher.py` | Offline RFC 5755 evaluation: signature, validity, holder, targets. |
| `checks/loader.py` | PEM/DER loading and target-name construction. |
| `expected_results.yml` | Authoritative matrix of every expected decision and failure reason. |
| `run_checks.py` | Executes the matrix and asserts actual vs. expected (exit 0 = pass). |
| `tests/test_holder_binding.py` | Pytest version of the same guarantees plus tamper controls. |
| `keys/`, `certs/` | Generated private keys and PEM artifacts. |

## Running it offline

All commands use the repository virtualenv and perform no network access.

```bash
# 1. regenerate keys (optional; committed-free, fully local)
.venv/bin/python holder-binding-suite/generate_keys.py

# 2. build the PKCs, ACs, and manifest
.venv/bin/python holder-binding-suite/materialize.py

# 3. run the authorization matrix (prints 37/37 on success)
.venv/bin/python holder-binding-suite/run_checks.py

# 4. run the pytest regression suite
.venv/bin/python -m pytest holder-binding-suite/tests/ -q
```

The standard Certomancer CLI emits byte-identical artifacts, e.g.

```bash
.venv/bin/certomancer --config holder-binding-suite/certomancer.yml \
    summon holder-binding ac-a-combined --attr out.pem
```

## The two control groups

All four holder PKCs carry the **identical** distinguished name
`CN=Alice Holder, OU=Authorization Lab, O=Holder Binding Test Org, C=US`.
They differ in key material and serial:

| PKC | Key (SPKI) | Serial | Group / meaning |
| --- | --- | --- | --- |
| `alice-a` | `alice-key-1` | S_a | Original holder certificate. |
| `alice-b` | `alice-key-2` | S_b | Same name, **different key**. |
| `carol` | `carol-key` | S_x | Same name, **foreign key**. |
| `alice-c` | `alice-key-1` | S_c | **Same key**, re-certified (new serial/DER). |

- **Same name, different key:** `alice-a` vs `alice-b` and `carol` — equal
  subject DN, unrelated key pairs.
- **Same key, re-certified:** `alice-a` vs `alice-c` — identical
  SubjectPublicKeyInfo, but a new serial and a new whole-certificate DER.

The manifest proves the invariants: `alice-a`/`alice-c` share an SPKI digest
but have different certificate digests and serials; every PKC has a distinct
SPKI except that pair.

## Holder bindings covered

Each binding appears for both the original cert (`ac-a-*`, bound to `alice-a`)
and the renewed cert (`ac-b-*`, bound to `alice-c`). All ACs are signed by the
`role-aa` attribute authority, carry the `role` attribute, and include a
**critical** `targetInformation` extension naming `Payments Service` and
`Readonly Service`.

| AC label | Holder component | What it actually pins |
| --- | --- | --- |
| `ac-*-basecertid` | `baseCertificateID` | Issuer name **+ certificate serial**. |
| `ac-*-entityname` | `entityName` | Subject **directory name only**. |
| `ac-*-spki-digest` | `objectDigestInfo` `public_key` | SHA-256 of the whole SubjectPublicKeyInfo. |
| `ac-*-certdigest` | `objectDigestInfo` `public_key_cert` | SHA-256 of the whole certificate DER. |
| `ac-a-combined` | `baseCertificateID` **AND** `entityName` | Both components must match. |

For digest holders, `objectDigestInfo` uses `digestedObjectType`
`publicKey` (SPKI) or `publicKeyCert` (whole cert), both SHA-256.

## When each binding must fail

"Same DN" means the candidate has `CN=Alice Holder` exactly like the original
holder; this alone is never sufficient except for the `entityName` binding.

| Binding | Survives same name / new key (`alice-b`, `carol`)? | Survives same key / new cert (`alice-c`)? | Fails after |
| --- | --- | --- | --- |
| `baseCertificateID` | No | No | Any re-issue, renewal, or any cert whose issuer+serial differs — including same-name and same-key certificates. |
| `entityName` | **Yes** | Yes | Only when the subject directory name changes. This is deliberately the weak binding: it matches every same-DN cert and cannot tell keys apart. |
| SPKI digest (`public_key`) | No | **Yes** | A key change (new SPKI). Re-certification with the same key keeps matching. |
| Whole-cert digest (`public_key_cert`) | No | No | Any change to the certificate DER — renewal, re-signing, extension change — even with the identical key. |
| Combined (AND) | No | No | When **any** present component fails; the matching `entityName` cannot rescue a failed `baseCertificateID`. |

Concrete consequences exercised by the matrix:

- `ac-a-basecertid` matches only `alice-a`; `alice-b`, `alice-c`, and `carol`
  all fail with `baseCertificateID_mismatch` despite the equal subject string.
- `ac-a-entityname` matches all four same-DN PKCs — illustrating why a bare
  name binding is insufficient for role inheritance decisions.
- `ac-a-spki-digest` matches `alice-a` and the re-certified `alice-c` (same
  SPKI), but rejects `alice-b`/`carol` with `spki_digest_mismatch`.
- `ac-a-certdigest` matches only `alice-a`; even `alice-c`, which holds the
  same key, fails with `cert_digest_mismatch` because the certificate DER changed.
- The Group B (`ac-b-*`) ACs prove the symmetric facts from the renewed
  certificate's side.

## Target restriction

Every AC limits authorization to `Payments Service` and `Readonly Service`.
Presenting a holder that otherwise matches, but requesting `Other Service`,
returns `authorized = false` with reason `target_not_authorized`. The matcher
does not expand `targetGroup` entries into name matches; this suite uses
`targetName` only, so a group can never be silently treated as an allowed name.

## Decision pipeline and reason codes

`checks/matcher.py::evaluate_authorization` short-circuits through:

1. **AC signature** verification under the AA public key -> `bad_ac_signature`.
2. **Validity window** at the reference time -> `outside_validity_window`.
3. **Holder binding** with RFC 5755 AND-semantics across every present
   component -> `baseCertificateID_mismatch`, `entityName_mismatch`,
   `spki_digest_mismatch`, `cert_digest_mismatch`.
4. **Target restriction** -> `target_not_authorized`.

Authorization is granted only when all applicable stages pass. The reference
time in `expected_results.yml` lies inside every AC validity window, so the
matrix isolates holder and target behavior; a separate pytest confirms the
validity check itself rejects an out-of-window request.

## Signature validity is real, not assumed

All nine AC signatures verify under the `role-aa` public key (RSA-PKCS#1
SHA-256). The tests additionally prove the verifier is not a stub:

- flipping one byte of an AC signature yields `bad_ac_signature`;
- verifying against the wrong key (the root CA key) fails;
- the `role-aa` certificate chains to the local `root` trust anchor.

No OCSP/CRL or network fetching is involved; revocation is intentionally out
of scope for this holder-binding regression set.
