"""Regression tests for RFC 5755 holder bindings and target restrictions.

These tests operate entirely on the generated PEM artifacts under
holder-binding-suite/certs and never touch the network. They cover:

  * control-group invariants (same DN / same key distinctions),
  * the four holder bindings plus AND-combined binding,
  * targetInformation enforcement,
  * AC signature validity and tamper rejection,
  * the full expected_results.yml matrix.
"""
from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

SUITE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SUITE_DIR))

from checks.loader import load_ac, load_pkc, target_name  # noqa: E402
from checks import matcher  # noqa: E402

HOLDER_LABELS = ["alice-a", "alice-b", "alice-c", "carol"]
REF_TIME = datetime(2026, 6, 1, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def pkcs():
    return {label: load_pkc(label) for label in HOLDER_LABELS}


@pytest.fixture(scope="module")
def aa_cert():
    return load_pkc("role-aa")


# --------------------------------------------------------------------------- #
# Control-group invariants
# --------------------------------------------------------------------------- #
def test_all_holder_certs_share_one_subject_dn(pkcs):
    subjects = {cert.subject.dump() for cert in pkcs.values()}
    assert len(subjects) == 1, "all four holder PKCs must carry the SAME DN"


def test_same_name_different_key_group(pkcs):
    # alice-a vs alice-b vs carol: identical subject, distinct SPKIs.
    spkis = {label: pkcs[label].public_key.sha256 for label in HOLDER_LABELS}
    assert spkis["alice-a"] != spkis["alice-b"]
    assert spkis["alice-a"] != spkis["carol"]
    assert spkis["alice-b"] != spkis["carol"]


def test_same_key_recertified_group(pkcs):
    # alice-a and alice-c embed the same SubjectPublicKeyInfo but are distinct
    # certificates (different serial and whole-certificate DER).
    assert pkcs["alice-a"].public_key.sha256 == pkcs["alice-c"].public_key.sha256
    assert pkcs["alice-a"].serial_number != pkcs["alice-c"].serial_number
    assert pkcs["alice-a"].dump() != pkcs["alice-c"].dump()


def test_serials_are_distinct(pkcs):
    serials = [int(cert.serial_number) for cert in pkcs.values()]
    assert len(set(serials)) == len(serials)


# --------------------------------------------------------------------------- #
# Every AC signature is valid under the AA key; tampering breaks it.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "ac_label",
    [
        "ac-a-basecertid",
        "ac-a-entityname",
        "ac-a-spki-digest",
        "ac-a-certdigest",
        "ac-a-combined",
        "ac-b-basecertid",
        "ac-b-entityname",
        "ac-b-spki-digest",
        "ac-b-certdigest",
    ],
)
def test_all_ac_signatures_valid(ac_label, aa_cert):
    ac = load_ac(ac_label)
    assert matcher.verify_ac_signature(ac, aa_cert) is True


def test_tampered_signature_is_rejected(aa_cert):
    ac = load_ac("ac-a-basecertid")
    tampered = type(ac).load(ac.dump())
    sig = bytearray(tampered["signature"].native)
    sig[0] ^= 0xFF
    tampered["signature"] = bytes(sig)
    assert matcher.verify_ac_signature(tampered, aa_cert) is False


def test_wrong_verifier_key_rejects_signature(pkcs):
    ac = load_ac("ac-a-basecertid")
    root = load_pkc("root")
    assert matcher.verify_ac_signature(ac, root) is False


# --------------------------------------------------------------------------- #
# Individual holder-binding semantics
# --------------------------------------------------------------------------- #
def test_base_certificate_id_does_not_inherit_by_name(pkcs):
    ac = load_ac("ac-a-basecertid")
    assert matcher.evaluate_holder(ac["ac_info"]["holder"], pkcs["alice-a"]).matches
    for foreign in ("alice-b", "alice-c", "carol"):
        report = matcher.evaluate_holder(ac["ac_info"]["holder"], pkcs[foreign])
        assert not report.matches
        assert matcher.REASON_BASE_CERT_ID in report.failures


def test_entity_name_matches_every_same_dn_cert(pkcs):
    ac = load_ac("ac-a-entityname")
    for label in HOLDER_LABELS:
        report = matcher.evaluate_holder(ac["ac_info"]["holder"], pkcs[label])
        assert report.matches, f"entityName should match same-DN cert {label}"


def test_spki_digest_survives_renewal_but_not_key_change(pkcs):
    ac = load_ac("ac-a-spki-digest")
    holder = ac["ac_info"]["holder"]
    # same key, re-certified -> SPKI unchanged -> match
    assert matcher.evaluate_holder(holder, pkcs["alice-a"]).matches
    assert matcher.evaluate_holder(holder, pkcs["alice-c"]).matches
    # new/foreign keys -> mismatch
    for foreign in ("alice-b", "carol"):
        report = matcher.evaluate_holder(holder, pkcs[foreign])
        assert not report.matches
        assert matcher.REASON_SPKI_DIGEST in report.failures


def test_cert_digest_breaks_on_any_recertification(pkcs):
    ac = load_ac("ac-a-certdigest")
    holder = ac["ac_info"]["holder"]
    assert matcher.evaluate_holder(holder, pkcs["alice-a"]).matches
    for foreign in ("alice-b", "alice-c", "carol"):
        report = matcher.evaluate_holder(holder, pkcs[foreign])
        assert not report.matches
        assert matcher.REASON_CERT_DIGEST in report.failures


def test_combined_binding_requires_all_components(pkcs):
    ac = load_ac("ac-a-combined")
    holder = ac["ac_info"]["holder"]
    assert matcher.evaluate_holder(holder, pkcs["alice-a"]).matches
    # All other certs share the DN (entityName OK) but fail baseCertificateID.
    for foreign in ("alice-b", "alice-c", "carol"):
        report = matcher.evaluate_holder(holder, pkcs[foreign])
        assert not report.matches
        assert matcher.REASON_BASE_CERT_ID in report.failures


# --------------------------------------------------------------------------- #
# Target restriction
# --------------------------------------------------------------------------- #
def test_target_information_enforced(pkcs, aa_cert):
    ac = load_ac("ac-a-basecertid")
    allowed = matcher.evaluate_authorization(
        ac, pkcs["alice-a"], aa_cert, REF_TIME, target_name("Payments Service")
    )
    denied = matcher.evaluate_authorization(
        ac, pkcs["alice-a"], aa_cert, REF_TIME, target_name("Other Service")
    )
    assert allowed.authorized is True
    assert denied.authorized is False
    assert matcher.REASON_TARGET in denied.reasons


def test_validity_window_respected(pkcs, aa_cert):
    ac = load_ac("ac-a-basecertid")
    ancient = datetime(2000, 1, 1, tzinfo=timezone.utc)
    decision = matcher.evaluate_authorization(
        ac, pkcs["alice-a"], aa_cert, ancient, target_name("Payments Service")
    )
    assert decision.in_validity_window is False
    assert decision.authorized is False
    assert matcher.REASON_EXPIRED in decision.reasons


# --------------------------------------------------------------------------- #
# Full data-driven matrix
# --------------------------------------------------------------------------- #
def test_expected_results_matrix(pkcs, aa_cert):
    matrix = yaml.safe_load((SUITE_DIR / "expected_results.yml").read_text())
    from dateutil.parser import parse as parse_dt

    ref_time = parse_dt(matrix["reference_time"])
    targets = {key: target_name(cn) for key, cn in matrix["targets"].items()}

    checked = 0
    for case in matrix["cases"]:
        ac = load_ac(case["ac"])
        for check in case["checks"]:
            decision = matcher.evaluate_authorization(
                ac=ac,
                candidate=pkcs[check["candidate"]],
                aa_cert=aa_cert,
                at_time=ref_time,
                target_name=targets[check["target"]],
            )
            assert decision.authorized == bool(check["authorized"]), (
                case["ac"], check
            )
            for reason in check.get("expected_reasons", []):
                assert reason in decision.reasons
            # Every matrix evaluation must rest on a cryptographically valid AC.
            assert decision.signature_valid is True
            checked += 1
    assert checked >= 30


def test_run_checks_script_exits_zero():
    result = subprocess.run(
        [sys.executable, str(SUITE_DIR / "run_checks.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "All holder-binding" in result.stdout
