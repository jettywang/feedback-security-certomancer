"""Run the offline holder-binding regression checks.

Loads the PEM artifacts produced by materialize.py, evaluates every
(attribute certificate, candidate PKC, target) triple in expected_results.yml
with the local matcher, and asserts the actual authorization conclusion and
failure reasons against the expected ones.

Exit code 0 means the whole matrix passed; non-zero means at least one
regression (the offending rows are printed). No network access is performed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml
from dateutil.parser import parse as parse_dt

SUITE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SUITE_DIR))

from checks.loader import load_ac, load_pkc, target_name  # noqa: E402
from checks.matcher import evaluate_authorization  # noqa: E402

CANDIDATE_LABELS = ["alice-a", "alice-b", "alice-c", "carol"]
AA_CERT_LABEL = "role-aa"


def main() -> int:
    matrix = yaml.safe_load((SUITE_DIR / "expected_results.yml").read_text())
    ref_time = parse_dt(matrix["reference_time"])
    targets = {key: target_name(cn) for key, cn in matrix["targets"].items()}

    aa_cert = load_pkc(AA_CERT_LABEL)
    pkcs = {label: load_pkc(label) for label in CANDIDATE_LABELS}

    total = passed = 0
    signature_checked = 0
    failures = []

    for case in matrix["cases"]:
        ac_label = case["ac"]
        ac = load_ac(ac_label)
        for check in case["checks"]:
            total += 1
            candidate = pkcs[check["candidate"]]
            target = targets[check["target"]]
            decision = evaluate_authorization(
                ac=ac,
                candidate=candidate,
                aa_cert=aa_cert,
                at_time=ref_time,
                target_name=target,
            )
            decision.ac_label = ac_label
            decision.candidate_label = check["candidate"]

            if decision.signature_valid:
                signature_checked += 1

            expected_auth = bool(check["authorized"])
            expected_reasons = check.get("expected_reasons", [])
            reason_ok = all(reason in decision.reasons for reason in expected_reasons)
            ok = decision.authorized == expected_auth and reason_ok

            if ok:
                passed += 1
            else:
                failures.append(
                    {
                        "ac": ac_label,
                        "binding": case["binding"],
                        "candidate": check["candidate"],
                        "target": check["target"],
                        "expected_authorized": expected_auth,
                        "actual_authorized": decision.authorized,
                        "expected_reasons": expected_reasons,
                        "actual_reasons": decision.reasons,
                        "holder_checked": decision.holder_report.checked_components,
                    }
                )

    print(f"reference time      : {ref_time.isoformat()}")
    print(f"AC signatures valid : {signature_checked}/{total} evaluations")
    print(f"checks passed       : {passed}/{total}")

    if failures:
        print("\nREGRESSIONS:")
        for failure in failures:
            print(f"  - {failure['ac']} ({failure['binding']}) vs "
                  f"{failure['candidate']} @ {failure['target']}")
            print(f"      expected authorized={failure['expected_authorized']} "
                  f"reasons={failure['expected_reasons']}")
            print(f"      actual   authorized={failure['actual_authorized']} "
                  f"reasons={failure['actual_reasons']}")
            print(f"      holder components checked={failure['holder_checked']}")
        return 1

    print("\nAll holder-binding and target conclusions match expectations.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
