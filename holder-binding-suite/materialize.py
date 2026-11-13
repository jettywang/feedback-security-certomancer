"""Build the holder-binding suite and emit PEM artifacts plus a manifest.

Outputs (all offline, deterministic given the generated keys):

  certs/
    root.pem, role-aa.pem                 -> PKI / attribute-authority chain
    alice-a.pem, alice-b.pem, alice-c.pem, carol.pem -> holder PKC candidates
    ac-*.pem                              -> the nine attribute certificates
  manifest.json                           -> computed identifiers + expectations

The manifest is *computed from the produced DER*, not hand-typed, so the
matching checker and a human reviewer always see the real serials/digests.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from asn1crypto import pem
from certomancer.registry import ArchLabel, CertLabel, CertomancerConfig

SUITE_DIR = Path(__file__).resolve().parent
CERT_DIR = SUITE_DIR / "certs"
CONFIG_PATH = SUITE_DIR / "certomancer.yml"

PKC_LABELS = ["root", "role-aa", "alice-a", "alice-b", "alice-c", "carol"]
AC_LABELS = [
    "ac-a-basecertid",
    "ac-a-entityname",
    "ac-a-spki-digest",
    "ac-a-certdigest",
    "ac-a-combined",
    "ac-b-basecertid",
    "ac-b-entityname",
    "ac-b-spki-digest",
    "ac-b-certdigest",
]


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_pem(path: Path, armor: str, der: bytes) -> None:
    path.write_bytes(pem.armor(armor, der))


def _holder_summary(holder) -> dict:
    summary: dict = {"present": []}
    native = holder.native
    if native.get("base_certificate_id") is not None:
        bci = holder["base_certificate_id"]
        summary["present"].append("baseCertificateID")
        summary["baseCertificateID"] = {
            "serial": int(bci["serial"].native),
            "issuer_general_name": bci["issuer"][0].chosen.human_friendly,
        }
    if native.get("entity_name") is not None:
        entity_names = holder["entity_name"]
        summary["present"].append("entityName")
        summary["entityName"] = [gn.chosen.human_friendly for gn in entity_names]
    if native.get("object_digest_info") is not None:
        odi = holder["object_digest_info"]
        summary["present"].append("objectDigestInfo")
        summary["objectDigestInfo"] = {
            "digested_object_type": odi["digested_object_type"].native,
            "digest_algorithm": odi["digest_algorithm"]["algorithm"].native,
            "object_digest_hex": odi["object_digest"].native.hex(),
        }
    return summary


def _targets_summary(ac) -> list[str]:
    for ext in ac["ac_info"]["extensions"]:
        if ext["extn_id"].native != "target_information":
            continue
        parsed = ext["extn_value"].parsed
        names: list[str] = []
        for targets_group in parsed:
            for target in targets_group:
                chosen = target.chosen
                readable = (
                    chosen.chosen.human_friendly
                    if target.name == "target_name"
                    else str(chosen.native)
                )
                names.append(f"{target.name}:{readable}")
        return names
    return []


def main() -> None:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    cfg = CertomancerConfig.from_file(
        str(CONFIG_PATH),
        key_search_dir=str(SUITE_DIR),
        config_search_dir=str(SUITE_DIR),
    )
    arch = cfg.get_pki_arch(ArchLabel("holder-binding"))

    manifest: dict = {"pkcs": {}, "attr_certs": {}, "subjects": {}}

    # --- public-key certificates -------------------------------------------
    for label in PKC_LABELS:
        cert = arch.get_cert(CertLabel(label))
        der = cert.dump()
        _write_pem(CERT_DIR / f"{label}.pem", "CERTIFICATE", der)
        spki_der = cert.public_key.dump()
        entry = {
            "file": f"certs/{label}.pem",
            "subject": cert.subject.human_friendly,
            "issuer": cert.issuer.human_friendly,
            "serial": int(cert.serial_number),
            "spki_sha256": _sha256_hex(spki_der),
            "cert_sha256": _sha256_hex(der),
            "not_before": cert["tbs_certificate"]["validity"]["not_before"].native.isoformat(),
            "not_after": cert["tbs_certificate"]["validity"]["not_after"].native.isoformat(),
        }
        manifest["pkcs"][label] = entry
        manifest["subjects"].setdefault(cert.subject.human_friendly, []).append(label)

    # --- attribute certificates --------------------------------------------
    for label in AC_LABELS:
        ac = arch.get_attr_cert(CertLabel(label))
        der = ac.dump()
        _write_pem(CERT_DIR / f"{label}.pem", "ATTRIBUTE CERTIFICATE", der)
        info = ac["ac_info"]
        manifest["attr_certs"][label] = {
            "file": f"certs/{label}.pem",
            "serial": int(info["serial_number"].native),
            "signature_algorithm": ac["signature_algorithm"]["algorithm"].native,
            "holder": _holder_summary(info["holder"]),
            "targets": _targets_summary(ac),
            "attributes": [a["type"].native for a in info["attributes"]],
        }

    (SUITE_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    )

    print(f"wrote {len(PKC_LABELS)} PKC + {len(AC_LABELS)} AC PEM files to {CERT_DIR}")
    print("subjects sharing a DN:")
    for dn, labels in manifest["subjects"].items():
        print(f"  {dn!r} -> {labels}")
    print("manifest -> manifest.json")


if __name__ == "__main__":
    main()
