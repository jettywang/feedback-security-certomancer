"""PEM/DER loading helpers for the offline holder-binding suite."""
from __future__ import annotations

from pathlib import Path
from typing import Dict

from asn1crypto import cms, pem, x509

# Register target_information (OID 2.5.29.55) and the other AC extension
# mappings so extn_id.native resolves to a readable name instead of a bare OID.
from certomancer._asn1_types import register_extensions  # noqa: E402

register_extensions()

SUITE_DIR = Path(__file__).resolve().parent.parent
CERT_DIR = SUITE_DIR / "certs"


def _read_der(path: Path) -> bytes:
    raw = path.read_bytes()
    if pem.detect(raw):
        _, _, der = pem.unarmor(raw)
        return der
    return raw


def load_pkc(label: str) -> x509.Certificate:
    return x509.Certificate.load(_read_der(CERT_DIR / f"{label}.pem"))


def load_ac(label: str) -> cms.AttributeCertificateV2:
    return cms.AttributeCertificateV2.load(_read_der(CERT_DIR / f"{label}.pem"))


def load_all_pkcs(labels) -> Dict[str, x509.Certificate]:
    return {label: load_pkc(label) for label in labels}


def target_name(entity_cn: str) -> x509.Name:
    """Build the directory name of a target service the way it appears on disk.

    The DN components mirror certomancer.yml entity-defaults + the entity CN.
    """
    return x509.Name.build(
        {
            "country_name": "US",
            "organization_name": "Holder Binding Test Org",
            "organizational_unit_name": "Authorization Lab",
            "common_name": entity_cn,
        }
    )
