"""Generate the offline RSA key set for the holder-binding regression suite.

All keys are fresh, local, unencrypted PKCS#8 PEM files. Nothing is fetched
over the network. Re-running the script regenerates every key (and therefore
every derived certificate/digest), which keeps the suite self-contained.
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_DIR = Path(__file__).resolve().parent / "keys"

# label -> human-readable purpose. Two labels sharing a subject DN is the
# whole point of the "same name, different key" control group.
KEY_LABELS = {
    "root": "root CA / trust anchor",
    "aa": "attribute authority signing key",
    "alice-key-1": "Alice original key (holder of alice-a)",
    "alice-key-2": "Alice rotated key (same subject, new SPKI)",
    "carol-key": "Carol key, but issued under Alice's identical DN",
}

RSA_PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE = 2048


def generate_one(label: str) -> Path:
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE
    )
    out_path = KEY_DIR / f"{label}.key.pem"
    out_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return out_path


def main() -> None:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    for label, purpose in KEY_LABELS.items():
        path = generate_one(label)
        print(f"generated {path.name:24s} {purpose}")
    print(f"\nWrote {len(KEY_LABELS)} private keys to {KEY_DIR}")


if __name__ == "__main__":
    main()
