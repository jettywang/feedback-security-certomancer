"""Factories wiring production and faulty signing services to a registry.

Keeping the construction logic in one place means both the positive and the
negative (fault-injection) campaigns summon services with identical keying,
fixed time and validity settings -- the only difference is the injected
misimplementation.
"""

from datetime import datetime

from asn1crypto import ocsp

from certomancer.registry import PKIArchitecture, ServiceLabel
from certomancer.registry.pki_arch import OCSPInterface
from certomancer.services import choose_signed_digest

from .faulty_services import FaultyOCSPResponder, FaultyTimeStamper


def build_faulty_responder(
    pki_arch: PKIArchitecture,
    label: ServiceLabel,
    at_time: datetime,
) -> FaultyOCSPResponder:
    registry = pki_arch.service_registry
    info = registry.get_ocsp_info(label)
    responder_key = pki_arch.key_set.get_private_key(info.signing_key)
    issuer_cert_label = info.resolve_issuer_cert(pki_arch)
    responder_cert = pki_arch.get_cert(info.responder_cert)

    return FaultyOCSPResponder(
        responder_cert=responder_cert,
        responder_key=responder_key,
        signature_algo=choose_signed_digest(
            info.digest_algo,
            responder_cert.public_key,
            signature_algo=info.signature_algo,
        ),
        at_time=at_time,
        revinfo_interface=OCSPInterface(
            for_issuer=info.for_issuer,
            pki_arch=pki_arch,
            issuer_cert_label=issuer_cert_label,
            is_aa_responder=info.is_aa_responder,
        ),
        validity=info.validity_period,
        response_extensions=[
            ext.to_asn1(pki_arch, ocsp.ResponseDataExtension)
            for ext in info.ocsp_extensions
        ],
    )


def build_faulty_timestamper(
    pki_arch: PKIArchitecture,
    label: ServiceLabel,
    at_time: datetime,
) -> FaultyTimeStamper:
    registry = pki_arch.service_registry
    info = registry.get_tsa_info(label)
    tsa_key = pki_arch.key_set.get_private_key(info.signing_key)
    tsa_cert = pki_arch.get_cert(info.signing_cert)

    return FaultyTimeStamper(
        tsa_cert=tsa_cert,
        tsa_key=tsa_key,
        fixed_dt=at_time,
        signature_algo=choose_signed_digest(
            info.digest_algo,
            pub_key=tsa_cert.public_key,
            signature_algo=info.signature_algo,
        ),
        certs_to_embed=[
            pki_arch.get_cert(lbl) for lbl in info.certs_to_embed
        ],
        md_algorithm=info.digest_algo,
    )
