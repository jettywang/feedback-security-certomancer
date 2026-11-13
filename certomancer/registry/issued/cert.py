from dataclasses import dataclass
from typing import Optional

from ..common import CertLabel, EntityLabel, KeyLabel
from .general import IssuedItemSpec

EXCLUDED_FROM_TEMPLATE = frozenset(
    {
        'subject',
        'subject_key',
        'serial',
        'certificate_file',
        'allow_import_mismatch',
    }
)
EXTNS_EXCLUDED_FROM_TEMPLATE = frozenset({'subject_alt_name'})


@dataclass(frozen=True)
class CertificateSpec(IssuedItemSpec):
    """Certificate specification."""

    label: CertLabel
    """Internal name of the certificate spec."""

    subject: EntityLabel
    """Certificate subject"""

    subject_key: KeyLabel
    """Subject's (public) key. Defaults to the value of :attr:`subject`."""

    templatable_config: dict
    """Configuration that can be reused by other certificate specs."""

    certificate_file: Optional[str] = None
    """
    Path to a file with a pre-generated copy of the certificate in question,
    either in DER or in PEM format.

    When the certificate determined by this certificate spec is requested,
    the certificate in the file will be returned.

    Certomancer runs a preflight check on the imported certificate before it
    is accepted. The certificate's subject, issuer, serial number, subject
    public key and (where applicable) the key that signed it must agree with
    the data in this spec. Otherwise, OCSP responders and CRL repositories
    configured for this PKI architecture could answer queries about a
    different certificate than the one the spec describes. Such conflicts
    cause a :class:`.ConfigurationError` at load time.

    No private key is required for the imported certificate's subject key, as
    long as that key is not needed by the configuration. The certificate
    itself carries no private key; Certomancer only uses its DER content.

    .. note::
        This option is unavailable when external configuration is disabled.
        Moreover, it is excluded from templates derived from this certificate
        spec.
    """

    allow_import_mismatch: bool = False
    """
    Deliberately accept an imported certificate that fails the preflight
    check. This is only intended for test samples that rely on a certificate
    being inconsistent with its spec (e.g. to test how a client copes with a
    misissued certificate).

    When set, Certomancer keeps the mismatch visible: it logs a warning
    describing every discrepancy between the imported certificate and the
    spec. Impersonated trust services in this architecture (OCSP responders,
    CRL repositories and certificate repositories) will then answer based on
    the spec, not on the imported DER. Use this flag sparingly.
    """

    @property
    def self_issued(self) -> bool:
        """
        Check whether the corresponding certificate is self-issued,
        i.e. whether the subject and issuer coincide.

        .. warning::
            Self-issued and self-signed are two related, but very different
            notions. Not all self-issued certificates are self-signed (e.g.
            CA key rollover can be implemented using self-issued certificates),
            and in principle self-signed certificates need not be self-issued
            either (although that usually makes little sense in practice).
        :return:
        """
        return self.subject == self.issuer

    @property
    def self_signed(self) -> bool:
        """
        Check whether the produced certificate is self-signed,
        i.e. whether the signer's (public) key is the same as the subject key.
        """
        return self.subject_key == self.authority_key

    @classmethod
    def extract_templatable_config(cls, config_dict):
        # Do this first for consistency, so we don't put processed values
        # into the template
        for k, v in config_dict.items():
            if k.replace('-', '_') in EXCLUDED_FROM_TEMPLATE:
                continue
            elif k == 'extensions':
                yield (
                    k,
                    [
                        ext_dict
                        for ext_dict in v
                        if ext_dict['id'] not in EXTNS_EXCLUDED_FROM_TEMPLATE
                    ],
                )
            else:
                yield k, v
