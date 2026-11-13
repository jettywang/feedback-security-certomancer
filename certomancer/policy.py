"""
Deployment policies for Certomancer service endpoints.

Certomancer is a testing tool, but a shared Animator instance still
wields real private keys (to sign CRLs, OCSP responses and timestamps).
The public-only policy in this module makes sure that those keys can
never be extracted through an export endpoint, regardless of whether
the web UI is enabled or how the export is packaged (PFX, ZIP, CLI, ...).
"""

from dataclasses import dataclass
from typing import Any, Optional

from .config_utils import ConfigurationError, check_config_keys
from .services import PrivateKeyExportDisabled, RestrictedServiceError

__all__ = [
    'ServicePolicy',
]


@dataclass(frozen=True)
class ServicePolicy:
    """
    Controls what a deployed Animator instance is allowed to expose.

    ``restricted`` enables public-only mode: certificate, OCSP, CRL and
    TSA endpoints stay available, but any operation that would export
    private key material is rejected with an explicit error (HTTP 403
    in both HTTP adapters). Plugin endpoints are disabled by default
    because a plugin can return arbitrary bytes; set
    ``allow_plugin_endpoints`` to opt in to a reviewed plugin set.

    The default policy (``ServicePolicy()``) preserves the historical
    single-machine development behaviour.
    """

    restricted: bool = False
    allow_plugin_endpoints: bool = False

    @classmethod
    def from_config(cls, config_value: Any) -> 'ServicePolicy':
        """
        Parse the top-level ``restricted-mode`` configuration entry.

        Accepted forms::

            restricted-mode: true

            restricted-mode:
              enabled: true
              allow-plugins: false

        Anything else raises :class:`.ConfigurationError`, which callers
        (CLI, WSGI entrypoint) surface before serving a single request.
        """
        if config_value is None:
            return cls()
        if isinstance(config_value, bool):
            return cls(restricted=config_value)
        if not isinstance(config_value, dict):
            raise ConfigurationError(
                "'restricted-mode' must be a boolean or a dictionary with "
                "'enabled' and optional 'allow-plugins' keys; got "
                f"{type(config_value).__name__}."
            )

        check_config_keys(
            'restricted-mode', ('enabled', 'allow-plugins'), config_value
        )
        enabled = config_value.get('enabled', True)
        if not isinstance(enabled, bool):
            raise ConfigurationError(
                "'restricted-mode.enabled' must be a boolean."
            )
        allow_plugins = config_value.get('allow-plugins', False)
        if not isinstance(allow_plugins, bool):
            raise ConfigurationError(
                "'restricted-mode.allow-plugins' must be a boolean."
            )
        return cls(
            restricted=enabled, allow_plugin_endpoints=allow_plugins
        )

    def merge(self, override: Optional['ServicePolicy']) -> 'ServicePolicy':
        """
        Combine this (file) policy with an operator-supplied override.

        Neither source can weaken the other: both ``restricted`` and
        ``allow_plugin_endpoints`` are combined with logical OR.

        A config file can therefore never re-enable a key export path that
        the operator locked down, and an operator override cannot silently
        discard a reviewed plugin allowlist either.
        """
        if override is None:
            return self
        return ServicePolicy(
            restricted=self.restricted or override.restricted,
            allow_plugin_endpoints=(
                self.allow_plugin_endpoints or override.allow_plugin_endpoints
            ),
        )

    def assert_private_key_export_allowed(self, operation: str):
        """
        Reject operations that would hand private key material to a caller.

        :raises PrivateKeyExportDisabled:
            if the policy is in restricted mode.
        """
        if self.restricted:
            raise PrivateKeyExportDisabled(
                f"{operation} is disabled: this Animator runs in "
                "public-only restricted mode and must never export "
                "private key material."
            )

    def assert_plugin_endpoint_allowed(self, label=None):
        """
        Reject plugin service calls unless explicitly allowlisted.

        :raises RestrictedServiceError:
            if plugin endpoints are not permitted by the policy.
        """
        if self.restricted and not self.allow_plugin_endpoints:
            target = f" '{label}'" if label is not None else ''
            raise RestrictedServiceError(
                f"Plugin service endpoint{target} is disabled in "
                "public-only restricted mode. Set "
                "'restricted-mode.allow-plugins: true' only for reviewed "
                "plugins that do not expose key material."
            )
