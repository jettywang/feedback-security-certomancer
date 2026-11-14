"""
Offline SCEP (RFC 8894) test responder packaged as a Certomancer service
plugin. Importing this package registers the ``scep-responder`` service
plugin with Certomancer's default service plugin registry.
"""

# Register with the default registry on import.
from certomancer.registry import service_plugin_registry

from .responder import ScepResponderPlugin, ScepServiceConfig
from .responder import ScepResponderPlugin as _Plugin

service_plugin_registry.register(_Plugin)

__all__ = ['ScepResponderPlugin', 'ScepServiceConfig']
