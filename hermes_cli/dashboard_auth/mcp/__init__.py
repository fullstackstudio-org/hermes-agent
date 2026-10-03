"""The gateway as the OAuth 2.1 authorization server for its remote MCP endpoint (``/mcp``).

:mod:`.store` is the grant registry (``$HERMES_HOME/dashboard_auth/mcp.db``), :mod:`.settings` reads the
``dashboard.mcp`` config section, and :mod:`.provider` implements the ``mcp`` SDK's authorization-server
provider and token verifier over the store. Only :mod:`.provider` needs the ``mcp`` package (the
``[mcp]`` extra): import it lazily, when the feature is enabled, so a gateway without the extra still
imports this package, its store and its settings.
"""
