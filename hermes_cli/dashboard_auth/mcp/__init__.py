"""The gateway as the OAuth 2.1 authorization server for its remote MCP endpoint (``/mcp``).

:mod:`.store` is the grant registry (``$HERMES_HOME/dashboard_auth/mcp.db``), :mod:`.settings` reads the
``dashboard.mcp`` config section, :mod:`.provider` implements the ``mcp`` SDK's authorization-server
provider and token verifier over the store, :mod:`.mount` switches the feature on at startup (or leaves it
off and says why), :mod:`.routes` and :mod:`.consent` are its HTTP surface, :mod:`.api_routes` is what the
app's Settings › MCP page reads (``/api/auth/mcp``), and :mod:`.cli` is ``hermes dashboard mcp``. Only
:mod:`.provider`, :mod:`.routes` and :mod:`.consent` need the ``mcp`` package (the ``[mcp]`` extra):
:mod:`.mount` imports them lazily, when the feature is enabled, so a gateway without the extra still
imports this package, its store, its settings, the mount, the app's routes and the CLI.
"""
