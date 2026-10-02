"""Passkeys for the ``confirm`` level ``passkey``: the challenge construction (:mod:`.challenge`), the CBOR
subset (:mod:`.cbor`), the WebAuthn verifier (:mod:`.webauthn`), the store (:mod:`.store`), the
``confirm.passkey`` settings (:mod:`.settings`) and the operator commands (:mod:`.cli`).

The construction and the verification order are defined by ``contract/confirm-passkey/README.md``; the
vectors in ``contract/confirm-passkey/vectors.json`` are the test of this package. Nothing here imports
the gateway's request machinery: the verifier is pure (no I/O, no clock, no logging of inputs) so the
``confirm`` answer path can call it under its lock, twice if it must.
"""
