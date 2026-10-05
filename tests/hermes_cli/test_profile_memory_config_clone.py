"""``--clone`` carries a memory provider's CONFIG, never another profile's memory DATA (HERM-127).

``clone_memory_provider_config`` copies ``<home>/<provider>/`` and ``<home>/<provider>.json`` by
convention. Three providers keep only runtime data in that directory, with their settings in
``config.yaml`` (which the clone copies anyway):

* ``mem0/``: the OSS history database, the past texts of the source's memories;
* ``byterover/``: the ``brv`` working directory, i.e. the source's curated context tree and its
  project binding;
* ``openviking/``: ``pending_sessions/`` markers of the source's own sessions awaiting commit (a clone
  holding them would commit the source's conversations as its own on its first start) and ``runs/``
  locks.

Each recreates its directory on first use, so the clone starts empty and working.
"""

from __future__ import annotations

import pytest

from hermes_cli.profile_memory_config import clone_memory_provider_config


@pytest.mark.parametrize("provider, data_file", [
    ("mem0", "history.db"),
    ("byterover", ".brv/context-tree/marker.md"),
    ("openviking", "pending_sessions/marker-session.json"),
])
def test_a_providers_data_directory_stays_with_the_source(tmp_path, provider, data_file):
    source, clone = tmp_path / "source", tmp_path / "clone"
    (source / provider / data_file).parent.mkdir(parents=True)
    (source / provider / data_file).write_text("the source profile's memory data marker")
    clone.mkdir()

    clone_memory_provider_config(source, clone, provider)

    assert not (clone / provider).exists()


def test_a_providers_config_directory_still_travels(tmp_path):
    """hindsight keeps its settings in ``hindsight/``: that is config, and the clone needs it."""
    source, clone = tmp_path / "source", tmp_path / "clone"
    (source / "hindsight").mkdir(parents=True)
    (source / "hindsight" / "config.json").write_text("{}")
    clone.mkdir()

    assert clone_memory_provider_config(source, clone, "hindsight") is True
    assert (clone / "hindsight" / "config.json").is_file()
