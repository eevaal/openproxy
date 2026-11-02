from pathlib import Path

import pytest

from openproxy.core.config import CONFIG_ENV


@pytest.fixture(autouse=True)
def isolated_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(CONFIG_ENV, raising=False)
