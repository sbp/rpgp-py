from __future__ import annotations

import subprocess
from pathlib import Path


def pytest_sessionstart(session) -> None:
    project_root = Path(__file__).resolve().parents[1]
    subprocess.run(
        ["maturin", "develop", "--quiet"],
        check=True,
        cwd=project_root,
    )
