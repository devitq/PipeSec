from __future__ import annotations

from pathlib import Path

__all__ = ["__version__"]
__version__ = "0.1.0"

# Delegate module loading to the src-layout implementation.
# This keeps imports like `static.cli` working when running from the repo
# without requiring installation.
_src_static = Path(__file__).resolve().parent / "src" / "static"
if _src_static.is_dir():
    __path__ = [str(_src_static)]  # type: ignore[name-defined]
