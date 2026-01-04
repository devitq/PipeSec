__all__ = ["__version__"]

# Keep version in sync with the legacy `static` package.
try:
    from static import __version__  # type: ignore
except Exception:  # pragma: no cover
    __version__ = "0.1.0"
