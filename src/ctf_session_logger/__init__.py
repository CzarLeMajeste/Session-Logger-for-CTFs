"""ctf_session_logger – Session Logger for CTFs.

Provides:
    - dump2note: Convert raw data dumps into structured Markdown notes.
    - gui:       Tkinter-based desktop front-end.
"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("ctf-session-logger")
except PackageNotFoundError:  # running directly from source
    __version__ = "0.1.0a1"

__all__ = ["__version__"]
