#!/usr/bin/env python3
"""
gui.py – Entry-point shim.

Run this file directly (``python gui.py``) **or** install the package
with ``pip install .`` and use the ``ctf-session-logger-gui`` console-script
entry point.

The actual implementation lives in
``src/ctf_session_logger/gui.py`` so it can be imported as a package
module once installed.
"""

import os
import sys

# ---------------------------------------------------------------------------
# Make the package importable when running directly from the repository root
# (i.e. before ``pip install``).
# ---------------------------------------------------------------------------
_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if os.path.isdir(_src) and _src not in sys.path:
    sys.path.insert(0, _src)

from ctf_session_logger.gui import main  # noqa: E402

if __name__ == "__main__":
    main()
