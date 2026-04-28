#!/usr/bin/env python3
"""
dump2note.py – Entry-point shim.

Run this file directly (``python dump2note.py``) **or** install the package
with ``pip install .`` and use the ``dump2note`` console-script entry point.

The actual implementation lives in
``src/ctf_session_logger/dump2note.py`` so it can be imported as a package
module once installed.  All symbols are re-exported here so that existing code
that does ``import dump2note`` continues to work unchanged.
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

import ctf_session_logger.dump2note as _impl  # noqa: E402

# Re-export every symbol so ``import dump2note; dump2note.detect_tool(...)``
# keeps working without modification.
globals().update(vars(_impl))

if __name__ == "__main__":
    sys.exit(_impl.main())
