"""The deterministic fix-loop demo, runnable by path from a checkout.

The engine is `aether/fix_loop.py`, inside the package, so that
`aether fix-loop` works in a pip-installed copy (BUGS.md BUG-026). This
file only keeps the demo's documented entry point working:

  python -B demos/payment_workflow/fix_loop.py demos/payment_workflow/broken.aeth
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "transpiler"))

from aether.fix_loop import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
