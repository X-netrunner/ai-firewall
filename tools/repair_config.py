#!/usr/bin/env python3
"""Use the shared transactional repair coordinator; defaults to a dry run."""
import runpy, sys
from pathlib import Path
runner=Path(__file__).resolve().parents[2]/"recovery-kit"/"recovery.py"
sys.argv.extend(["--component", "ai-firewall"])
runpy.run_path(str(runner), run_name="__main__")
