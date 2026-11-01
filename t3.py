"""Compatibility launcher; installed users can run t3-inspect or python -m t3core."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "T3-Phishing-Detection"))
from t3core.cli import main

if __name__ == "__main__":
    main()
