from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def raw_scenario(name: str = "payroll-no-malware.json") -> Dict[str, Any]:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
