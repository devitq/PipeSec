from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from static.models import Finding


def to_json_dict(findings: list[Finding]) -> dict[str, Any]:
    return {
        "findings": [asdict(f) for f in findings],
        "count": len(findings),
        "countsBySeverity": {
            sev: sum(1 for f in findings if f.severity.value == sev)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        },
    }


def render_json(findings: list[Finding], *, indent: int = 2) -> str:
    return json.dumps(to_json_dict(findings), ensure_ascii=False, indent=indent)
