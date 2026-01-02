from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional


@dataclass(frozen=True)
class SecretMatch:
    secret_type: str
    value: str


class SecretDetectionEngine:
    """Pattern-based secret detection.

    Note: This is heuristic and can yield false positives/negatives.
    """

    DEFAULT_PATTERNS: Dict[str, str] = {
        "GitHub Token (classic)": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "GitHub Token (fine-grained)": r"github_pat_[A-Za-z0-9_]{80,255}",
        "GitLab Personal Access Token": r"glpat-[A-Za-z0-9_\-]{20,}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"(?i)aws(.{0,20})?[\"'][0-9a-zA-Z/+]{40}[\"']",
        "Slack Token": r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,32}",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "Private Key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "JWT (possible)": r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}",
        "Generic Secret": r"(?i)(secret|password|api[_-]?key|token|credential)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?",
    }

    SUSPICIOUS_ENV_NAME_SUBSTRINGS = [
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "CREDENTIALS",
        "AUTH",
    ]

    def __init__(self, *, patterns_path: Optional[Path] = None):
        self._patterns: Dict[str, str] = dict(self.DEFAULT_PATTERNS)

        resolved = self._resolve_patterns_path(patterns_path)
        if resolved is not None:
            loaded = self._load_patterns_json(resolved)
            if loaded:
                self._patterns = loaded

    def detect_in_text(self, text: str) -> List[SecretMatch]:
        matches: List[SecretMatch] = []
        for secret_type, pattern in self._patterns.items():
            for match in re.finditer(pattern, text):
                matches.append(SecretMatch(secret_type=secret_type, value=match.group(0)))
        return matches

    @staticmethod
    def _resolve_patterns_path(patterns_path: Optional[Path]) -> Optional[Path]:
        if patterns_path is not None:
            return patterns_path

        here = Path(__file__).resolve()
        candidate = here.parent.parent / "data" / "secret_patterns.json"
        if candidate.exists():
            return candidate
        return None

    @staticmethod
    def _load_patterns_json(path: Path) -> Dict[str, str]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

        patterns = {}
        items = data.get("patterns")
        if not isinstance(items, list):
            return {}

        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            regex = item.get("regex")
            if not isinstance(name, str) or not isinstance(regex, str):
                continue
            patterns[name] = regex
        return patterns

    def is_suspicious_env_name(self, name: str) -> bool:
        upper = name.upper()
        return any(s in upper for s in self.SUSPICIOUS_ENV_NAME_SUBSTRINGS)

    def iter_suspicious_env_names(self, env: Iterable[str]) -> List[str]:
        out: List[str] = []
        for entry in env:
            if "=" not in entry:
                continue
            k = entry.split("=", 1)[0]
            if self.is_suspicious_env_name(k):
                out.append(k)
        return sorted(set(out))
