from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.secrets import SecretDetectionEngine


@register_workflow_rule
class HardcodedSecretsRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        yaml_str = yaml.dump(workflow, sort_keys=False)
        for secret in secret_engine.detect_in_text(yaml_str):
            if "${{" in secret.value or "secrets." in secret.value:
                continue
            out.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="Hardcoded Secret",
                    description=f"Обнаружен hardcoded секрет типа '{secret.secret_type}'.",
                    location=str(path),
                    recommendation="Перенесите секрет в GitHub Secrets/Variables и подставляйте через ${{ secrets.NAME }}.",
                    evidence=(secret.value[:20] + "...") if len(secret.value) > 20 else secret.value,
                )
            )
        return out
