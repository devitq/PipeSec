from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.secrets import SecretDetectionEngine


@register_workflow_rule
class DangerousTriggersRule(WorkflowRule):
    def evaluate(
        self,
        workflow: Dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> List[Finding]:
        out: List[Finding] = []
        on_triggers = workflow.get("on", {})
        if isinstance(on_triggers, str):
            on_triggers = {on_triggers: {}}

        if isinstance(on_triggers, dict) and "pull_request_target" in on_triggers:
            out.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="Dangerous Trigger",
                    description="Использование 'pull_request_target' может привести к утечке секретов из форков.",
                    location=f"{path}:on.pull_request_target",
                    recommendation=(
                        "Используйте 'pull_request' вместо 'pull_request_target' или добавьте строгую проверку источника PR. "
                        "Не выполняйте непроверенный код из PR с доступом к secrets."
                    ),
                )
            )
        return out
