from __future__ import annotations

from pathlib import Path
from typing import Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.secrets import SecretDetectionEngine


@register_workflow_rule
class ExcessivePermissionsRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        permissions = workflow.get("permissions")
        if permissions is None:
            out.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="Permissions",
                    description="Workflow не задаёт явные permissions для GITHUB_TOKEN.",
                    location=f"{path}:permissions",
                    recommendation=(
                        "Явно задавайте минимально необходимые permissions (principle of least privilege). "
                        "Это снижает риск эскалации при компрометации runner/Action."
                    ),
                )
            )
            return out

        if permissions == "write-all":
            out.append(
                Finding(
                    severity=Severity.HIGH,
                    category="Excessive Permissions",
                    description="Workflow имеет 'write-all' permissions.",
                    location=f"{path}:permissions",
                    recommendation="Используйте принцип наименьших привилегий: перечислите только необходимые permissions.",
                )
            )

        if isinstance(permissions, dict):
            risky = {"contents", "packages", "actions", "pull-requests", "issues", "deployments"}
            for k, v in permissions.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    continue
                if k in risky and v.lower().strip() == "write":
                    out.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="Permissions",
                            description=f"Workflow запрашивает повышенные privileges: '{k}: write'.",
                            location=f"{path}:permissions.{k}",
                            recommendation="Проверьте необходимость write-доступа и минимизируйте permissions, где это возможно.",
                        )
                    )
        return out
