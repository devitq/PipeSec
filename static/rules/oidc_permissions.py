from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.secrets import SecretDetectionEngine


def _check_permissions_obj(permissions: Any) -> bool:
    if not isinstance(permissions, dict):
        return False
    v = permissions.get("id-token")
    return isinstance(v, str) and v.strip().lower() == "write"


@register_workflow_rule
class OIDCPermissionsRule(WorkflowRule):
    def evaluate(
        self,
        workflow: Dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> List[Finding]:
        out: List[Finding] = []

        if _check_permissions_obj(workflow.get("permissions")):
            out.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="Permissions",
                    description="Workflow запрашивает 'id-token: write' (OIDC).",
                    location=f"{path}:permissions.id-token",
                    recommendation=(
                        "Используйте 'id-token: write' только когда это необходимо (OIDC federation). "
                        "Убедитесь, что доверенные аудитории/провайдеры настроены строго и минимизируйте остальные permissions."
                    ),
                )
            )

        jobs = workflow.get("jobs", {})
        if isinstance(jobs, dict):
            for job_name, job_config in jobs.items():
                if not isinstance(job_config, dict):
                    continue
                if _check_permissions_obj(job_config.get("permissions")):
                    out.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="Permissions",
                            description=f"Job '{job_name}' запрашивает 'id-token: write' (OIDC).",
                            location=f"{path}:jobs.{job_name}.permissions.id-token",
                            recommendation=(
                                "Запрашивайте OIDC токен только в job, который его использует, и только на время необходимости."
                            ),
                        )
                    )

        return out
