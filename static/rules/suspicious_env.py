from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.rules.utils import contains_secret_context, get_env, is_expression, iter_jobs, iter_steps
from static.secrets import SecretDetectionEngine


@register_workflow_rule
class SuspiciousEnvRule(WorkflowRule):
    def evaluate(
        self,
        workflow: Dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> List[Finding]:
        out: List[Finding] = []

        def check_env(env: Dict[str, str], location: str) -> None:
            for k, v in env.items():
                if not secret_engine.is_suspicious_env_name(k):
                    continue
                if not isinstance(v, str) or not v.strip():
                    continue
                if is_expression(v) or contains_secret_context(v):
                    continue
                out.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="Hardcoded Secret",
                        description=f"Подозрительная переменная окружения '{k}' имеет литеральное значение (возможный hardcoded секрет).",
                        location=location,
                        recommendation="Перенесите значение в GitHub Secrets/Variables и подставляйте через ${{ secrets.NAME }}.",
                        evidence=(v[:20] + "...") if len(v) > 20 else v,
                    )
                )

        check_env(get_env(workflow), f"{path}:env")

        for job_name, job_config in iter_jobs(workflow):
            check_env(get_env(job_config), f"{path}:jobs.{job_name}.env")
            for idx, step in iter_steps(job_config):
                check_env(get_env(step), f"{path}:jobs.{job_name}.steps[{idx}].env")

        return out
