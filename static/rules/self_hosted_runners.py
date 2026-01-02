from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.rules.utils import iter_jobs
from static.secrets import SecretDetectionEngine


@register_workflow_rule
class SelfHostedRunnerRule(WorkflowRule):
    def evaluate(
        self,
        workflow: Dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> List[Finding]:
        out: List[Finding] = []

        for job_name, job_config in iter_jobs(workflow):
            runs_on = job_config.get("runs-on")

            labels: List[str] = []
            if isinstance(runs_on, str):
                labels = [runs_on]
            elif isinstance(runs_on, list):
                labels = [x for x in runs_on if isinstance(x, str)]

            if any(lbl.lower().strip() == "self-hosted" for lbl in labels):
                out.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="Runner",
                        description=f"Job '{job_name}' использует self-hosted runner.",
                        location=f"{path}:jobs.{job_name}.runs-on",
                        recommendation=(
                            "Self-hosted runners повышают риск (персистентное окружение, возможные остатки секретов/артефактов). "
                            "Рекомендуется усилить hardening, изоляцию, очистку workspace, контроль egress и минимизировать permissions."
                        ),
                    )
                )

        return out
