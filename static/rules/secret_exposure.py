from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.rules.utils import get_step_name, iter_jobs, iter_steps
from static.secrets import SecretDetectionEngine


@register_workflow_rule
class SecretExposureRule(WorkflowRule):
    def evaluate(
        self,
        workflow: Dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> List[Finding]:
        out: List[Finding] = []
        for job_name, job_config in iter_jobs(workflow):
            for idx, step in iter_steps(job_config):

                run_command = step.get("run", "")
                if isinstance(run_command, str) and re.search(
                    r"(echo|print).*(\$\{\{\s*secrets\.|\$\{\{\s*github\.token\s*\}\})",
                    run_command,
                    re.IGNORECASE,
                ):
                    step_name = get_step_name(step, idx)
                    out.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            category="Secret Exposure",
                            description=f"Секрет может быть выведен в логи через echo/print в шаге '{step_name}'.",
                            location=f"{path}:jobs.{job_name}.steps[{idx}]",
                            recommendation="Не выводите secrets/token в stdout. Если нужно отладить — используйте маскирование и redaction.",
                        )
                    )

                uses_value = step.get("uses", "")
                if isinstance(uses_value, str) and uses_value.startswith("actions/upload-artifact"):
                    with_config = step.get("with", {})
                    if isinstance(with_config, dict):
                        upload_path = str(with_config.get("path", ""))
                        if any(k in upload_path.lower() for k in ["env", "secret", ".env", "credential"]):
                            out.append(
                                Finding(
                                    severity=Severity.HIGH,
                                    category="Artifact Exposure",
                                    description=f"Артефакт может содержать секреты: '{upload_path}'.",
                                    location=f"{path}:jobs.{job_name}.steps[{idx}]",
                                    recommendation="Исключите .env/credentials/secrets из артефактов (artifact exclude / отдельные пути).",
                                )
                            )

        return out
