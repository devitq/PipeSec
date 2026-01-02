from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.rules.utils import get_run, get_step_name, iter_jobs, iter_steps
from static.secrets import SecretDetectionEngine


@register_workflow_rule
class InsecureDownloadsRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []

        pipe_exec = re.compile(
            r"(?i)\b(curl|wget)\b[^\n]*\|\s*(bash|sh|zsh|python|python3)\b"
        )

        for job_name, job_config in iter_jobs(workflow):
            for idx, step in iter_steps(job_config):
                run = get_run(step)
                if not isinstance(run, str):
                    continue
                if pipe_exec.search(run):
                    step_name = get_step_name(step, idx)
                    out.append(
                        Finding(
                            severity=Severity.HIGH,
                            category="Supply Chain",
                            description=(
                                f"В шаге '{step_name}' обнаружен потенциально небезопасный паттерн загрузки и выполнения: curl/wget | shell."
                            ),
                            location=f"{path}:jobs.{job_name}.steps[{idx}]",
                            recommendation=(
                                "Избегайте curl|bash. Загружайте артефакт по HTTPS, проверяйте checksum/подпись и выполняйте локально. "
                                "Предпочитайте фиксированные версии и проверенные источники."
                            ),
                        )
                    )

        return out
