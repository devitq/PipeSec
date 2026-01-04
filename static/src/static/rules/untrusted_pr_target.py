from __future__ import annotations

from pathlib import Path
from typing import Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.rules.utils import (
    get_run,
    get_step_name,
    iter_jobs,
    iter_steps,
    run_has_local_exec,
)
from static.secrets import SecretDetectionEngine


@register_workflow_rule
class UntrustedCodeOnPRTargetRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        on_triggers = workflow.get("on", {})
        if isinstance(on_triggers, str):
            on_triggers = {on_triggers: {}}

        if not (isinstance(on_triggers, dict) and "pull_request_target" in on_triggers):
            return out

        for job_name, job_config in iter_jobs(workflow):
            for idx, step in iter_steps(job_config):
                run = get_run(step)
                if not isinstance(run, str):
                    continue
                if not run_has_local_exec(run):
                    continue

                step_name = get_step_name(step, idx)
                out.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="Untrusted Code Execution",
                        description=(
                            f"В шаге '{step_name}' выполняется локальный скрипт/файл при trigger 'pull_request_target'. "
                            "Это может позволить PR-автору выполнить произвольный код с доступом к secrets."
                        ),
                        location=f"{path}:jobs.{job_name}.steps[{idx}]",
                        recommendation=(
                            "Не выполняйте код из PR при pull_request_target. Используйте pull_request или разделите workflow: "
                            "безопасные проверки для PR, а деплой/секреты — только после merge/approval."
                        ),
                    )
                )

        return out
