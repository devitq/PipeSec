from __future__ import annotations

from pathlib import Path
from typing import Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.rules.utils import get_uses, iter_jobs, iter_steps
from static.secrets import SecretDetectionEngine


@register_workflow_rule
class PRTargetUntrustedCheckoutRule(WorkflowRule):
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
                uses = get_uses(step)
                if not isinstance(uses, str):
                    continue
                if not uses.startswith("actions/checkout"):
                    continue

                with_cfg = step.get("with", {})
                if not isinstance(with_cfg, dict):
                    continue

                ref = with_cfg.get("ref")
                if not isinstance(ref, str):
                    continue

                lower = ref.lower()
                if (
                    "github.event.pull_request.head" in lower
                    or "github.head_ref" in lower
                    or "pull_request.head" in lower
                ):
                    out.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            category="Untrusted Code Execution",
                            description=(
                                "В workflow с 'pull_request_target' выполняется checkout PR head ref/sha. "
                                "Это типовой путь к выполнению кода из форка с доступом к secrets."
                            ),
                            location=f"{path}:jobs.{job_name}.steps[{idx}].with.ref",
                            recommendation=(
                                "Не делайте checkout кода из PR в workflow на pull_request_target. "
                                "Используйте pull_request или разделите workflow: проверки для PR без secrets, "
                                "а деплой/секреты — только после merge/approval."
                            ),
                            evidence=ref,
                        )
                    )
        return out
