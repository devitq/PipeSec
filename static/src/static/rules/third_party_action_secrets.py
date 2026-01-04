from __future__ import annotations

from pathlib import Path
from typing import Any

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.rules.utils import (
    contains_secret_context,
    get_env,
    get_uses,
    is_expression,
    iter_jobs,
    iter_steps,
)
from static.secrets import SecretDetectionEngine


def _dict_values_strings(d: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for v in d.values():
        if isinstance(v, str):
            out.append(v)
    return out


@register_workflow_rule
class ThirdPartyActionSecretsRule(WorkflowRule):
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        out: list[Finding] = []
        for job_name, job_config in iter_jobs(workflow):
            for idx, step in iter_steps(job_config):
                uses = get_uses(step)
                if not isinstance(uses, str) or "@" not in uses:
                    continue

                action, _ref = uses.rsplit("@", 1)
                if action.startswith("actions/"):
                    continue

                env_values = list(get_env(step).values())
                with_cfg = step.get("with", {})
                with_values: list[str] = _dict_values_strings(with_cfg) if isinstance(with_cfg, dict) else []

                passed = [
                    v
                    for v in (env_values + with_values)
                    if isinstance(v, str) and (is_expression(v) or contains_secret_context(v))
                ]
                if not passed:
                    continue

                out.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="Third-Party Action",
                        description="Секреты/токены передаются в сторонний GitHub Action.",
                        location=f"{path}:jobs.{job_name}.steps[{idx}]",
                        recommendation=(
                            "Минимизируйте передачу secrets в сторонние actions. Предпочитайте официальные actions, "
                            "проверяйте репутацию/подпись, закрепляйте по SHA и используйте отдельный токен с минимальными правами."
                        ),
                        evidence=uses,
                    )
                )

        return out
