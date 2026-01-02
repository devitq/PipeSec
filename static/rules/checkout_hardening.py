from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.rules.utils import get_uses, iter_jobs, iter_steps
from static.secrets import SecretDetectionEngine


@register_workflow_rule
class CheckoutCredentialPersistenceRule(WorkflowRule):
    def evaluate(
        self,
        workflow: Dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> List[Finding]:
        out: List[Finding] = []

        for job_name, job_config in iter_jobs(workflow):
            for idx, step in iter_steps(job_config):
                uses = get_uses(step)
                if not isinstance(uses, str):
                    continue
                if not uses.startswith("actions/checkout"):
                    continue

                with_cfg = step.get("with", {})
                if not isinstance(with_cfg, dict):
                    with_cfg = {}

                pc = with_cfg.get("persist-credentials")
                if pc is None or (isinstance(pc, str) and pc.strip().lower() in {"true", "1", "yes", "on"}):
                    out.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="Checkout Hardening",
                            description=(
                                "actions/checkout выполняется с persist-credentials=true (явно или по умолчанию). "
                                "Это оставляет токен в git-конфиге и увеличивает риск злоупотребления при выполнении стороннего кода."
                            ),
                            location=f"{path}:jobs.{job_name}.steps[{idx}]",
                            recommendation=(
                                "Установите `with: persist-credentials: false` для actions/checkout, если push не требуется. "
                                "Также минимизируйте permissions для GITHUB_TOKEN."
                            ),
                        )
                    )

        return out
