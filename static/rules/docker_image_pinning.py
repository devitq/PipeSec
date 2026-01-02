from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from static.models import Finding, Severity
from static.rules.base import WorkflowRule
from .registry import register_workflow_rule
from static.rules.utils import get_uses, iter_jobs, iter_steps
from static.secrets import SecretDetectionEngine


@register_workflow_rule
class DockerImagePinningRule(WorkflowRule):
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

                if not uses.startswith("docker://"):
                    continue

                image = uses[len("docker://") :]
                if "@sha256:" in image:
                    continue

                if ":" not in image or image.endswith(":latest"):
                    out.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            category="Supply Chain",
                            description="Используется docker image без pin на digest (или с latest).",
                            location=f"{path}:jobs.{job_name}.steps[{idx}].uses",
                            recommendation=(
                                "Закрепляйте docker image по digest (docker://image@sha256:...) или используйте фиксированный тег. "
                                "Это снижает риск supply-chain подмены."
                            ),
                            evidence=uses,
                        )
                    )

        return out
