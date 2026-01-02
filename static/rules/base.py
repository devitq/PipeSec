from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from static.models import Finding
from static.secrets import SecretDetectionEngine


class WorkflowRule(ABC):
    @abstractmethod
    def evaluate(
        self,
        workflow: dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> list[Finding]:
        raise NotImplementedError
