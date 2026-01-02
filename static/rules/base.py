from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List

from static.models import Finding
from static.secrets import SecretDetectionEngine


class WorkflowRule(ABC):
    @abstractmethod
    def evaluate(
        self,
        workflow: Dict[str, Any],
        path: Path,
        secret_engine: SecretDetectionEngine,
    ) -> List[Finding]:
        raise NotImplementedError
