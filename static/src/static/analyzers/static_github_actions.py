from __future__ import annotations

from pathlib import Path

import yaml  # type: ignore[import-untyped]

from static.models import Finding, Severity
from static.rules import default_workflow_rules
from static.secrets import SecretDetectionEngine


class StaticGithubActionsAnalyzer:
    def __init__(
        self,
        secret_engine: SecretDetectionEngine,
        *,
        enabled_rules: set[str] | None = None,
        disabled_rules: set[str] | None = None,
    ):
        self.secret_engine = secret_engine
        self.enabled_rules = enabled_rules
        self.disabled_rules = disabled_rules

    @staticmethod
    def _rule_id(rule: object) -> str:
        module = getattr(rule.__class__, "__module__", "")
        return module.split(".")[-1] if isinstance(module, str) and module else ""

    @staticmethod
    def _rule_fqn(rule: object) -> str:
        module = getattr(rule.__class__, "__module__", "")
        name = getattr(rule.__class__, "__name__", "")
        if (
            not isinstance(module, str)
            or not isinstance(name, str)
            or not module
            or not name
        ):
            return ""
        return f"{module}.{name}"

    def _is_rule_enabled(self, rule: object) -> bool:
        rule_id = self._rule_id(rule)
        rule_fqn = self._rule_fqn(rule)

        if self.enabled_rules is not None and len(self.enabled_rules) > 0:
            if rule_id not in self.enabled_rules and rule_fqn not in self.enabled_rules:
                return False

        if self.disabled_rules is not None and len(self.disabled_rules) > 0:
            if rule_id in self.disabled_rules or rule_fqn in self.disabled_rules:
                return False

        return True

    def analyze_workflow_file(self, workflow_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            workflow_text = workflow_path.read_text(encoding="utf-8")
        except Exception as exc:
            return [
                Finding(
                    severity=Severity.HIGH,
                    category="IO Error",
                    description=f"Не удалось прочитать файл: {exc}",
                    location=str(workflow_path),
                    recommendation="Проверьте путь и права доступа к файлу.",
                )
            ]

        try:
            workflow = yaml.safe_load(workflow_text)
        except Exception as exc:
            return [
                Finding(
                    severity=Severity.HIGH,
                    category="Parse Error",
                    description=f"Не удалось разобрать YAML файл: {exc}",
                    location=str(workflow_path),
                    recommendation="Проверьте синтаксис YAML файла.",
                )
            ]

        if not isinstance(workflow, dict):
            return [
                Finding(
                    severity=Severity.HIGH,
                    category="Parse Error",
                    description="YAML разобран, но корневой объект не является словарём.",
                    location=str(workflow_path),
                    recommendation="Проверьте формат workflow (ожидается mapping).",
                )
            ]

        for rule in default_workflow_rules():
            if self._is_rule_enabled(rule):
                findings.extend(rule.evaluate(workflow, workflow_path, self.secret_engine))

        return findings
