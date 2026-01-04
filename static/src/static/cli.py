from __future__ import annotations

import argparse
from pathlib import Path

from static.analyzers.logs import LogAnalyzer
from static.analyzers.static_github_actions import StaticGithubActionsAnalyzer
from static.models import Finding, Severity
from static.reporting.console import render_console_report
from static.reporting.json_report import render_json
from static.secrets import SecretDetectionEngine
from static.rules.registry import default_workflow_rules


def _read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pipesec",
        description="PipeSec: гибридный анализатор безопасности CI/CD workflow",
    )

    parser.add_argument(
        "workflow", type=Path, nargs="?", help="Путь к workflow YAML (GitHub Actions)"
    )
    parser.add_argument(
        "--log",
        dest="log_path",
        type=Path,
        default=None,
        help="Путь к логу выполнения (опционально)",
    )
    parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
        help="Формат отчёта",
    )
    parser.add_argument(
        "--out",
        dest="out_path",
        type=Path,
        default=None,
        help="Записать отчёт в файл вместо stdout",
    )

    parser.add_argument(
        "--patterns",
        dest="patterns_path",
        type=Path,
        default=None,
        help=(
            "Путь к JSON с regex-паттернами секретов (опционально). "
            "По умолчанию используется data/secret_patterns.json, если он существует."
        ),
    )

    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Вывести список доступных правил статического анализа и выйти",
    )
    parser.add_argument(
        "--enable-rule",
        dest="enable_rules",
        action="append",
        default=[],
        help=(
            "Включить только указанные правила статического анализа (можно повторять). "
            "Значение: rule id (например, dangerous_triggers) или полное имя класса "
            "(например, static.rules.dangerous_triggers.DangerousTriggersRule)."
        ),
    )
    parser.add_argument(
        "--disable-rule",
        dest="disable_rules",
        action="append",
        default=[],
        help=(
            "Отключить указанные правила статического анализа (можно повторять). "
            "Значение: rule id или полное имя класса."
        ),
    )

    args = parser.parse_args(argv)

    if args.workflow is None and not args.list_rules:
        parser.print_help()
        return 0

    if args.list_rules:
        rules = default_workflow_rules()
        for rule in rules:
            rule_id = StaticGithubActionsAnalyzer._rule_id(rule)
            rule_fqn = StaticGithubActionsAnalyzer._rule_fqn(rule)
            print(f" - id: {rule_id}, fqdn: {rule_fqn}")
        return 0

    findings: list[Finding] = []

    if not args.workflow.exists():
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category="IO Error",
                description=f"Файл не найден: {args.workflow}",
                location=str(args.workflow),
                recommendation="Укажите корректный путь к workflow.yml.",
            )
        )
    else:
        secret_engine = SecretDetectionEngine(patterns_path=args.patterns_path)
        enabled = {
            r.strip() for r in args.enable_rules if isinstance(r, str) and r.strip()
        }
        disabled = {
            r.strip() for r in args.disable_rules if isinstance(r, str) and r.strip()
        }
        static_analyzer = StaticGithubActionsAnalyzer(
            secret_engine,
            enabled_rules=enabled if enabled else None,
            disabled_rules=disabled if disabled else None,
        )
        findings.extend(static_analyzer.analyze_workflow_file(args.workflow))

        if args.log_path is not None:
            if args.log_path.exists():
                log_analyzer = LogAnalyzer(secret_engine)
                findings.extend(
                    log_analyzer.analyze_text(
                        _read_text_file(args.log_path), str(args.log_path)
                    )
                )
            else:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="IO Warning",
                        description=f"Файл лога не найден: {args.log_path}",
                        location=str(args.log_path),
                        recommendation="Либо укажите существующий файл лога, либо уберите --log.",
                    )
                )

    if args.format == "json":
        report = render_json(findings)
    else:
        report = render_console_report(findings)

    if args.out_path is not None:
        args.out_path.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)

    return 1 if any(f.severity == Severity.CRITICAL for f in findings) else 0
