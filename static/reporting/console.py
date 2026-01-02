from __future__ import annotations

from collections import defaultdict

from static.models import Finding, Severity


_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
_SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}


def render_console_report(findings: list[Finding]) -> str:
    if not findings:
        return "✅ Уязвимостей не обнаружено!"

    by_severity: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_severity[finding.severity.value].append(finding)

    lines: list[str] = []
    lines.append("\n" + "=" * 80)
    lines.append("🔍 PipeSec Static - Отчёт")
    lines.append("=" * 80 + "\n")

    lines.append(f"📊 Всего найдено проблем: {len(findings)}")
    for sev in _SEVERITY_ORDER:
        cnt = len(by_severity.get(sev.value, []))
        if cnt:
            lines.append(f"   {_SEVERITY_EMOJI[sev.value]} {sev.value}: {cnt}")

    for sev in _SEVERITY_ORDER:
        items = by_severity.get(sev.value, [])
        if not items:
            continue

        lines.append("\n" + "─" * 80)
        lines.append(f"[{sev.value}] Проблемы")
        lines.append("─" * 80)

        for idx, f in enumerate(items, 1):
            lines.append(f"\n#{idx} {f.category}")
            lines.append(f"   📍 Местоположение: {f.location}")
            lines.append(f"   📝 Описание: {f.description}")
            if f.evidence:
                lines.append(f"   🔎 Доказательство: {f.evidence}")
            lines.append(f"   💡 Рекомендация: {f.recommendation}")

    lines.append("\n" + "=" * 80 + "\n")
    return "\n".join(lines)
