from __future__ import annotations

import importlib
import pkgutil

from static.rules.base import WorkflowRule


_RULE_TYPES: list[type[WorkflowRule]] = []
_RULE_TYPE_NAMES: set[str] = set()
_DISCOVERED: bool = False


def register_workflow_rule(rule_cls: type[WorkflowRule]) -> type[WorkflowRule]:
    name = f"{rule_cls.__module__}.{rule_cls.__name__}"
    if name not in _RULE_TYPE_NAMES:
        _RULE_TYPE_NAMES.add(name)
        _RULE_TYPES.append(rule_cls)
    return rule_cls


def _discover_rule_modules() -> None:
    global _DISCOVERED
    if _DISCOVERED:
        return

    pkg = importlib.import_module(__name__.rsplit(".", 1)[0])  # static.rules
    pkg_path = getattr(pkg, "__path__", None)
    if pkg_path is None:
        _DISCOVERED = True
        return

    skip = {"__init__", "base", "registry", "utils"}
    for m in pkgutil.iter_modules(pkg_path):
        if m.name in skip:
            continue
        importlib.import_module(f"{pkg.__name__}.{m.name}")

    _DISCOVERED = True


def default_workflow_rules() -> list[WorkflowRule]:
    _discover_rule_modules()
    return [cls() for cls in _RULE_TYPES]
