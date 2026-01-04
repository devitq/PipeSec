from __future__ import annotations

from collections.abc import Iterator
import re
from typing import Any


def iter_jobs(workflow: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return
    for job_name, job_config in jobs.items():
        if isinstance(job_name, str) and isinstance(job_config, dict):
            yield job_name, job_config


def iter_steps(job_config: dict[str, Any]) -> Iterator[tuple[int, dict[str, Any]]]:
    steps = job_config.get("steps", [])
    if not isinstance(steps, list):
        return
    for idx, step in enumerate(steps):
        if isinstance(step, dict):
            yield idx, step


def get_step_name(step: dict[str, Any], idx: int) -> str:
    name = step.get("name")
    return name if isinstance(name, str) and name.strip() else f"step-{idx}"


def get_run(step: dict[str, Any]) -> str | None:
    v = step.get("run")
    return v if isinstance(v, str) else None


def get_uses(step: dict[str, Any]) -> str | None:
    v = step.get("uses")
    return v if isinstance(v, str) else None


def get_env(obj: dict[str, Any]) -> dict[str, str]:
    env = obj.get("env", {})
    if not isinstance(env, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in env.items():
        if isinstance(k, str) and isinstance(v, str):
            out[k] = v
    return out


def is_expression(value: str) -> bool:
    return "${{" in value


def contains_secret_context(value: str) -> bool:
    v = value.lower()
    return "secrets." in v or "github.token" in v


def run_has_local_exec(run: str) -> bool:
    return bool(re.search(r"(?m)^\s*(chmod\s+\+x\s+\./|\./)", run))
