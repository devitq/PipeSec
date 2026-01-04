#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TS="$(date -u +"%Y%m%dT%H%M%SZ")"
OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
OUTDIR="$ROOT_DIR/test_runs/${TS}_${OS_NAME}"
mkdir -p "$OUTDIR"

VENV_DIR="$ROOT_DIR/.venv"
PY_BIN="$VENV_DIR/bin/python"
DYNAMIC_BIN="$ROOT_DIR/dynamic/bin/pipesec-dynamic"
PATTERNS_FILE="$ROOT_DIR/data/secret_patterns.json"

SAFE_YML="$ROOT_DIR/samples/safe-all.yml"
VULN_YML="$ROOT_DIR/samples/vulnerable-all.yml"

meta() {
  {
    echo "timestamp_utc=$TS"
    echo "uname=$(uname -a)"
    echo "os_name=$OS_NAME"
    echo "whoami=$(whoami)"
    echo "pwd=$ROOT_DIR"
    echo "python_bin=$PY_BIN"
    echo "dynamic_bin=$DYNAMIC_BIN"
    echo "patterns=$PATTERNS_FILE"
    if [[ "$OS_NAME" == "linux" ]]; then
      echo "egress_supported=true"
    else
      echo "egress_supported=false"
    fi
  } | tee "$OUTDIR/meta.txt"
}

run_cmd() {
  local name="$1"; shift
  local cmd_str="$*"

  echo "=== $name ===" | tee "$OUTDIR/${name}.header.txt"
  echo "$cmd_str" | tee "$OUTDIR/${name}.cmd.txt"

  # capture both streams + exit code
  set +e
  bash -lc "$cmd_str" >"$OUTDIR/${name}.stdout.txt" 2>"$OUTDIR/${name}.stderr.txt"
  local ec=$?
  set -e
  echo "$ec" >"$OUTDIR/${name}.exitcode.txt"
}

ensure_python() {
  if [[ ! -x "$PY_BIN" ]]; then
    python3 -m venv "$VENV_DIR"
  fi

  # Ensure PyYAML exists for workflow parsing.
  set +e
  "$PY_BIN" -c 'import yaml' >/dev/null 2>&1
  local has_yaml=$?
  set -e
  if [[ $has_yaml -ne 0 ]]; then
    "$PY_BIN" -m pip install --upgrade pip >/dev/null
    "$PY_BIN" -m pip install "pyyaml>=6.0.3" >/dev/null
  fi
}

ensure_dynamic_bin() {
  if [[ -x "$DYNAMIC_BIN" ]]; then
    return 0
  fi
  make -C "$ROOT_DIR/dynamic" build-dynamic >/dev/null
  if [[ ! -x "$DYNAMIC_BIN" ]]; then
    echo "dynamic binary not found after build: $DYNAMIC_BIN" >&2
    exit 1
  fi
}

make_test_logs() {
  # log file for static log scanning
  # Use values that match regex patterns in data/secret_patterns.json.
  local sendgrid="SG.$(printf 'A%.0s' {1..22}).$(printf 'B%.0s' {1..43})"
  cat >"$OUTDIR/leaky-build.log" <<'LOG'
Starting build...
AWS_ACCESS_KEY_ID=AKIA1234567890ABCD12
STRIPE_KEY=sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Done.
LOG

  # Append SendGrid in correct format (kept out of the heredoc for portability).
  echo "SENDGRID=${sendgrid}" >>"$OUTDIR/leaky-build.log"
  echo "Done." >>"$OUTDIR/leaky-build.log"
}

ensure_python
ensure_dynamic_bin
meta
make_test_logs

# -------------------------
# Flow 1: Static analyzer
# -------------------------
run_cmd "sast_safe_yaml" \
  "\"$PY_BIN\" -m static --patterns \"$PATTERNS_FILE\" --format json \"$SAFE_YML\""

run_cmd "sast_vuln_yaml" \
  "\"$PY_BIN\" -m static --patterns \"$PATTERNS_FILE\" --format json \"$VULN_YML\""

run_cmd "sast_vuln_yaml_log" \
  "\"$PY_BIN\" -m static --patterns \"$PATTERNS_FILE\" --format json \"$VULN_YML\" --log \"$OUTDIR/leaky-build.log\""

run_cmd "sast_list_rules" \
  "\"$PY_BIN\" -m static --list-rules"

# Show rule toggling works: run only one rule.
run_cmd "sast_enable_single_rule" \
  "\"$PY_BIN\" -m static --patterns \"$PATTERNS_FILE\" --format json --enable-rule dangerous_triggers \"$VULN_YML\""

# -------------------------
# Flow 2: Dynamic analyzer - secret leaks to stdout/stderr
# -------------------------
run_cmd "dast_run_secret_leak" \
  "\"$DYNAMIC_BIN\" -mode run -source runtime --patterns \"$PATTERNS_FILE\" --format json -- \"$PY_BIN\" -c 'import sys; \
print(\"leak AWS AKIA1234567890ABCD12\"); \
print(\"leak STRIPE sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"); \
print(\"stderr SENDGRID SG.\" + (\"A\"*22) + \".\" + (\"B\"*43), file=sys.stderr);'"

# -------------------------
# Flow 3: Dynamic analyzer - network egress
# -------------------------
# Linux-only. Avoid external network: connect to a local TCP server.
if [[ "$OS_NAME" == "linux" ]]; then
  run_cmd "dast_run_network_egress" \
    "\"$DYNAMIC_BIN\" -mode run -source egress-local --patterns \"$PATTERNS_FILE\" --format json -- \"$PY_BIN\" -c 'import socket,threading,time; \
srv=socket.socket(); srv.bind((\"127.0.0.1\",0)); port=srv.getsockname()[1]; srv.listen(1); \
def accept_once(): c,_=srv.accept(); time.sleep(1); c.close(); srv.close(); \
threading.Thread(target=accept_once,daemon=True).start(); \
cli=socket.create_connection((\"127.0.0.1\",port),timeout=5); time.sleep(2); cli.close(); time.sleep(1);'"
else
  echo "SKIP: dast_run_network_egress (egress_supported=false)" | tee "$OUTDIR/dast_run_network_egress.skip.txt"
fi

run_cmd "dast_scan_log_file" \
  "\"$DYNAMIC_BIN\" -mode scan -source leaky-build.log --patterns \"$PATTERNS_FILE\" --format json --log \"$OUTDIR/leaky-build.log\""

echo "Artifacts saved to: $OUTDIR"
ls -la "$OUTDIR" | tee "$OUTDIR/ls.txt"
