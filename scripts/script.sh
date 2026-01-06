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
PIP_BIN="$VENV_DIR/bin/pip"

DYNAMIC_BIN="$ROOT_DIR/dynamic/bin/pipesec-dynamic"
PATTERNS_FILE="$ROOT_DIR/data/secret_patterns.json"

SAFE_YML="$ROOT_DIR/samples/safe-all.yml"
VULN_YML="$ROOT_DIR/samples/vulnerable-all.yml"

log() { echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*"; }

die() {
  echo "ERROR: $*" >&2
  exit 1
}

meta() {
  {
    echo "timestamp_utc=$TS"
    echo "uname=$(uname -a)"
    echo "os_name=$OS_NAME"
    echo "whoami=$(whoami)"
    echo "pwd=$ROOT_DIR"
    echo "python_bin=$PY_BIN"
    echo "pip_bin=$PIP_BIN"
    echo "dynamic_bin=$DYNAMIC_BIN"
    echo "patterns=$PATTERNS_FILE"
    if [[ "$OS_NAME" == "linux" ]]; then
      echo "egress_supported=true"
    else
      echo "egress_supported=false"
    fi
    if command -v go >/dev/null 2>&1; then
      echo "go_version=$(go version)"
    else
      echo "go_version=missing"
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
    command -v python3 >/dev/null 2>&1 || die "python3 not found in PATH (required). Install Python 3.11+."
    python3 -m venv "$VENV_DIR"
  fi

  # Make sure pip/setuptools/wheel are recent enough for local editable installs.
  "$PY_BIN" -m pip install --upgrade pip setuptools wheel >/dev/null

  # Install the static module as a local package (editable) so `python -m pipesec` works
  # and runtime deps (PyYAML) are present.
  "$PY_BIN" -m pip install -e "$ROOT_DIR/static" >/dev/null
}

ensure_dynamic_bin() {
  if [[ -x "$DYNAMIC_BIN" ]]; then
    return 0
  fi

  command -v go >/dev/null 2>&1 || die "go not found in PATH (required for dynamic module). Install Go 1.25+."
  command -v make >/dev/null 2>&1 || die "make not found in PATH (required to build dynamic module)."

  make -C "$ROOT_DIR/dynamic" build-dynamic >/dev/null

  if [[ ! -x "$DYNAMIC_BIN" ]]; then
    die "dynamic binary not found after build: $DYNAMIC_BIN"
  fi
}

make_test_logs() {
  # log file for static/dynamic log scanning
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
  "\"$PY_BIN\" -m pipesec --patterns \"$PATTERNS_FILE\" --format json \"$SAFE_YML\""

run_cmd "sast_vuln_yaml" \
  "\"$PY_BIN\" -m pipesec --patterns \"$PATTERNS_FILE\" --format json \"$VULN_YML\""

run_cmd "sast_vuln_yaml_log" \
  "\"$PY_BIN\" -m pipesec --patterns \"$PATTERNS_FILE\" --format json \"$VULN_YML\" --log \"$OUTDIR/leaky-build.log\""

run_cmd "sast_list_rules" \
  "\"$PY_BIN\" -m pipesec --list-rules"

# Show rule toggling works: run only one rule.
run_cmd "sast_enable_single_rule" \
  "\"$PY_BIN\" -m pipesec --patterns \"$PATTERNS_FILE\" --format json --enable-rule dangerous_triggers \"$VULN_YML\""

# -------------------------
# Flow 2: Dynamic analyzer - secret leaks to stdout/stderr
# -------------------------
run_cmd "dast_run_secret_leak" \
  "\"$DYNAMIC_BIN\" -mode run -source runtime --patterns \"$PATTERNS_FILE\" -format json -- \"$PY_BIN\" -c 'import sys; \
print(\"leak AWS AKIA1234567890ABCD12\"); \
print(\"leak STRIPE sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"); \
print(\"stderr SENDGRID SG.\" + (\"A\"*22) + \".\" + (\"B\"*43), file=sys.stderr);'"

# -------------------------
# Flow 3: Dynamic analyzer - network egress
# -------------------------
# Linux-only. Avoid external network: connect to a local TCP server.
if [[ "$OS_NAME" == "linux" ]]; then
  run_cmd "dast_run_network_egress" \
    "\"$DYNAMIC_BIN\" -mode run -source egress-local --patterns \"$PATTERNS_FILE\" -format json -- \"$PY_BIN\" -c 'import socket,threading,time; \
srv=socket.socket(); srv.bind((\"127.0.0.1\",0)); port=srv.getsockname()[1]; srv.listen(1); \
def accept_once(): c,_=srv.accept(); time.sleep(1); c.close(); srv.close(); \
threading.Thread(target=accept_once,daemon=True).start(); \
cli=socket.create_connection((\"127.0.0.1\",port),timeout=5); time.sleep(2); cli.close(); time.sleep(1);'"
else
  echo "SKIP: dast_run_network_egress (egress_supported=false)" | tee "$OUTDIR/dast_run_network_egress.skip.txt"
fi

run_cmd "dast_scan_log_file" \
  "\"$DYNAMIC_BIN\" -mode scan -source leaky-build.log --patterns \"$PATTERNS_FILE\" -format json --log \"$OUTDIR/leaky-build.log\""

echo "Artifacts saved to: $OUTDIR"
ls -la "$OUTDIR" | tee "$OUTDIR/ls.txt"
