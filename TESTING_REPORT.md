# Отчёт о тестировании

Источник данных: артефакты прогона `scripts/script.sh` на стенде.

## 1. Цель тестирования
Проверить работоспособность ключевых возможностей PipeSec по нескольким флоу:

1) **Статический анализ (SAST)**:
- анализ GitHub Actions YAML (безопасный / небезопасный);
- анализ утечек секретов в логах (как часть статической проверки через флаг `--log`).

2) **Динамический анализ (DAST)**:
- запуск программы, которая выводит секреты в логи (`stdout/stderr`);
- запуск программы, которая инициирует исходящие сетевые соединения (egress).

Во всех запусках используется файл паттернов через флаг `--patterns data/secret_patterns.json`.

## 2. Тестовая среда (meta.txt)
- Timestamp (UTC): `20260104T115842Z`
- OS: `Linux debian 6.17.8-orbstack-00308-g8f9c941121b1 #1 SMP PREEMPT Thu Nov 20 09:34:02 UTC 2025 aarch64 GNU/Linux`
- User: `admin`
- Workdir: `/home/admin`
- Static analyzer: `/home/admin/static/.venv/bin/pipesec`
- Dynamic analyzer: `/home/admin/pipesec-dynamic`
- Patterns: `/home/admin/data/secret_patterns.json`

## 3. Артефакты и формат результатов
Для каждого кейса сохранены:
- `<case>.cmd.txt` — команда,
- `<case>.stdout.txt` — JSON-вывод,
- `<case>.stderr.txt` — stderr,
- `<case>.exitcode.txt` — код завершения.

## 4. Тестовые данные
### 4.1 YAML-файлы
- Safe workflow: `/home/admin/samples/safe-all.yml`
- Vulnerable workflow: `/home/admin/samples/vulnerable-all.yml`

### 4.2 Лог для проверки утечек
Файл: `test_runs/20260104T115842Z_linux/leaky-build.log`

Содержимое (фрагмент):
- `AWS_ACCESS_KEY_ID=AKIA1234567890ABCD12`
- `STRIPE_KEY=sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
- `SENDGRID=SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

## 5. Результаты тестирования по флоу

### 5.1 SAST: анализ YAML (safe)
Команда (из `sast_safe_yaml.cmd.txt`):
- `"/home/admin/static/.venv/bin/pipesec" --patterns "/home/admin/data/secret_patterns.json" --format json "/home/admin/samples/safe-all.yml"`

Результат (из `sast_safe_yaml.stdout.txt`):
- `count: 0`
- `findings: []`
- `countsBySeverity: CRITICAL=0, HIGH=0, MEDIUM=0, LOW=0`

Exit code (из `sast_safe_yaml.exitcode.txt`): `0`

**Итог:** корректно, безопасный YAML не даёт срабатываний.

---

### 5.2 SAST: анализ YAML (vulnerable)
Команда (из `sast_vuln_yaml.cmd.txt`):
- `"/home/admin/static/.venv/bin/pipesec" --patterns "/home/admin/data/secret_patterns.json" --format json "/home/admin/samples/vulnerable-all.yml"`

Результат (из `sast_vuln_yaml.stdout.txt`):
- `count: 25`
- `countsBySeverity: CRITICAL=6, HIGH=10, MEDIUM=9, LOW=0`

Exit code (из `sast_vuln_yaml.exitcode.txt`): `1`

**Итог:** корректно, небезопасный YAML детектируется (25 findings).

---

### 5.3 SAST: анализ логов (флоу “YAML + log” через `--log`)
Команда (из `sast_vuln_yaml_log.cmd.txt`):
- `"/home/admin/static/.venv/bin/pipesec" --patterns "/home/admin/data/secret_patterns.json" --format json "/home/admin/samples/vulnerable-all.yml" --log "/home/admin/test_runs/20260104T115842Z_linux/leaky-build.log"`

Результат (из `sast_vuln_yaml_log.stdout.txt`):
- `count: 27`
- `countsBySeverity: CRITICAL=8, HIGH=10, MEDIUM=9, LOW=0`
- Дополнительно к findings из YAML обнаружены секреты в лог-файле:
  - `Secret in Logs` (CRITICAL) — `AWS Access Key`, location: `.../leaky-build.log:line 2`, evidence: `AKIA1234567890ABCD12`
  - `Secret in Logs` (CRITICAL) — `Stripe Secret Key`, location: `.../leaky-build.log:line 3`, evidence: `sk_live_51Hxxxxxxxxx...`

Exit code (из `sast_vuln_yaml_log.exitcode.txt`): `1`

**Итог:** статический флоу “YAML + лог” работает; утечки в логе детектируются (AWS/Stripe).

**Наблюдение:** в `leaky-build.log` присутствует строка `SENDGRID=...`, но в результатах SAST log finding по SendGrid нет.

---

### 5.4 DAST: динамический запуск программы, выводящей секреты в логи
Команда (из `dast_run_secret_leak.cmd.txt`):
- `"/home/admin/pipesec-dynamic" -mode run --patterns "/home/admin/data/secret_patterns.json" --format json -- python3 -c 'import sys; print("leak AWS AKIA1234567890ABCD12"); print("leak STRIPE sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"); print("stderr SENDGRID SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", file=sys.stderr);'`

Результат (из `dast_run_secret_leak.stdout.txt`):
- `count: 2`
- `Secret in Logs` (CRITICAL):
  - `AWS Access Key`, location: `stdin:stdout:line 1`, evidence: `AKIA1234567890ABCD12`
  - `Stripe Secret Key`, location: `stdin:stdout:line 2`, evidence: `sk_live_51Hxxxxxxxxx...`

Exit code (из `dast_run_secret_leak.exitcode.txt`): `1`

**Итог:** динамический детект секретов в `stdout` подтверждён.

**Наблюдение:** команда печатает SendGrid-подобное значение в `stderr`, но finding по нему отсутствует (findings=2: AWS/Stripe). Возможные причины: отсутствие/строгость паттерна, либо неполное покрытие stderr в режиме `run`.

---

### 5.5 DAST: динамический запуск программы с egress (сторонние ресурсы)
Команда (из `dast_run_network_egress.cmd.txt`):
- `"/home/admin/pipesec-dynamic" -mode run --patterns "/home/admin/data/secret_patterns.json" --format json -- python3 -c 'import socket,time; s=socket.create_connection(("example.com",443),timeout=5); time.sleep(5); s.close()'`

Результат (из `dast_run_network_egress.stdout.txt`):
- `count: 1`
- `Network Egress (Observed)` (MEDIUM)
  - evidence: `104.18.26.120:443`

Exit code (из `dast_run_network_egress.exitcode.txt`): `0`

**Итог:** обнаружение исходящего сетевого соединения во время выполнения команды подтверждено.

---

### 5.6 DAST: scan файла лога
Команда (из `dast_scan_log_file.cmd.txt`):
- `"/home/admin/pipesec-dynamic" -mode scan --patterns "/home/admin/data/secret_patterns.json" --format json --log "/home/admin/test_runs/20260104T115842Z_linux/leaky-build.log"`

Результат (из `dast_scan_log_file.stdout.txt`):
- `count: 2`
- `Secret in Logs` (CRITICAL):
  - `AWS Access Key`, location: `stdin:line 2`, evidence: `AKIA1234567890ABCD12`
  - `Stripe Secret Key`, location: `stdin:line 3`, evidence: `sk_live_51Hxxxxxxxxx...`

Exit code (из `dast_scan_log_file.exitcode.txt`): `1`

**Итог:** динамический анализ лог-файла детектирует AWS/Stripe.

**Наблюдение:** строка `SENDGRID=...` в `leaky-build.log` не обнаружена (аналогично SAST log finding).

## 6. Сводка (pass/fail по флоу)
- SAST safe YAML: **PASS** (0 findings, exit 0)
- SAST vulnerable YAML: **PASS** (25 findings, exit 1)
- SAST log (через `--log`): **PASS** (добавились findings по log: AWS/Stripe; total 27)
- DAST secret leak (run): **PASS** (2 findings, exit 1), но **не детектирован SendGrid из stderr**
- DAST network egress (run): **PASS** (1 finding, exit 0)
- DAST log scan (scan): **PASS** (2 findings, exit 1)

## 7. Вывод и замечания
1) Базовая функциональность подтверждена: SAST по workflow, DAST по утечкам в stdout и обнаружение egress на Linux.
