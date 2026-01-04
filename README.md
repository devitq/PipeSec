# PipeSec

## Описание

PipeSec — гибридный инструмент для статического и динамического анализа CI/CD пайплайнов на предмет утечек секретов.

## Требования

- Python 3.11+
- Golang 1.25+

## Установка

### Статический модуль

```bash
# Создание виртуального окружения и активация
python3 -m venv venv
source venv/bin/activate

# Установка как пакета (появится команда pipesec)
pip install "git+https://github.com/yetanotherparticipant/PipeSec.git#subdirectory=static"
```

### Динамический модуль

```
# собраный бинарник появится в $(go env GOPATH)/bin/pipesec-dynamic
# не забудьте добавить $(go env GOPATH)/bin в PATH
GOPROXY=direct go install github.com/yetanotherparticipant/PipeSec/dynamic/cmd/pipesec-dynamic@latest
```

## Использование

### Базовое использование

#### Статический модуль

**Статический анализ:**

```bash
# через CLI entrypoint:
pipesec <путь к workflow.yml>

# или запуск как модуль:
python -m pipesec <путь к workflow.yml>
```

**Гибридный анализ:**

```bash
pipesec <путь к workflow.yml> --log <путь к логу>
```

**Форматы отчёта:**

```bash
# JSON
pipesec samples/vulnerable-all.yml --format json

# вывод в файл
pipesec samples/vulnerable-all.yml --format json --out out.json
```

**Паттерны секретов (единый источник):**

По умолчанию инструмент использует [data/secret_patterns.json](data/secret_patterns.json), если файл существует.

```bash
# явное указание файла паттернов (по дефолту берётся либо data/secret_patterns.json либо ../data/secret_patterns.json)
pipesec samples/vulnerable-all.yml --patterns data/secret_patterns.json
```

**Справка**

```bash
pipesec --help
```

```bash
usage: pipesec [-h] [--log LOG_PATH] [--format {console,json}]
               [--out OUT_PATH] [--patterns PATTERNS_PATH] [--list-rules]
               [--enable-rule ENABLE_RULES] [--disable-rule DISABLE_RULES]
               [workflow]

PipeSec: гибридный анализатор безопасности CI/CD workflow

positional arguments:
  workflow              Путь к workflow YAML (GitHub Actions)

options:
  -h, --help            show this help message and exit
  --log LOG_PATH        Путь к логу выполнения (опционально)
  --format {console,json}
                        Формат отчёта
  --out OUT_PATH        Записать отчёт в файл вместо stdout
  --patterns PATTERNS_PATH
                        Путь к JSON с regex-паттернами секретов (опционально).
                        По умолчанию используется data/secret_patterns.json,
                        если он существует.
  --list-rules          Вывести список доступных правил статического анализа и
                        выйти
  --enable-rule ENABLE_RULES
                        Включить только указанные правила статического анализа
                        (можно повторять). Значение: rule id (например,
                        dangerous_triggers) или полное имя класса (например, s
                        tatic.rules.dangerous_triggers.DangerousTriggersRule).
  --disable-rule DISABLE_RULES
                        Отключить указанные правила статического анализа
                        (можно повторять). Значение: rule id или полное имя
                        класса.
```

#### Динамический модуль

Динамический модуль поддерживает два режима:

- `scan` — сканирование stdin/файла лога на утечки секретов;
- `run` — запуск команды и потоковый анализ её stdout/stderr; дополнительно (best-effort) фиксируется сетевой egress на Linux.

**Сканирование логов (scan):**

```bash
# сканирование файла лога
pipesec-dynamic -mode scan --log ./samples/build-all.log -source build-all.log

# сканирование stdin
cat ./samples/build-all.log | pipesec-dynamic -mode scan -source stdin
```

**Запуск стороннего кода (run):**

```bash
# запуск команды и анализ stdout/stderr
pipesec-dynamic -mode run -source runtime -- bash -lc 'echo "AKIAIOSFODNN7EXAMPLE"'

# запуск команды с анализом egress трафика
pipesec-dynamic -mode run -source runtime -- curl https://example.com
```

**Форматы отчёта:**

```bash
# JSON
pipesec-dynamic -mode scan --log ./samples/build-all.log -source build-all.log -format json
```

**Паттерны секретов (единый источник):**

По умолчанию модуль пытается автоматически загрузить паттерны секретов из `data/secret_patterns.json`.
Можно явно указать файл через `--patterns`.

```bash
pipesec-dynamic -mode scan --patterns ./data/secret_patterns.json --log ./samples/build-all.log -source build-all.log
```

**Справка:**

```bash
pipesec-dynamic -h
```

```bash
Usage of pipesec-dynamic:
  -format string
        console|json (default "console")
  -log string
        path to log file (optional; default stdin)
  -mode string
        scan|run (default "scan")
  -patterns string
        path to pipesec secret_patterns.json (optional)
  -source string
        source label for findings (default "stdin")
  -timeout duration
        timeout for run mode (0 = none)
```

**Замечание про egress:**

- finding `Network Egress (Observed)` появляется только в Linux (используется `/proc/net/*`).
- на macOS/Windows модуль работает, но egress-наблюдение будет недоступно.

### Примеры

**Сканирование уязвимого workflow:**

```bash
pipesec samples/vulnerable-all.yml
```

Ожидаемый результат: Обнаружение 25 проблем различной критичности.

**Сканирование безопасного workflow:**

```bash
pipesec samples/safe-all.yml
```

Ожидаемый результат: Уязвимостей не обнаружено.

**Динамический анализ (scan) лога с утечками:**

```bash
pipesec-dynamic -mode scan -format json --log ./samples/build-all.log -source build-all.log
```

Ожидаемый результат: CRITICAL-находки по секретам из лога, exit code = 1.

**Динамический анализ (run) утечки в stdout:**

```bash
pipesec-dynamic -mode run -format json -source runtime -- bash -lc 'echo "AKIAIOSFODNN7EXAMPLE"'
```

Ожидаемый результат: CRITICAL-находка по утечке, exit code = 1.
