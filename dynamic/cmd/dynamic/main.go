package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"pipesec-dyn/internal/dynscan"
)

func main() {
	mode := flag.String("mode", "scan", "scan|run")
	format := flag.String("format", "console", "console|json")
	source := flag.String("source", "stdin", "source label for findings")
	logFile := flag.String("log", "", "path to log file (optional; default stdin)")
	timeout := flag.Duration("timeout", 0, "timeout for run mode (0 = none)")
	patternsPath := flag.String("patterns", "", "path to pipesec secret_patterns.json (optional)")
	flag.Parse()

	patterns := dynscan.DefaultSecretPatterns()
	if *patternsPath != "" {
		if loaded, err := dynscan.LoadSecretPatternsFromFile(*patternsPath); err == nil {
			patterns = loaded
		} else {
			fmt.Fprintln(os.Stderr, "warning: failed to load patterns:", err)
		}
	} else {
		if loaded, usedPath, err := dynscan.LoadSecretPatternsAuto(); err == nil {
			_ = usedPath
			patterns = loaded
		}
	}

	var findings []dynscan.Finding
	switch *mode {
	case "scan":
		var r io.Reader = os.Stdin
		if *logFile != "" {
			f, err := os.Open(*logFile)
			if err != nil {
				exitWith(findingsWithIOError(*logFile, err), *format, 1)
			}
			defer f.Close()
			r = f
		}
		findings = dynscan.ScanLogStream(r, *source, patterns)
		exitWith(findings, *format, exitCode(findings))
	case "run":
		if flag.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "pipesec-dynamic -mode run -- <command> [args...]")
			os.Exit(2)
		}
		cmdName := flag.Arg(0)
		cmdArgs := flag.Args()[1:]

		ctx, cancel := contextOrBackground(*timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, cmdName, cmdArgs...)
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		before := dynscan.LinuxRemoteEndpoints()
		observed := map[string]struct{}{}

		if err := cmd.Start(); err != nil {
			exitWith(findingsWithExecError(cmdName, err), *format, 1)
		}

		stopEgress := make(chan struct{})
		egressDone := make(chan struct{})
		go func() {
			defer close(egressDone)
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					for ep := range dynscan.LinuxRemoteEndpoints() {
						observed[ep] = struct{}{}
					}
				case <-stopEgress:
					return
				}
			}
		}()

		outCh := make(chan []dynscan.Finding, 2)
		go func() { outCh <- dynscan.ScanLogStream(stdout, *source+":stdout", patterns) }()
		go func() { outCh <- dynscan.ScanLogStream(stderr, *source+":stderr", patterns) }()

		f1 := <-outCh
		f2 := <-outCh
		findings = append(findings, f1...)
		findings = append(findings, f2...)

		err := cmd.Wait()
		close(stopEgress)
		<-egressDone

		for ep := range dynscan.LinuxRemoteEndpoints() {
			observed[ep] = struct{}{}
		}

		for ep := range observed {
			if _, ok := before[ep]; ok {
				continue
			}
			findings = append(findings, dynscan.Finding{
				Severity:       dynscan.SeverityMedium,
				Category:       "Network Egress (Observed)",
				Description:    "Обнаружено новое исходящее сетевое соединение во время выполнения команды.",
				Location:       *source,
				Recommendation: "Проверьте необходимость сетевого доступа; для CI лучше ограничивать egress и/или фиксировать allowlist доменов.",
				Evidence:       ep,
			})
		}

		if err != nil {
			findings = append(findings, dynscan.Finding{
				Severity:       dynscan.SeverityLow,
				Category:       "Command Exit",
				Description:    "Команда завершилась с ошибкой.",
				Location:       cmdName,
				Recommendation: "Проверьте логи выполнения команды.",
				Evidence:       err.Error(),
			})
		}

		exitWith(findings, *format, exitCode(findings))
	default:
		fmt.Fprintln(os.Stderr, "unknown -mode:", *mode)
		os.Exit(2)
	}
}

func contextOrBackground(timeout time.Duration) (context.Context, func()) {
	if timeout <= 0 {
		return context.Background(), func() {}
	}
	return context.WithTimeout(context.Background(), timeout)
}

func exitCode(findings []dynscan.Finding) int {
	for _, f := range findings {
		if f.Severity == dynscan.SeverityCritical {
			return 1
		}
	}
	return 0
}

func exitWith(findings []dynscan.Finding, format string, code int) {
	if format == "json" {
		b, _ := json.MarshalIndent(map[string]any{
			"findings": findings,
			"count":    len(findings),
		}, "", "  ")
		fmt.Println(string(b))
	} else {
		if len(findings) == 0 {
			fmt.Println("✅ Уязвимостей не обнаружено!")
			os.Exit(code)
		}
		fmt.Println("\n" + repeat("=", 80))
		fmt.Println("🔍 PipeSec Dynamic - Отчёт")
		fmt.Println(repeat("=", 80))
		fmt.Println("\n📊 Всего найдено проблем:", len(findings))
		for i, f := range findings {
			fmt.Printf("\n#%d [%s] %s\n", i+1, f.Severity, f.Category)
			fmt.Println("   📍 Местоположение:", f.Location)
			fmt.Println("   📝 Описание:", f.Description)
			if f.Evidence != "" {
				fmt.Println("   🔎 Доказательство:", f.Evidence)
			}
			fmt.Println("   💡 Рекомендация:", f.Recommendation)
		}
		fmt.Println("\n" + repeat("=", 80))
	}
	os.Exit(code)
}

func findingsWithIOError(path string, err error) []dynscan.Finding {
	return []dynscan.Finding{{
		Severity:       dynscan.SeverityHigh,
		Category:       "IO Error",
		Description:    "Не удалось открыть файл лога.",
		Location:       path,
		Recommendation: "Проверьте путь и права доступа.",
		Evidence:       err.Error(),
	}}
}

func findingsWithExecError(cmd string, err error) []dynscan.Finding {
	return []dynscan.Finding{{
		Severity:       dynscan.SeverityHigh,
		Category:       "Exec Error",
		Description:    "Не удалось запустить команду.",
		Location:       cmd,
		Recommendation: "Проверьте имя команды и окружение.",
		Evidence:       err.Error(),
	}}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
