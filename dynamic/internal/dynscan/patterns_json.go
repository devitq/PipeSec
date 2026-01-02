package dynscan

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
)

type secretPatternsFile struct {
	Version  int `json:"version"`
	Patterns []struct {
		Name  string `json:"name"`
		Regex string `json:"regex"`
	} `json:"patterns"`
}

func LoadSecretPatternsFromFile(path string) ([]SecretPattern, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f secretPatternsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}

	var out []SecretPattern
	for _, p := range f.Patterns {
		if p.Name == "" || p.Regex == "" {
			continue
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}
		out = append(out, SecretPattern{Name: p.Name, Re: re})
	}
	if len(out) == 0 {
		return nil, errors.New("no valid patterns found")
	}
	return out, nil
}

func LoadSecretPatternsAuto() ([]SecretPattern, string, error) {
	candidates := candidatePatternsFiles()
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err != nil {
			continue
		}
		p, err := LoadSecretPatternsFromFile(c)
		if err != nil {
			continue
		}
		return p, c, nil
	}
	return nil, "", errors.New("patterns file not found")
}

func candidatePatternsFiles() []string {
	var out []string

	out = append(out,
		filepath.Join("data", "secret_patterns.json"),
		filepath.Join("..", "data", "secret_patterns.json"),
	)

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		out = append(out,
			filepath.Join(exeDir, "data", "secret_patterns.json"),
			filepath.Join(exeDir, "..", "data", "secret_patterns.json"),
		)
	}

	return out
}
