package dynscan

import "regexp"

type SecretPattern struct {
	Name string
	Re   *regexp.Regexp
}

func DefaultSecretPatterns() []SecretPattern {
	return []SecretPattern{
		{Name: "GitHub Token (classic)", Re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,255}`)},
		{Name: "GitHub Token (fine-grained)", Re: regexp.MustCompile(`github_pat_[A-Za-z0-9_]{80,255}`)},
		{Name: "GitLab Personal Access Token", Re: regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`)},
		{Name: "AWS Access Key", Re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{Name: "AWS Secret Key", Re: regexp.MustCompile(`(?i)aws(.{0,20})?[\"'][0-9a-zA-Z/+]{40}[\"']`)},
		{Name: "Slack Token", Re: regexp.MustCompile(`xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,32}`)},
		{Name: "Google API Key", Re: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
		{Name: "Private Key", Re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
		{
			Name: "JWT (possible)",
			Re:   regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}`),
		},
		{
			Name: "Generic Secret",
			Re: regexp.MustCompile(
				`(?i)(secret|password|api[_-]?key|token|credential)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?`,
			),
		},
	}
}
