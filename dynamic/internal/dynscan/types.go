package dynscan

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type Finding struct {
	Severity       Severity `json:"severity"`
	Category       string   `json:"category"`
	Description    string   `json:"description"`
	Location       string   `json:"location"`
	Recommendation string   `json:"recommendation"`
	Evidence       string   `json:"evidence,omitempty"`
}
