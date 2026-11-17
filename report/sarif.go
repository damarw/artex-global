package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// SARIF 2.1.0 export for findings.
//
// Why SARIF: it is what auditors and CI security dashboards import. The Markdown/CSV exports
// stay human-readable; SARIF is the machine-readable hand-over format, so a finding produced
// here can be tracked in an external system without manual retyping.
//
// Mapping decisions:
//   - severity critical|high -> level "error", medium -> "warning", low/unknown -> "note";
//   - one rule per vulnerability class, results reference that rule;
//   - no `locations` are emitted because a finding references internal asset ids, not URLs —
//     embedding a fake URI would be worse than omitting it. The asset ids travel in
//     properties.assetIds instead.

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool     `json:"tool"`
	Invocations []sarifInvoke `json:"invocations"`
	Results     []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name,omitempty"`
	ShortDescription     sarifText        `json:"shortDescription"`
	DefaultConfiguration sarifRuleDefault `json:"defaultConfiguration"`
	Properties           map[string]any   `json:"properties,omitempty"`
}

type sarifRuleDefault struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifInvoke struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	EndTimeUTC          string `json:"endTimeUtc"`
}

type sarifResult struct {
	RuleID     string         `json:"ruleId"`
	Level      string         `json:"level"`
	Message    sarifText      `json:"message"`
	Properties map[string]any `json:"properties,omitempty"`
}

// sarifLevel maps a finding severity onto a SARIF result level.
func sarifLevel(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// sarifRuleID turns a vulnerability class into a stable, URI-friendly rule id.
func sarifRuleID(class string) string {
	c := strings.ToLower(strings.TrimSpace(class))
	if c == "" {
		return "artex/uncategorized"
	}
	repl := func(r rune) rune {
		switch r {
		case ' ', '_', '/', '\\', '.', ':':
			return '-'
		}
		return r
	}
	return "artex/" + strings.Trim(strings.Map(repl, c), "-")
}

// FindingsSARIF renders findings as a SARIF 2.1.0 log.
func FindingsSARIF(fs []*db.DBFinding, generatedAt time.Time) ([]byte, error) {
	items := append([]*db.DBFinding(nil), fs...)
	sortFindingsForExport(items)

	rules := make([]sarifRule, 0, len(items))
	seen := map[string]bool{}
	results := make([]sarifResult, 0, len(items))

	for _, f := range items {
		id := sarifRuleID(f.VulnClass)
		if !seen[id] {
			seen[id] = true
			rules = append(rules, sarifRule{
				ID:                   id,
				Name:                 findingTitle(f),
				ShortDescription:     sarifText{Text: nz(f.VulnClass, "uncategorized")},
				DefaultConfiguration: sarifRuleDefault{Level: sarifLevel(f.Severity)},
				Properties:           map[string]any{"vulnClass": f.VulnClass},
			})
		}

		msg := nz(f.Summary, nz(f.Name, findingTitle(f)))
		if msg == "" {
			msg = "finding without summary"
		}
		props := map[string]any{
			"severity":  nz(f.Severity, "unknown"),
			"findingId": f.ID,
		}
		if f.Status != "" {
			props["status"] = f.Status
		}
		if f.Worker != "" {
			props["worker"] = f.Worker
		}
		if f.TaskID != nil {
			props["taskId"] = *f.TaskID
		}
		if len(f.AssetIDs) > 0 {
			props["assetIds"] = f.AssetIDs
		}
		if f.Evidence != "" {
			ev := f.Evidence
			if len(ev) > 4000 { // keep the log importable; full evidence stays in the DB/export zip
				ev = ev[:4000] + "\n… (truncated, full evidence in the evidence store)"
			}
			props["evidence"] = ev
		}

		results = append(results, sarifResult{
			RuleID:     id,
			Level:      sarifLevel(f.Severity),
			Message:    sarifText{Text: msg},
			Properties: props,
		})
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "ARTEX",
				InformationURI: "https://github.com/jiwoochris/artex-global",
				Rules:          rules,
			}},
			Invocations: []sarifInvoke{{
				ExecutionSuccessful: true,
				EndTimeUTC:          generatedAt.UTC().Format(time.RFC3339),
			}},
			Results: results,
		}},
	}

	b, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal sarif: %w", err)
	}
	return append(b, '\n'), nil
}
