package report

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestFindingsSARIFShape(t *testing.T) {
	now := time.Date(2026, 11, 17, 5, 0, 0, 0, time.UTC)
	taskID := int64(7)
	fs := []*db.DBFinding{
		{ID: 1, TaskID: &taskID, VulnClass: "sql_injection", Name: "SQLi in search", Severity: "high",
			Summary: "Search parameter reaches a concatenated query", Evidence: "GET /x?q=' -> 500", Status: "confirmed"},
		{ID: 2, TaskID: &taskID, VulnClass: "SQL Injection", Name: "dup rule", Severity: "critical", Summary: "dup"},
		{ID: 3, VulnClass: "idor", Name: "IDOR", Severity: "medium", Summary: "cross-account read"},
		{ID: 4, VulnClass: "", Name: "misc", Severity: "low", Summary: "no class"},
	}

	raw, err := FindingsSARIF(fs, now)
	if err != nil {
		t.Fatalf("FindingsSARIF: %v", err)
	}

	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID                   string `json:"id"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Invocations []struct {
				ExecutionSuccessful bool   `json:"executionSuccessful"`
				EndTimeUTC          string `json:"endTimeUtc"`
			} `json:"invocations"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Properties map[string]any `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if log.Version != "2.1.0" || log.Schema == "" {
		t.Fatalf("bad envelope: version=%q schema=%q", log.Version, log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "ARTEX" {
		t.Fatalf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("invocation missing or unsuccessful: %+v", run.Invocations)
	}
	if got, want := run.Invocations[0].EndTimeUTC, "2026-11-17T05:00:00Z"; got != want {
		t.Fatalf("endTimeUtc = %q, want %q", got, want)
	}

	// one rule per class, with case/spacing normalised ("SQL Injection" == "sql_injection")
	rules := map[string]string{}
	for _, r := range run.Tool.Driver.Rules {
		if _, dup := rules[r.ID]; dup {
			t.Fatalf("duplicate rule id %q", r.ID)
		}
		rules[r.ID] = r.DefaultConfiguration.Level
	}
	if len(rules) != 3 {
		t.Fatalf("want 3 rules (sql-injection, idor, uncategorized), got %d: %v", len(rules), rules)
	}
	if rules["artex/sql-injection"] != "error" {
		t.Fatalf("sql-injection default level = %q", rules["artex/sql-injection"])
	}
	if rules["artex/idor"] != "warning" {
		t.Fatalf("idor default level = %q", rules["artex/idor"])
	}
	if _, ok := rules["artex/uncategorized"]; !ok {
		t.Fatalf("missing uncategorized rule: %v", rules)
	}

	if len(run.Results) != len(fs) {
		t.Fatalf("results = %d, want %d", len(run.Results), len(fs))
	}
	// severity-ordered: critical first, low last
	if run.Results[0].Level != "error" || run.Results[len(run.Results)-1].Level != "note" {
		t.Fatalf("results not severity ordered: first=%q last=%q",
			run.Results[0].Level, run.Results[len(run.Results)-1].Level)
	}
	if run.Results[0].Message.Text == "" {
		t.Fatal("empty result message")
	}
	if run.Results[0].Properties["findingId"] == nil {
		t.Fatalf("findingId missing in properties: %v", run.Results[0].Properties)
	}
}

func TestFindingsSARIFEmpty(t *testing.T) {
	raw, err := FindingsSARIF(nil, time.Now())
	if err != nil {
		t.Fatalf("FindingsSARIF(nil): %v", err)
	}
	var log map[string]any
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("empty export is not JSON: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Fatalf("version = %v", log["version"])
	}
}
