package squashcli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// fakeRunner implements Runner without spawning a process. It writes a
// fixed JSON record to whatever --json-result path the caller passes,
// then returns the configured exit code.
type fakeRunner struct {
	gotArgs  []string
	exitCode int
	stderr   string
	record   AttestationRecord
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, []byte, int, error) {
	f.gotArgs = append([]string(nil), args...)
	for i, a := range args {
		if a == "--json-result" && i+1 < len(args) {
			data, _ := json.Marshal(f.record)
			_ = os.WriteFile(args[i+1], data, 0o600)
		}
	}
	return nil, []byte(f.stderr), f.exitCode, nil
}

func TestAttestRequest_args(t *testing.T) {
	t.Parallel()
	req := AttestRequest{
		ModelPath:       "./model",
		Policies:        []string{"eu-ai-act", "", "iso-42001"},
		OutputDir:       "/tmp/out",
		Sign:            true,
		FailOnViolation: true,
		SkipScan:        true,
		ModelID:         "phi-3",
		HFRepo:          "microsoft/phi-3",
		QuantFormat:     "INT4",
		Offline:         true,
	}
	got := req.args("/tmp/r.json")
	want := []string{
		"attest", "./model",
		"--policy", "eu-ai-act",
		"--policy", "iso-42001",
		"--output-dir", "/tmp/out",
		"--sign",
		"--fail-on-violation",
		"--skip-scan",
		"--model-id", "phi-3",
		"--hf-repo", "microsoft/phi-3",
		"--quant-format", "INT4",
		"--offline",
		"--json-result", "/tmp/r.json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestAttestRequest_args_minimal(t *testing.T) {
	t.Parallel()
	req := AttestRequest{ModelPath: "./m", QuantFormat: "unknown"}
	got := req.args("")
	want := []string{"attest", "./m"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected minimal args, got: %v", got)
	}
}

func TestAttest_happyPath(t *testing.T) {
	t.Parallel()
	fake := &fakeRunner{
		record: AttestationRecord{
			AttestationID: "att-123",
			ModelID:       "phi-3",
			Passed:        true,
			OverallScore:  92.5,
			FrameworkScores: map[string]float64{
				"eu-ai-act":   95,
				"iso-42001":   88,
				"nist-ai-rmf": 90,
			},
			PolicyResults: []PolicyResult{
				{Policy: "enterprise-strict", Passed: true, Score: 92.5, Findings: 0},
			},
			SBOMPaths: SBOMPaths{
				CycloneDX:    "/tmp/sbom.cdx.json",
				MasterRecord: "/tmp/master.json",
			},
		},
	}
	rec, _, _, code, err := Attest(context.Background(), fake, AttestRequest{ModelPath: "./m"})
	if err != nil {
		t.Fatalf("Attest err: %v", err)
	}
	if code != 0 {
		t.Fatalf("code: %d", code)
	}
	if rec.AttestationID != "att-123" || rec.OverallScore != 92.5 || !rec.Passed {
		t.Fatalf("record decoded incorrectly: %+v", rec)
	}
	// argv must include attest + model + an injected --json-result
	if len(fake.gotArgs) < 4 || fake.gotArgs[0] != "attest" {
		t.Fatalf("unexpected argv: %v", fake.gotArgs)
	}
	sawJSON := false
	for _, a := range fake.gotArgs {
		if a == "--json-result" {
			sawJSON = true
		}
	}
	if !sawJSON {
		t.Fatalf("--json-result not appended: %v", fake.gotArgs)
	}
}

func TestAttest_nonZeroExit_noRecord(t *testing.T) {
	t.Parallel()
	// runner returns non-zero and never writes the JSON file → expect a
	// formatted error containing the exit code and stderr snippet.
	fake := &fakeRunnerNoWrite{exitCode: 2, stderr: "policy violation: x"}
	_, _, _, _, err := Attest(context.Background(), fake, AttestRequest{ModelPath: "./m"})
	if err == nil {
		t.Fatal("expected error on non-zero exit with no record")
	}
	if !strings.Contains(err.Error(), "exited 2") || !strings.Contains(err.Error(), "policy violation") {
		t.Fatalf("error did not surface exit code/stderr: %v", err)
	}
}

type fakeRunnerNoWrite struct {
	exitCode int
	stderr   string
}

func (f *fakeRunnerNoWrite) Run(_ context.Context, _ ...string) ([]byte, []byte, int, error) {
	return nil, []byte(f.stderr), f.exitCode, nil
}

func TestParseRecord_lenientUnknownFields(t *testing.T) {
	t.Parallel()
	// future squash version adds fields we don't know about — must still parse
	doc := []byte(`{"attestation_id":"x","unknown_future_field":42,"overall_score":80}`)
	rec, err := ParseRecord(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.AttestationID != "x" || rec.OverallScore != 80 {
		t.Fatalf("bad parse: %+v", rec)
	}
}

func TestTopFrameworks_orderAndLimit(t *testing.T) {
	t.Parallel()
	rec := &AttestationRecord{
		FrameworkScores: map[string]float64{
			"a": 90, "b": 90, "c": 70, "d": 95,
		},
	}
	got := rec.TopFrameworks(3)
	want := []string{"d", "a", "b"}
	if !reflect.DeepEqual(got, want) {
		// order ties broken lexically — deterministic sort regression
		sort.Strings(got)
		sort.Strings(want)
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExecRunner_realBin_missing(t *testing.T) {
	t.Parallel()
	r := &ExecRunner{Path: filepath.Join(os.TempDir(), "no-such-squash-xyz")}
	_, _, _, err := r.Run(context.Background(), "version")
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
}
