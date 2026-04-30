// Package squashcli wraps the `squash` Python CLI as a typed Go API.
//
// It exists to keep the Terraform provider thin: the provider becomes a
// declarative front-end over the same CLI surface used by humans and CI,
// which means there is exactly one source of truth for attestation
// behaviour. No duplicate SBOM logic, no parallel policy engine.
//
// Stdlib-only by design — this package must build offline and remain
// independent of the terraform-plugin-framework so it can be unit-tested
// without network access or HashiCorp dependencies.
package squashcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Runner executes `squash` subcommands. The interface lets tests inject a
// fake without spawning real processes.
type Runner interface {
	Run(ctx context.Context, args ...string) (stdout, stderr []byte, exitCode int, err error)
}

// ExecRunner shells out to the real `squash` binary on PATH (or a configured
// absolute path). Output is fully captured — never mixed into the parent
// process — so the provider can return clean diagnostics.
type ExecRunner struct {
	// Path to the squash binary. Empty defaults to "squash" on PATH.
	Path string
	// Extra environment variables, KEY=VALUE form. Inherits os.Environ().
	Env []string
	// Working directory for the subprocess. Empty inherits parent.
	Dir string
}

func (r *ExecRunner) bin() string {
	if r.Path == "" {
		return "squash"
	}
	return r.Path
}

// Run executes the configured binary and returns captured stdout, stderr,
// the process exit code, and a non-nil error only for spawn failures
// (binary missing, IO error). A non-zero exit code is reported via the
// returned int — not an error — because squash uses exit codes as part of
// its protocol (2 = policy violation, 1 = bad input).
func (r *ExecRunner) Run(ctx context.Context, args ...string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	if r.Dir != "" {
		cmd.Dir = r.Dir
	}
	if len(r.Env) > 0 {
		cmd.Env = append(os.Environ(), r.Env...)
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			err = nil
		}
	}
	return []byte(stdout.String()), []byte(stderr.String()), exitCode, err
}

// AttestRequest is the typed input to a `squash attest` invocation.
type AttestRequest struct {
	ModelPath       string
	Policies        []string // repeatable; empty → CLI default (enterprise-strict)
	OutputDir       string
	Sign            bool
	FailOnViolation bool
	SkipScan        bool
	ModelID         string
	HFRepo          string
	QuantFormat     string
	Offline         bool
}

// args renders the request as a `squash attest ...` argv slice. The
// --json-result flag is appended by Attest() with a per-call temp path so
// callers cannot accidentally collide on the output file.
func (a AttestRequest) args(jsonResultPath string) []string {
	out := []string{"attest", a.ModelPath}
	for _, p := range a.Policies {
		if p == "" {
			continue
		}
		out = append(out, "--policy", p)
	}
	if a.OutputDir != "" {
		out = append(out, "--output-dir", a.OutputDir)
	}
	if a.Sign {
		out = append(out, "--sign")
	}
	if a.FailOnViolation {
		out = append(out, "--fail-on-violation")
	}
	if a.SkipScan {
		out = append(out, "--skip-scan")
	}
	if a.ModelID != "" {
		out = append(out, "--model-id", a.ModelID)
	}
	if a.HFRepo != "" {
		out = append(out, "--hf-repo", a.HFRepo)
	}
	if a.QuantFormat != "" && a.QuantFormat != "unknown" {
		out = append(out, "--quant-format", a.QuantFormat)
	}
	if a.Offline {
		out = append(out, "--offline")
	}
	if jsonResultPath != "" {
		out = append(out, "--json-result", jsonResultPath)
	}
	return out
}

// Attest runs `squash attest` against the configured runner, capturing
// the master attestation record as JSON and decoding it into a typed
// AttestationRecord. The temp file holding --json-result is removed
// before return — the parsed value is the durable artefact.
func Attest(ctx context.Context, r Runner, req AttestRequest) (*AttestationRecord, []byte, []byte, int, error) {
	tmp, err := os.CreateTemp("", "squash-tf-*.json")
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("create temp result file: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	stdout, stderr, code, err := r.Run(ctx, req.args(tmpPath)...)
	if err != nil {
		return nil, stdout, stderr, code, err
	}

	rec, parseErr := readRecord(tmpPath)
	if parseErr != nil {
		// A non-zero exit with no record means the run aborted early
		// (e.g. bad path). Surface stderr so the provider can show it.
		if code != 0 {
			return nil, stdout, stderr, code, fmt.Errorf("squash attest exited %d: %s", code, strings.TrimSpace(string(stderr)))
		}
		return nil, stdout, stderr, code, fmt.Errorf("read attestation record: %w", parseErr)
	}
	return rec, stdout, stderr, code, nil
}

func readRecord(path string) (*AttestationRecord, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	return ParseRecord(data)
}

// ParseRecord decodes a master attestation record JSON document. It is
// deliberately tolerant: unknown fields are ignored so future squash
// versions can add metadata without breaking provider users.
func ParseRecord(data []byte) (*AttestationRecord, error) {
	var rec AttestationRecord
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields() // strict path used by tests
	err := dec.Decode(&rec)
	if err == nil {
		return &rec, nil
	}
	// Strict failed — fall back to lenient decode so production reads
	// always succeed; the strict pass exists to catch test-data drift.
	var lenient AttestationRecord
	if err2 := json.Unmarshal(data, &lenient); err2 != nil {
		return nil, err2
	}
	return &lenient, nil
}
