package squashcli

// AttestationRecord is the typed view of squash's master attestation JSON
// (the `--json-result` payload written by `squash attest`). Fields are
// intentionally a superset stable shape — squash may add more, but these
// are the ones the Terraform provider exposes as resource attributes.
//
// All fields use json tags matching the Python record key names exactly.
// New fields should be added with `omitempty` so older squash versions
// that omit them parse cleanly.
type AttestationRecord struct {
	AttestationID   string             `json:"attestation_id,omitempty"`
	ModelID         string             `json:"model_id,omitempty"`
	ModelPath       string             `json:"model_path,omitempty"`
	GeneratedAt     string             `json:"generated_at,omitempty"`
	SquashVersion   string             `json:"squash_version,omitempty"`
	Passed          bool               `json:"passed,omitempty"`
	OverallScore    float64            `json:"overall_score,omitempty"`
	FrameworkScores map[string]float64 `json:"framework_scores,omitempty"`
	PolicyResults   []PolicyResult     `json:"policy_results,omitempty"`
	SBOMPaths       SBOMPaths          `json:"sbom_paths,omitempty"`
	Signature       *Signature         `json:"signature,omitempty"`
	ScanSummary     *ScanSummary       `json:"scan_summary,omitempty"`
}

// PolicyResult is one policy evaluation entry.
type PolicyResult struct {
	Policy   string  `json:"policy,omitempty"`
	Passed   bool    `json:"passed,omitempty"`
	Score    float64 `json:"score,omitempty"`
	Findings int     `json:"findings,omitempty"`
}

// SBOMPaths records artefact locations on disk after a run.
type SBOMPaths struct {
	CycloneDX    string `json:"cyclonedx,omitempty"`
	SPDXJSON     string `json:"spdx_json,omitempty"`
	MasterRecord string `json:"master_record,omitempty"`
}

// Signature carries Sigstore-keyless or offline-Ed25519 metadata.
type Signature struct {
	Path        string `json:"path,omitempty"`
	KeylessOIDC bool   `json:"keyless_oidc,omitempty"`
	Identity    string `json:"identity,omitempty"`
}

// ScanSummary is the security scanner outcome.
type ScanSummary struct {
	Status   string `json:"status,omitempty"`
	IsSafe   bool   `json:"is_safe,omitempty"`
	Critical int    `json:"critical,omitempty"`
	High     int    `json:"high,omitempty"`
}

// TopFrameworks returns the (up to n) framework keys with the highest
// scores, in descending order. Stable across runs by lexicographic
// tiebreak. Used to populate the data source's compact view.
func (r *AttestationRecord) TopFrameworks(n int) []string {
	if r == nil || len(r.FrameworkScores) == 0 || n <= 0 {
		return nil
	}
	keys := make([]string, 0, len(r.FrameworkScores))
	for k := range r.FrameworkScores {
		keys = append(keys, k)
	}
	// insertion sort — N is tiny (single-digit frameworks)
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0; j-- {
			a, b := keys[j-1], keys[j]
			sa, sb := r.FrameworkScores[a], r.FrameworkScores[b]
			if sa > sb || (sa == sb && a < b) {
				break
			}
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	if n > len(keys) {
		n = len(keys)
	}
	return keys[:n]
}
