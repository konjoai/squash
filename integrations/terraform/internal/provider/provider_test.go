package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Schema validation: all schemas must accept Validate() without panic.
// This is the "compiles + framework accepts it" floor — the smallest
// signal that the provider is actually loadable by Terraform.
func TestProviderSchema(t *testing.T) {
	t.Parallel()
	p := New("test")()
	resp := provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("provider schema diagnostics: %v", resp.Diagnostics)
	}
	if _, ok := resp.Schema.Attributes["cli_path"]; !ok {
		t.Fatal("expected cli_path attribute on provider schema")
	}
}

func TestAttestationResourceSchema(t *testing.T) {
	t.Parallel()
	r := NewAttestationResource()
	resp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diagnostics: %v", resp.Diagnostics)
	}
	for _, want := range []string{"model_path", "policies", "attestation_id", "overall_score", "framework_scores"} {
		if _, ok := resp.Schema.Attributes[want]; !ok {
			t.Errorf("missing attribute %q", want)
		}
	}
}

func TestPolicyCheckResourceSchema(t *testing.T) {
	t.Parallel()
	r := NewPolicyCheckResource()
	resp := resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diagnostics: %v", resp.Diagnostics)
	}
	for _, want := range []string{"min_score", "require_passed", "result"} {
		if _, ok := resp.Schema.Attributes[want]; !ok {
			t.Errorf("missing attribute %q", want)
		}
	}
}

func TestComplianceScoreDataSourceSchema(t *testing.T) {
	t.Parallel()
	d := NewComplianceScoreDataSource()
	resp := datasource.SchemaResponse{}
	d.Schema(context.Background(), datasource.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("diagnostics: %v", resp.Diagnostics)
	}
	if _, ok := resp.Schema.Attributes["top_frameworks"]; !ok {
		t.Error("missing top_frameworks attribute")
	}
}

func TestStrOrEnv(t *testing.T) {
	t.Setenv("SQUASH_TEST_KEY", "from-env")
	if got := strOrEnv(types.StringNull(), "SQUASH_TEST_KEY"); got != "from-env" {
		t.Errorf("env fallback failed: %q", got)
	}
	if got := strOrEnv(types.StringValue("explicit"), "SQUASH_TEST_KEY"); got != "explicit" {
		t.Errorf("explicit value should win: %q", got)
	}
	if got := strOrEnv(types.StringValue(""), "SQUASH_TEST_KEY"); got != "from-env" {
		t.Errorf("empty string should fall back to env: %q", got)
	}
}

func TestReadRecordIfPresent_missingFile(t *testing.T) {
	t.Parallel()
	rec, err := readRecordIfPresent(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing file should return (nil, nil), got err: %v", err)
	}
	if rec != nil {
		t.Fatal("expected nil record for missing file")
	}
}

func TestReadRecordIfPresent_validJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "master.json")
	body := []byte(`{"attestation_id":"att-xyz","overall_score":91.5,"passed":true}`)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := readRecordIfPresent(p)
	if err != nil {
		t.Fatalf("read err: %v", err)
	}
	if rec == nil || rec.AttestationID != "att-xyz" || rec.OverallScore != 91.5 {
		t.Fatalf("bad record: %+v", rec)
	}
}

func TestFloat64MapValue_nilMap(t *testing.T) {
	t.Parallel()
	v := float64MapValue(nil)
	if !v.IsNull() {
		t.Fatal("nil map should produce a null Map value")
	}
}

func TestFloat64MapValue_populated(t *testing.T) {
	t.Parallel()
	v := float64MapValue(map[string]float64{"eu-ai-act": 95, "iso-42001": 88})
	if v.IsNull() || v.IsUnknown() {
		t.Fatal("populated map should be known and non-null")
	}
	elems := v.Elements()
	if len(elems) != 2 {
		t.Fatalf("element count: %d", len(elems))
	}
}

func TestStringListValue_emptyIsNonNull(t *testing.T) {
	t.Parallel()
	v := stringListValue(nil)
	if v.IsNull() {
		t.Fatal("empty slice should produce empty (non-null) list — plan stability")
	}
	if len(v.Elements()) != 0 {
		t.Fatalf("expected empty list, got %d elements", len(v.Elements()))
	}
}
