package provider

import (
	"context"
	"encoding/json"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/konjoai/squash-terraform-provider/internal/squashcli"
)

// stringList unpacks a types.List of strings, dropping nulls and empties.
func stringList(ctx context.Context, l types.List, diags *diag.Diagnostics) []string {
	if l.IsNull() || l.IsUnknown() {
		return nil
	}
	var out []string
	d := l.ElementsAs(ctx, &out, false)
	diags.Append(d...)
	clean := out[:0]
	for _, s := range out {
		if s != "" {
			clean = append(clean, s)
		}
	}
	return clean
}

// stringListValue lifts a Go []string into a typed types.List value.
// Always returns a non-null list (empty slice → empty list) so the
// Terraform plan is stable across reads.
func stringListValue(ss []string) types.List {
	elems := make([]types.String, 0, len(ss))
	for _, s := range ss {
		elems = append(elems, types.StringValue(s))
	}
	v, _ := types.ListValueFrom(context.Background(), types.StringType, elems)
	return v
}

// float64MapValue lifts a Go map[string]float64 into a typed types.Map.
// nil maps become null Map values — Terraform treats null != empty, and
// computed-null is the right signal that no per-framework data was
// produced (older squash versions).
func float64MapValue(m map[string]float64) types.Map {
	if m == nil {
		return types.MapNull(types.Float64Type)
	}
	elems := make(map[string]types.Float64, len(m))
	for k, v := range m {
		elems[k] = types.Float64Value(v)
	}
	v, _ := types.MapValueFrom(context.Background(), types.Float64Type, elems)
	return v
}

// readRecordIfPresent reads a master record, returning (nil, nil) if the
// file simply does not exist — caller may interpret that as "drift; drop
// from state". Other I/O errors are returned verbatim.
func readRecordIfPresent(path string) (*squashcli.AttestationRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !json.Valid(data) {
		return nil, nil
	}
	return squashcli.ParseRecord(data)
}
