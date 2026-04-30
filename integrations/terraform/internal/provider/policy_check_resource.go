package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// PolicyCheckResource is a declarative gate. It does no I/O of its own —
// it consumes computed attributes from a `squash_attestation` resource
// (or a `squash_compliance_score` data source) and fails the apply if a
// minimum score or a required pass-state is not met.
//
// This is the pattern that makes squash usable in GitOps: the gate is
// part of the dependency graph, so a regression in compliance blocks
// every dependent resource — model deployments, API gateway rules,
// container image promotions — without any custom external-data hacks.
type PolicyCheckResource struct{}

func NewPolicyCheckResource() resource.Resource { return &PolicyCheckResource{} }

type policyCheckModel struct {
	ID            types.String  `tfsdk:"id"`
	AttestationID types.String  `tfsdk:"attestation_id"`
	Score         types.Float64 `tfsdk:"score"`
	Passed        types.Bool    `tfsdk:"passed"`
	MinScore      types.Float64 `tfsdk:"min_score"`
	RequirePassed types.Bool    `tfsdk:"require_passed"`
	Result        types.String  `tfsdk:"result"`
}

func (r *PolicyCheckResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_check"
}

func (r *PolicyCheckResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Declarative compliance gate. Fails `terraform apply` when a score drops below `min_score` or when `require_passed = true` and the upstream attestation did not pass.",
		Attributes: map[string]schema.Attribute{
			"id":             schema.StringAttribute{Computed: true},
			"attestation_id": schema.StringAttribute{Required: true, MarkdownDescription: "Attestation ID being gated."},
			"score":          schema.Float64Attribute{Required: true, MarkdownDescription: "Score reported by the upstream attestation."},
			"passed":         schema.BoolAttribute{Required: true, MarkdownDescription: "Pass-state of the upstream attestation."},
			"min_score":      schema.Float64Attribute{Optional: true, MarkdownDescription: "Minimum acceptable compliance score (0-100)."},
			"require_passed": schema.BoolAttribute{Optional: true, MarkdownDescription: "If true, gate fails when `passed = false`."},
			"result":         schema.StringAttribute{Computed: true, MarkdownDescription: "Human-readable gate result."},
		},
	}
}

func (r *PolicyCheckResource) Configure(_ context.Context, _ resource.ConfigureRequest, _ *resource.ConfigureResponse) {
}

func (r *PolicyCheckResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var p policyCheckModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &p)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !p.MinScore.IsNull() && p.Score.ValueFloat64() < p.MinScore.ValueFloat64() {
		resp.Diagnostics.AddError(
			"compliance gate failed: score below minimum",
			fmt.Sprintf("attestation_id=%s score=%.2f min_score=%.2f", p.AttestationID.ValueString(), p.Score.ValueFloat64(), p.MinScore.ValueFloat64()),
		)
		return
	}
	if !p.RequirePassed.IsNull() && p.RequirePassed.ValueBool() && !p.Passed.ValueBool() {
		resp.Diagnostics.AddError(
			"compliance gate failed: attestation did not pass",
			fmt.Sprintf("attestation_id=%s require_passed=true but passed=false", p.AttestationID.ValueString()),
		)
		return
	}
	p.ID = types.StringValue("gate-" + p.AttestationID.ValueString())
	p.Result = types.StringValue(fmt.Sprintf("ok score=%.2f passed=%t", p.Score.ValueFloat64(), p.Passed.ValueBool()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &p)...)
}

func (r *PolicyCheckResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
}

func (r *PolicyCheckResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var p policyCheckModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &p)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &p)...)
}

func (r *PolicyCheckResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}
