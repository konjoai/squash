package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/konjoai/squash-terraform-provider/internal/squashcli"
)

// AttestationResource declarative shape:
//
//	resource "squash_attestation" "phi3" {
//	  model_path        = "./models/phi-3"
//	  policies          = ["eu-ai-act", "iso-42001"]
//	  sign              = true
//	  fail_on_violation = true
//	}
//
// On Create the provider runs `squash attest` and stores the parsed
// master record. The resource ID is the squash AttestationID — a stable,
// auditable identifier — so terraform state aligns 1:1 with squash's
// own provenance store.
type AttestationResource struct {
	data *providerData
}

func NewAttestationResource() resource.Resource { return &AttestationResource{} }

type attestationModel struct {
	ID              types.String `tfsdk:"id"`
	ModelPath       types.String `tfsdk:"model_path"`
	ModelID         types.String `tfsdk:"model_id"`
	Policies        types.List   `tfsdk:"policies"`
	OutputDir       types.String `tfsdk:"output_dir"`
	HFRepo          types.String `tfsdk:"hf_repo"`
	QuantFormat     types.String `tfsdk:"quant_format"`
	Sign            types.Bool   `tfsdk:"sign"`
	FailOnViolation types.Bool   `tfsdk:"fail_on_violation"`
	SkipScan        types.Bool   `tfsdk:"skip_scan"`

	// Computed
	AttestationID    types.String  `tfsdk:"attestation_id"`
	OverallScore     types.Float64 `tfsdk:"overall_score"`
	Passed           types.Bool    `tfsdk:"passed"`
	GeneratedAt      types.String  `tfsdk:"generated_at"`
	SquashVersion    types.String  `tfsdk:"squash_version"`
	CycloneDXPath    types.String  `tfsdk:"cyclonedx_path"`
	SPDXJSONPath     types.String  `tfsdk:"spdx_json_path"`
	MasterRecordPath types.String  `tfsdk:"master_record_path"`
	SignaturePath    types.String  `tfsdk:"signature_path"`
	FrameworkScores  types.Map     `tfsdk:"framework_scores"`
}

func (r *AttestationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_attestation"
}

func (r *AttestationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Run `squash attest` against a model artefact and track the resulting attestation as Terraform-managed state. Re-running `terraform apply` after the model file changes triggers a replacement (a new attestation), preserving an immutable audit trail.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "Provider-stable ID — equal to `attestation_id`.",
			},
			"model_path": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				MarkdownDescription: "Path to the model directory or file.",
			},
			"model_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Override the model ID embedded in the SBOM.",
			},
			"policies": schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Policy names to evaluate. Empty → provider default → CLI default (`enterprise-strict`).",
			},
			"output_dir": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Directory for SBOM/signature artefacts. Default: squash's working dir.",
			},
			"hf_repo": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "HuggingFace `org/name` repo ID for provenance.",
			},
			"quant_format": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Quantization label (e.g. `INT4`, `BF16`).",
			},
			"sign": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Sign the SBOM via Sigstore keyless (or offline Ed25519 if `provider.offline = true`).",
			},
			"fail_on_violation": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "If true, an attestation that fails a policy gate causes `terraform apply` to error.",
			},
			"skip_scan": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Skip the security scanner stage.",
			},

			"attestation_id":     schema.StringAttribute{Computed: true, MarkdownDescription: "Squash-issued attestation ID."},
			"overall_score":      schema.Float64Attribute{Computed: true, MarkdownDescription: "Weighted compliance score 0-100."},
			"passed":             schema.BoolAttribute{Computed: true, MarkdownDescription: "True if all gating policies passed."},
			"generated_at":       schema.StringAttribute{Computed: true, MarkdownDescription: "ISO-8601 generation timestamp."},
			"squash_version":     schema.StringAttribute{Computed: true, MarkdownDescription: "Squash CLI version that produced this attestation."},
			"cyclonedx_path":     schema.StringAttribute{Computed: true, MarkdownDescription: "Path to the CycloneDX SBOM."},
			"spdx_json_path":     schema.StringAttribute{Computed: true, MarkdownDescription: "Path to the SPDX JSON SBOM."},
			"master_record_path": schema.StringAttribute{Computed: true, MarkdownDescription: "Path to the master attestation record."},
			"signature_path":     schema.StringAttribute{Computed: true, MarkdownDescription: "Path to the SBOM signature, if `sign = true`."},
			"framework_scores": schema.MapAttribute{
				Computed:            true,
				ElementType:         types.Float64Type,
				MarkdownDescription: "Per-framework score breakdown (e.g. eu-ai-act, iso-42001).",
			},
		},
	}
}

func (r *AttestationResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	if d, ok := req.ProviderData.(*providerData); ok {
		r.data = d
	}
}

func (r *AttestationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan attestationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policies := stringList(ctx, plan.Policies, &resp.Diagnostics)
	if len(policies) == 0 && r.data != nil && r.data.Policy != "" {
		policies = []string{r.data.Policy}
	}

	areq := squashcli.AttestRequest{
		ModelPath:       plan.ModelPath.ValueString(),
		Policies:        policies,
		OutputDir:       plan.OutputDir.ValueString(),
		Sign:            plan.Sign.ValueBool(),
		FailOnViolation: plan.FailOnViolation.ValueBool(),
		SkipScan:        plan.SkipScan.ValueBool(),
		ModelID:         plan.ModelID.ValueString(),
		HFRepo:          plan.HFRepo.ValueString(),
		QuantFormat:     plan.QuantFormat.ValueString(),
	}

	rec, _, stderr, code, err := squashcli.Attest(ctx, r.data.Runner, areq)
	if err != nil {
		resp.Diagnostics.AddError("squash attest failed", err.Error())
		return
	}
	if plan.FailOnViolation.ValueBool() && code != 0 {
		resp.Diagnostics.AddError(
			fmt.Sprintf("attestation gate failed (exit %d)", code),
			fmt.Sprintf("squash exited %d with --fail-on-violation set.\nstderr:\n%s", code, string(stderr)),
		)
		return
	}

	applyRecord(&plan, rec)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *AttestationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// The on-disk master record is the source of truth; if it has been
	// removed, drop the resource from state so the next apply re-creates.
	var state attestationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p := state.MasterRecordPath.ValueString()
	if p == "" {
		return
	}
	rec, err := readRecordIfPresent(p)
	if err != nil {
		// I/O error is *not* a hard failure — surface as warning so a
		// transient read miss doesn't blow up an unrelated apply.
		resp.Diagnostics.AddWarning("squash master record unreadable", err.Error())
		return
	}
	if rec == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	applyRecord(&state, rec)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *AttestationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// All meaningful inputs are RequiresReplace, so Update is only ever
	// called for cosmetic field flips. Re-run create-style logic.
	var plan attestationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *AttestationResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// Squash attestations are immutable provenance — never delete the
	// underlying record. Removing from state is sufficient. If the user
	// wants tombstoning, that is a `squash registry revoke` concern.
}

func (r *AttestationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by master_record_path: `terraform import squash_attestation.x /path/to/master.json`
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("master_record_path"), req.ID)...)
}

// applyRecord copies a parsed AttestationRecord into the typed Terraform model.
func applyRecord(m *attestationModel, rec *squashcli.AttestationRecord) {
	if rec == nil {
		return
	}
	id := rec.AttestationID
	if id == "" {
		// stable synthetic ID for older squash versions: hash of
		// (model_id || generated_at || master_record_path)
		h := sha256.Sum256([]byte(rec.ModelID + "|" + rec.GeneratedAt + "|" + rec.SBOMPaths.MasterRecord))
		id = "att-" + hex.EncodeToString(h[:8])
	}
	m.ID = types.StringValue(id)
	m.AttestationID = types.StringValue(id)
	m.OverallScore = types.Float64Value(rec.OverallScore)
	m.Passed = types.BoolValue(rec.Passed)
	m.GeneratedAt = types.StringValue(rec.GeneratedAt)
	m.SquashVersion = types.StringValue(rec.SquashVersion)
	m.CycloneDXPath = types.StringValue(rec.SBOMPaths.CycloneDX)
	m.SPDXJSONPath = types.StringValue(rec.SBOMPaths.SPDXJSON)
	m.MasterRecordPath = types.StringValue(rec.SBOMPaths.MasterRecord)
	if rec.Signature != nil {
		m.SignaturePath = types.StringValue(rec.Signature.Path)
	} else {
		m.SignaturePath = types.StringValue("")
	}
	m.FrameworkScores = float64MapValue(rec.FrameworkScores)
}
