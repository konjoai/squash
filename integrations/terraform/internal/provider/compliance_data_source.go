package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/konjoai/squash-terraform-provider/internal/squashcli"
)

// ComplianceScoreDataSource reads an existing master attestation record
// from disk and exposes its scores. Use this when an attestation was
// produced outside Terraform (e.g. by CI) but a downstream resource —
// say, a Kubernetes Deployment — should refuse to apply if the latest
// run's score is below threshold.
type ComplianceScoreDataSource struct{}

func NewComplianceScoreDataSource() datasource.DataSource { return &ComplianceScoreDataSource{} }

type complianceScoreModel struct {
	MasterRecordPath types.String  `tfsdk:"master_record_path"`
	AttestationID    types.String  `tfsdk:"attestation_id"`
	OverallScore     types.Float64 `tfsdk:"overall_score"`
	Passed           types.Bool    `tfsdk:"passed"`
	GeneratedAt      types.String  `tfsdk:"generated_at"`
	FrameworkScores  types.Map     `tfsdk:"framework_scores"`
	TopFrameworks    types.List    `tfsdk:"top_frameworks"`
}

func (d *ComplianceScoreDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_compliance_score"
}

func (d *ComplianceScoreDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Read an existing squash master attestation record (`master_record.json`) without re-running the pipeline.",
		Attributes: map[string]schema.Attribute{
			"master_record_path": schema.StringAttribute{Required: true, MarkdownDescription: "Path to a master attestation JSON file."},
			"attestation_id":     schema.StringAttribute{Computed: true},
			"overall_score":      schema.Float64Attribute{Computed: true},
			"passed":             schema.BoolAttribute{Computed: true},
			"generated_at":       schema.StringAttribute{Computed: true},
			"framework_scores":   schema.MapAttribute{Computed: true, ElementType: types.Float64Type},
			"top_frameworks":     schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Up to three highest-scoring framework keys, descending."},
		},
	}
}

func (d *ComplianceScoreDataSource) Configure(_ context.Context, _ datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
}

func (d *ComplianceScoreDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg complianceScoreModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	data, err := os.ReadFile(cfg.MasterRecordPath.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("read master record failed", err.Error())
		return
	}
	rec, err := squashcli.ParseRecord(data)
	if err != nil {
		resp.Diagnostics.AddError("parse master record failed", err.Error())
		return
	}

	cfg.AttestationID = types.StringValue(rec.AttestationID)
	cfg.OverallScore = types.Float64Value(rec.OverallScore)
	cfg.Passed = types.BoolValue(rec.Passed)
	cfg.GeneratedAt = types.StringValue(rec.GeneratedAt)
	cfg.FrameworkScores = float64MapValue(rec.FrameworkScores)
	cfg.TopFrameworks = stringListValue(rec.TopFrameworks(3))

	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}
