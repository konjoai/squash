// Package provider implements the Terraform provider for squash.
//
// Resources:
//
//	squash_attestation        — runs `squash attest` and tracks the artefact
//	squash_policy_check       — declarative gate that fails apply on regression
//
// Data sources:
//
//	squash_compliance_score   — reads an existing master attestation record
//
// All real work delegates to the squashcli package, which is the single
// source of truth for invoking the Python CLI. The provider is a typed,
// declarative facade — no business logic lives here.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/konjoai/squash-terraform-provider/internal/squashcli"
)

// SquashProvider satisfies provider.Provider.
type SquashProvider struct {
	version string
}

// New returns a constructor that the providerserver can call.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &SquashProvider{version: version}
	}
}

// providerData is what gets handed to every resource/data source via
// req.ProviderData after Configure runs.
type providerData struct {
	Runner    squashcli.Runner
	ModelsDir string
	Policy    string
}

func (p *SquashProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "squash"
	resp.Version = p.version
}

// providerConfigModel mirrors the provider {} block in HCL.
type providerConfigModel struct {
	CLIPath   types.String `tfsdk:"cli_path"`
	ModelsDir types.String `tfsdk:"models_dir"`
	Policy    types.String `tfsdk:"policy"`
	APIKey    types.String `tfsdk:"api_key"`
	Offline   types.Bool   `tfsdk:"offline"`
}

func (p *SquashProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Provider for [Squash](https://github.com/konjoai/squash) — automated EU AI Act, NIST AI RMF, and ISO 42001 compliance attestation. Wraps the `squash` CLI as declarative Terraform resources.",
		Attributes: map[string]schema.Attribute{
			"cli_path": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Path to the `squash` binary. Defaults to `squash` on `$PATH`. Override via env `SQUASH_CLI_PATH`.",
			},
			"models_dir": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Default directory for model lookups. Override via env `SQUASH_MODELS_DIR`.",
			},
			"policy": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Default policy name applied when a resource omits its own. E.g. `eu-ai-act`, `nist-ai-rmf`, `iso-42001`, `enterprise-strict`.",
			},
			"api_key": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "API key for the Squash cloud API (forwarded as `SQUASH_API_KEY` to the CLI). Override via env `SQUASH_API_KEY`.",
			},
			"offline": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Run in air-gapped mode — disables OIDC and all network calls. Override via env `SQUASH_OFFLINE=1`.",
			},
		},
	}
}

func (p *SquashProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cliPath := strOrEnv(cfg.CLIPath, "SQUASH_CLI_PATH")
	modelsDir := strOrEnv(cfg.ModelsDir, "SQUASH_MODELS_DIR")
	policy := strOrEnv(cfg.Policy, "")
	apiKey := strOrEnv(cfg.APIKey, "SQUASH_API_KEY")

	env := []string{}
	if apiKey != "" {
		env = append(env, "SQUASH_API_KEY="+apiKey)
	}
	if (!cfg.Offline.IsNull() && cfg.Offline.ValueBool()) || os.Getenv("SQUASH_OFFLINE") == "1" {
		env = append(env, "SQUASH_OFFLINE=1")
	}

	data := &providerData{
		Runner:    &squashcli.ExecRunner{Path: cliPath, Env: env},
		ModelsDir: modelsDir,
		Policy:    policy,
	}
	resp.ResourceData = data
	resp.DataSourceData = data
}

func (p *SquashProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewAttestationResource,
		NewPolicyCheckResource,
	}
}

func (p *SquashProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewComplianceScoreDataSource,
	}
}

// strOrEnv resolves a configured string to its env-var fallback.
// Configured non-null/non-empty values always win.
func strOrEnv(s types.String, envKey string) string {
	if !s.IsNull() && !s.IsUnknown() && s.ValueString() != "" {
		return s.ValueString()
	}
	if envKey == "" {
		return ""
	}
	return os.Getenv(envKey)
}
