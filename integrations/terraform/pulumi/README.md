# Squash + Pulumi

Two ways to use squash from Pulumi today, ordered by friction.

## 1. Pulumi Terraform bridge (recommended for parity)

When the `terraform-provider-squash` binary is published to the Terraform
Registry, generate Pulumi SDKs for it via the official bridge:

```bash
pulumi-tfgen-squash schema --out ./schema.json
pulumi package gen-sdk ./schema.json --language typescript,python,go,csharp
```

This is the canonical multi-language path. The bridge is maintained by
the Pulumi team — every Terraform resource (`squash_attestation`,
`squash_policy_check`, `squash_compliance_score`) becomes a strongly-typed
Pulumi resource in every supported language with zero hand-written code.

See: [pulumi/pulumi-terraform-bridge](https://github.com/pulumi/pulumi-terraform-bridge).

## 2. `command:Command` shell-out (works today, no bridge needed)

Until the bridge SDK ships, `@pulumi/command` is the fast path. It runs
`squash attest` as part of the Pulumi resource graph, and you can gate
downstream resources on its exit code and stdout.

See [`./examples/typescript/index.ts`](./examples/typescript/index.ts)
and [`./examples/python/__main__.py`](./examples/python/__main__.py).

The shell-out approach has one tradeoff vs. the bridge: result fields
(score, framework breakdown) come out of stdout JSON, not strongly-typed
attributes. For most CI/CD and platform-team use cases that's enough.
