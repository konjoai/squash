// Command terraform-provider-squash is the Terraform provider entrypoint.
//
// Build: `make build` (requires HashiCorp deps; `go mod tidy` first run).
// Install locally: `make install` — copies the binary to the right
// ~/.terraform.d/plugins/ path so `terraform init` resolves it.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/konjoai/squash-terraform-provider/internal/provider"
)

// version is overridden at link time by goreleaser:
//
//	-ldflags="-X main.version=$(git describe --tags)"
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/konjoai/squash",
		Debug:   debug,
	}

	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatal(err.Error())
	}
}
