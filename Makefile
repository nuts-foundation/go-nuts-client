.PHONY: gen-api

install-tools:
	go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v1.16.3

gen-api:

	oapi-codegen -generate client,types -package iam \
		-import-mapping='../common/ssi_types.yaml:github.com/SanteonNL/orca/orchestrator/lib/nuts' \
		-o nuts/auth/generated.go https://nuts-node.readthedocs.io/en/latest/_static/auth/v2.yaml
