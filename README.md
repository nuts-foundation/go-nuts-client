# Golang client library for the Nuts Node

Contains:

- Generated clients to interact with the Nuts node's internal APIs
  - Discovery
  - Auth
- An OAuth2 client for interacting with Resource Servers that are secured using Nuts.

## Development

The library generates code from the Nuts node's OpenAPI specifications. To regenerate the code, run:

```bash
go generate ./...
```

It uses the `oapi-codegen` tool to generate the code. To install it, run:

```bash
go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v1.16.3
```