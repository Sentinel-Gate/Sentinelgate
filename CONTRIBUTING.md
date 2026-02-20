# Contributing to Sentinel Gate

Thanks for your interest in contributing! We respond to issues and PRs within 24 hours.

We welcome code contributions. A CLA is required for all PRs so we can keep the OSS version free and also offer a commercial license.

## Quick Start

```bash
# Clone
git clone https://github.com/Sentinel-Gate/Sentinelgate.git
cd Sentinelgate

# Build
go build -o sentinel-gate ./cmd/sentinel-gate

# Test
go test ./...

# Run
./sentinel-gate start
```

## How to Contribute

### Found a Bug?

1. Check [existing issues](https://github.com/Sentinel-Gate/Sentinelgate/issues) first
2. Open a new issue with:
   - What you expected
   - What happened
   - Steps to reproduce
   - Sentinel Gate version (`sentinel-gate version`)

### Want a Feature?

Open an issue describing:
- The use case
- Why existing features don't solve it
- Proposed solution (optional)

### Submitting Code

Before your PR can be merged, you must sign the CLA:
- See `CLA.md` in this repo
- A CLA bot may prompt you on your first PR

1. Fork the repo
2. Create a branch (`git checkout -b fix/issue-123`)
3. Make changes
4. Run tests (`go test ./...`)
5. Run linter (`golangci-lint run`)
6. Commit with clear message
7. Open PR referencing the issue

## Code Style

- Go standard formatting (`go fmt`)
- Meaningful variable names
- Comments for non-obvious logic
- Tests for new functionality

## Architecture

```
/
├── cmd/sentinel-gate/   # CLI entry point
├── internal/
│   ├── adapter/         # Inbound (HTTP, stdio, admin) and outbound (MCP, state, CEL) adapters
│   ├── config/          # Configuration loading and validation
│   ├── domain/          # Core domain: proxy, policy, audit, auth, session
│   ├── port/            # Port interfaces (hexagonal architecture)
│   └── service/         # Application services
├── pkg/                 # Public packages (MCP codec)
└── docs/                # Documentation
```

## License

The project is licensed under AGPL-3.0.  
A CLA is required to allow dual-licensing of contributions.

## Questions?

- Open an issue
- Email: hello@sentinelgate.co.uk
