# Contributing to Sentinel Gate

Thanks for your interest in contributing! We respond to issues and PRs within 24 hours.

We welcome code contributions. A CLA is required for all PRs so we can keep the OSS version free and also offer a commercial license.

## Quick Start

```bash
# Clone
git clone https://github.com/sentinelgate/sentinelgate.git
cd sentinelgate

# Build
go build -o sentinelgate ./cmd/sentinelgate

# Test
go test ./...

# Run
./sentinelgate start --config configs/example.yaml
```

## How to Contribute

### Found a Bug?

1. Check [existing issues](https://github.com/sentinelgate/sentinelgate/issues) first
2. Open a new issue with:
   - What you expected
   - What happened
   - Steps to reproduce
   - Sentinel Gate version (`sentinelgate version`)

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
├── cmd/sentinelgate/    # CLI entry point
├── internal/
│   ├── proxy/           # Core proxy logic
│   ├── policy/          # CEL policy engine
│   ├── auth/            # Authentication
│   ├── audit/           # Audit logging
│   └── transport/       # Stdio + HTTP
└── configs/             # Example configs
```

## License

The project is licensed under AGPL-3.0.  
A CLA is required to allow dual-licensing of contributions.

## Questions?

- Open an issue
- Email: hello@sentinelgate.co.uk
