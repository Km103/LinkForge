# Contributing

Open an issue before a large protocol or architecture change. Keep pull
requests focused and include tests for packet parsing, scheduling, reordering,
failure behavior, or platform-specific code.

Before submitting:

```bash
gofmt -w cmd internal
make vet
make test
make race
make cross
```

Wire-format changes need a versioning analysis and updates to
`docs/protocol.md`. Do not introduce proprietary code, assets, trademarks, or
captured traffic containing credentials or personal data.

Contributions are licensed under the MIT License.
