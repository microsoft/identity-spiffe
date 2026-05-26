# Contributing

This project welcomes contributions and suggestions. Before opening a pull
request, please read the repository guidance in [`AGENTS.md`](AGENTS.md) and
[`CLAUDE.md`](CLAUDE.md), then run the relevant validation commands for the
files you changed.

## Contributor License Agreement

Most contributions require you to agree to a Contributor License Agreement
(CLA) declaring that you have the right to, and actually do, grant us the rights
to use your contribution. For details, visit
[https://cla.opensource.microsoft.com](https://cla.opensource.microsoft.com).

When you submit a pull request, the CLA bot will determine whether you need to
provide a CLA and decorate the pull request appropriately. Follow the bot's
instructions when prompted.

## Development workflow

1. Fork the repository and create a topic branch.
2. Keep changes focused and avoid committing generated build output, local
   deployment state, credentials, or environment-specific identifiers.
3. Update documentation when behavior, setup, deployment, or public APIs change.
4. Run targeted validation for the changed area before opening a pull request.

Useful validation commands:

```bash
bash -n deploy.sh
python3 -m compileall -q scripts portal/app src
mkdocs build --strict
```

For sidecar changes under `src/spiffe-proxy/`, also run the relevant Go tests.
Generated protobuf files are created during build/test flows and should not be
committed unless the repository policy changes.

## Security issues

Do not report security vulnerabilities through public GitHub issues. Follow the
instructions in [`SECURITY.md`](SECURITY.md).
