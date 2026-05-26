# Docs Site

This repo publishes its developer documentation through MkDocs and GitHub Pages.

The exact production URL is owned by the repository's GitHub Pages settings. Do not hardcode temporary Pages hostnames into source docs.

## Local Preview

Install the docs dependencies:

```bash
python3 -m pip install -r requirements-docs.txt
```

Start the local preview server:

```bash
mkdocs serve
```

Open `http://127.0.0.1:8000`.

## Static Build

```bash
mkdocs build --strict
```

The generated site is written to `site/`.

## GitHub Actions Behavior

`.github/workflows/docs.yml` does two things:

- on pull requests: build the docs to catch broken links or config errors
- on `main`: build and deploy to GitHub Pages

`workflow_dispatch` is enabled for manual runs, but only the `main` ref is allowed to publish the live site.

## Authoring Guidelines

- keep the root `README.md` short and route deep detail into `docs/`
- put long-lived architecture and reference material under `docs/`
- keep operational gotchas in `docs/runbooks/`
- add or update nav entries in `mkdocs.yml` when you add a new page

## Recommended Maintenance Rule

If a product or deploy change adds a new public endpoint, auth contract, or environment variable, update the matching docs page in the same change. For this repo that usually means one of:

- [Management APIs](../reference/management-apis.md)
- [Authentication Flows](../reference/authentication-flows.md)
- [Portal Runtime](portal-runtime.md)
- [Parallel Deployments](parallel-deployments.md)
