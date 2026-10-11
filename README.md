# pin-deep

**Recursive GitHub Actions pin checker.** You pinned your Actions — but did the actions you pinned pin *their* dependencies?

`pin-deep` starts from a SHA-pinned GitHub Action, fetches its `action.yml`, and recursively flags every nested `uses:` that is not pinned to a full commit SHA. Pinning has a depth dimension; this tool checks it.

## Why this exists

Pinning `uses:` to a commit SHA is standard supply-chain hygiene — until you realize the pinned action itself pulls in other actions by tag. The tj-actions incident (CVE-2025-30066) is the textbook case: the compromise reached victims *through* reviewdog, which referenced the compromised action. Pinning reviewdog itself was not enough, because the hole was one level deeper.

> "You pinned your Actions, but the Actions you pinned didn't pin their dependencies."

## Differentiation

Tools like [zizmor](https://github.com/woodruffw/zizmor) analyze your workflow files statically — they check *your* `uses:` lines. pin-deep checks one level further: it resolves what your pinned actions themselves depend on, recursively. Static workflow linters don't do recursive nested checks; pin-deep is the depth dimension of pinning.

## Install

```bash
pip install pin-deep
```

Requires Python 3.9+. No dependencies — stdlib only.

## Usage

Scan a workflow file:

```bash
pin-deep .github/workflows/ci.yml
```

Scan a single pinned action (starts the recursion from there):

```bash
pin-deep reviewdog/action-setup@e04ffabe3898a1af8f75141d79fa1ba7a3636eb3
```

Example output:

```
[unpinned] depth=1 actions/checkout@v4
    source: action.yml of acme/root@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    chain:  acme/root@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  ->  actions/checkout@v4
    note:   not pinned to a full commit SHA
```

Options:

```bash
pin-deep --max-depth 5 --format json .github/workflows/ci.yml
pin-deep --strict .github/workflows/ci.yml   # also fail on short SHAs and fetch errors
```

Exit code is 1 when unpinned nested actions are found, so it drops straight into CI:

```yaml
- run: pip install pin-deep
- run: pin-deep .github/workflows/ci.yml
```

`GITHUB_TOKEN` (or `--token`) is used for the API fallback when fetching `action.yml`; public repos work without one.

## How it works

1. Parse every `uses:` value from the target (workflow file or bare `owner/repo@ref`).
2. Classify each: `pinned` (full 40/64-char SHA), `unpinned` (tag, branch, or no ref), `short-sha` (warning), or skipped (`./local`, `docker://`, dynamic expressions).
3. For each pinned action, fetch its `action.yml` at that exact SHA and repeat — up to `--max-depth` (default 3), with a visited set so reference cycles can't loop forever.
4. Unpinned refs are reported but never recursed into: a moving tag has no fixed content to analyze.

## Limitations

- Only recurses into full-SHA pins. Analyzing the children of a floating tag would audit today's state, not the state you ship.
- `uses:` parsing is line-based, not a full YAML parse — exotic YAML layouts may be missed.
- Private repos need `GITHUB_TOKEN`.

## License

MIT — see [LICENSE](LICENSE).
