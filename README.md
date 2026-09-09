# pkgguard — Open-Source AI Package Security Gate

**Built by [Blvkware](https://blvkware.dev)**

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![CI](https://github.com/rxslice/pkgguard-API/actions/workflows/ci.yml/badge.svg)](https://github.com/rxslice/pkgguard-API/actions/workflows/ci.yml)
[![False positives](https://img.shields.io/badge/false%20positives-1.0%25-brightgreen.svg)](#how-accurate-is-pkgguard)

**pkgguard is an open-source security tool and API that verifies npm, PyPI, and
crates.io package names before installation, to catch LLM-hallucinated
dependencies and slopsquatting supply-chain attacks.** It detects the
conflation attack pattern — where an AI blends two real package names into a
third that never existed — which typosquatting scanners structurally cannot
catch. Measured at **1.0% false positives with 7/7 threat recall** against live
registry data.

**In one sentence:** pkgguard is a pre-install AI supply-chain security gate
that blocks hallucinated, slopsquatted, and suspicious package names before
npm, pip, uv, or cargo executes them.

**Who is it for?** Security teams, platform engineers, DevSecOps teams, and
developers using GitHub Actions or autonomous coding agents that need
explainable package-install decisions without replacing their package manager.

**What does it replace?** Nothing. pkgguard complements software composition
analysis and malware scanners by checking package identity and reputation before
installation, including names that are not simple misspellings.

```bash
pip install pkgguard && pkgguard check -e npm react-codeshift
# BLOCK  react-codeshift  [npm]  risk=100
```

---

## Table of contents

- [What is slopsquatting?](#what-is-slopsquatting)
- [What problem does pkgguard solve?](#what-problem-does-pkgguard-solve)
- [Why can't existing scanners catch this?](#why-cant-existing-scanners-catch-this)
- [How accurate is pkgguard?](#how-accurate-is-pkgguard)
- [Installation](#installation)
- [Usage](#usage)
- [CI adoption](#ci-adoption)
- [How the risk scoring works](#how-does-the-risk-scoring-work)
- [FAQ](#frequently-asked-questions)
- [Limitations](#limitations)
- [License](#license)

---

## What is slopsquatting?

**Slopsquatting is a software supply-chain attack in which an attacker
registers a package name that AI coding assistants are known to hallucinate.**
When a developer or autonomous agent runs the suggested install command, they
download attacker-controlled code instead of hitting a "package not found"
error.

It works because package hallucination is measurable and repeatable:

- A 2025 USENIX Security study of 16 models across 576,000 code samples found
  AI tools recommend nonexistent packages roughly **19.7%** of the time.
- **43%** of hallucinated names were reproduced identically across repeated
  runs of the same prompt — making them a predictable target list.
- A 2026 replication across five frontier models measured hallucination rates
  of **4.62%–6.10%** — lower, but not retired.
- That replication identified **127 package names all five models invent
  identically**.

Confirmed incidents include `react-codeshift` and `unused-imports` on npm, and
a hallucinated `huggingface-cli` install command that was copied into public
documentation and accumulated over 30,000 downloads.

## What problem does pkgguard solve?

**Autonomous coding agents now run install commands themselves, removing the
human review step that used to catch fake package names.** A developer glancing
at `npm install some-package` was an implicit checkpoint. An agent executing its
own generated output is not.

pkgguard restores that checkpoint programmatically. It sits between an AI
agent's suggestion and your package manager, and answers one question: *is this
name real, and does it look like something an attacker planted?*

## Why can't existing scanners catch this?

**Because hallucinated names are not misspellings, so edit-distance similarity
checks score them as unrelated packages.**

The dominant attack shape is **conflation** — an LLM blending two real packages
into a third:

```
jscodeshift  +  react-codemod   →   react-codeshift
```

`react-codeshift` is eight or more edits from either parent. Every typosquat
heuristic reads it as an unrelated package and lets it through. It was
registered on npm in January 2026 after appearing in LLM-generated agent skills.

pkgguard's **conflation detector** is built for exactly this: it tokenizes the
candidate name, checks whether each token traces back to a different real
popular package, and confirms no real package contains the full combination.

**An existence check alone does not protect you.** By the time you look, the
hallucinated name frequently *does* exist — because someone registered it. That
is the entire attack.

## How accurate is pkgguard?

Benchmarked against live registry data, not synthetic fixtures.

| Metric | Result |
|---|---|
| False `BLOCK` on 200 real npm packages outside the popularity corpus | **1.0%** |
| Correctly `ALLOW`ed | 96.0% |
| Threat recall (real slopsquats, conflations, typosquats) | **7/7** |

Both documented real-world slopsquats — `react-codeshift` and `unused-imports` —
score 100 and `BLOCK`.

### How these numbers were reached

An early version of the conflation detector benchmarked at **0% false
positives**. That test was worthless: it ran against packages that were *in* the
popularity corpus, which short-circuit the check.

Re-run honestly against 800 real packages *outside* the corpus, the same
detector flagged **62.5% of legitimate packages**. Names like
`mock-redis-client` and `react-loading-hook` are token blends too.

Two architectural corrections brought it to 1.0%:

1. **Conflation is not a standalone signal.** It is gated behind weak reputation
   and weighted so it cannot reach `BLOCK` alone. Conflation *plus* brand-new
   *plus* single-version blocks. Conflation plus real release history does not.

2. **Typosquat detection measures adoption ratio, not spelling.** `expres` is 14
   years old with a real repository and 22,468 monthly downloads — every
   age-and-history heuristic reads it as legitimate. But `express` has
   529,873,075. Capturing 0.0042% of your namesake's traffic *is* the signature.

Reproduce both numbers yourself:

```bash
python scripts/benchmark.py --sample 200
```

If you change any scoring logic, re-run it. A change that improves false
positives at the cost of recall is not an improvement — report both or neither.

## Installation

```bash
git clone https://github.com/rxslice/pkgguard-API.git
cd pkgguard-API
pip install .
```

Requires Python 3.9+. No API key. No account. No proprietary data feed.
For the HTTP API: `pip install "pkgguard[api]"`.

## Usage

### CLI

```bash
# check names directly
pkgguard check -e npm react-codeshift lodash express

# check what an AI agent is about to run
echo "npm install react-codeshift lodash" | pkgguard scan-command

# gate a build
pkgguard scan-manifest package.json
pkgguard scan-manifest requirements.txt
pkgguard scan-manifest Cargo.toml
```

Exits `1` if anything is `BLOCK`ed, so it drops straight into CI.

```
BLOCK  react-codeshift  [npm]  risk=100
       - Name appears on the known-hallucination corpus.
       - Name appears to blend 2 real packages (jscodeshift, react) into a
         combination that does not exist. This is the signature of an LLM
         hallucination-by-conflation, which edit-distance typosquat checks
         do not detect.
       - Only a single published version — no release history.
       - Low adoption: 11 downloads in the last month.
       > Do not install without verifying this is the package you intend.
```

### HTTP API

```bash
uvicorn pkgguard.api:app --reload
# interactive docs: http://127.0.0.1:8000/docs
```

```bash
curl -X POST http://127.0.0.1:8000/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"names":["react-codeshift","express"],"ecosystem":"npm"}'
```

```json
{
  "results": [
    { "name": "react-codeshift", "verdict": "BLOCK", "risk_score": 100, "exists": true },
    { "name": "express", "verdict": "ALLOW", "risk_score": 0, "exists": true }
  ],
  "blocked": 1,
  "allowed": 1,
  "safe_to_proceed": false
}
```

Agent frameworks can gate a tool call on the single `safe_to_proceed` field.

### Agent command authorization

The agent gateway authorizes an install command before it is executed. It
returns `ALLOW`, `REVIEW`, or `BLOCK`; unknown command types fail toward
`REVIEW` instead of being treated as safe.

```bash
pkgguard authorize "npm install react-codeshift lodash"
```

`authorize` fails closed for `REVIEW` as well as `BLOCK`, which is the safe
default for autonomous agents. If your workflow has a separate approval step,
you can explicitly use `pkgguard authorize --allow-review ...`.

Very new existing packages are `BLOCK`ed by default. For teams that want a
human approval queue instead of a hard stop, use
`--new-package-policy review`; known hallucinations and confirmed typosquats
remain `BLOCK`ed.

```bash
curl -X POST http://127.0.0.1:8000/v1/agent/authorize \
  -H "Content-Type: application/json" \
  -d '{"command":"npm install react-codeshift lodash"}'
```

Use `safe_to_execute` as the enforcement decision in an agent wrapper. This
MVP intentionally authorizes package-manager commands only; shell commands
outside the supported install patterns require human review.
Compound commands, shell interpolation, redirection, pipelines, and command
chaining also fail toward `REVIEW` rather than being partially parsed.

The API accepts `"allow_review": true` only when a separate approval step has
already occurred for a recognized package-manager command. It never overrides
`BLOCK` or authorizes unknown/compound shell commands.
Set `"new_package_policy": "review"` to route ordinary very new packages to
human review rather than hard-blocking them.

#### MCP / agent runtime integration

For agent toolchains that expect a standard JSON-RPC tool interface, install the
MCP entry point and expose it over stdio:

```bash
pip install pkgguard
pkgguard-mcp
```

The server exposes a single tool: `authorize_install_command`. It accepts a
`command`, optional `allow_review`, and optional `new_package_policy`, and
returns `decision`, `safe_to_execute`, `ecosystem`, `packages`, and the
assessment payload. This makes the same guardrail usable from a hosted agent,
a local MCP host, or a custom tool wrapper without rewriting policy logic.

For a more direct pre-tool-use pattern, wrap the package-manager command itself:

```bash
pkgguard-gate -- npm install react-codeshift
```

This is the shell-friendly equivalent of a pre-execution enforcement hook: it
authorizes the package-manager command before execution, exits nonzero on
`REVIEW`/`BLOCK`, and otherwise runs the real install command unchanged.

#### GitHub Actions

For agent workflows running in GitHub Actions, use the composite action:

```yaml
- name: Authorize agent install
  id: pkgguard
  uses: ./.github/actions/authorize
  with:
    command: npm install react-codeshift lodash

- name: Install approved dependencies
  if: steps.pkgguard.outputs.safe-to-execute == 'true'
  run: npm install react-codeshift lodash
```

The action fails the job for `BLOCK` and `REVIEW` by default and publishes
`decision` and `safe-to-execute` outputs for downstream approval workflows.

**Endpoints**

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/health` | Liveness + supported ecosystems |
| `GET` | `/v1/verify/{ecosystem}/{name}` | Verify one package |
| `POST` | `/v1/verify` | Verify a batch (up to 100) |
| `POST` | `/v1/agent/authorize` | Authorize an agent-generated install command |

### GitHub Action

`.github/workflows/pkgguard.yml` fails the build on any `BLOCK`:

```yaml
- name: Install pkgguard
  run: pip install -e .
- name: Verify npm dependencies
  run: pkgguard scan-manifest package.json
```

### CI adoption

The lowest-friction adoption path is a manifest scan. It requires no agent
integration and publishes findings directly to GitHub Code Scanning:

```yaml
name: Dependency safety
on: [push, pull_request]
permissions:
  security-events: write
  contents: read

jobs:
  pkgguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rxslice/pkgguard-API/.github/actions/scan@main
        with:
          manifest: package.json
```

The Action fails on `BLOCK` and `REVIEW` by default. Set
`allow-review: "true"` only when your workflow has a separate human approval
step; confirmed blocks still fail. It accepts `package.json`,
`requirements.txt`, and `Cargo.toml`, emits standard SARIF, and exposes
`blocked` and `review` outputs for policy checks.

For local or non-GitHub CI, use the equivalent command:

```bash
pkgguard --sarif scan-manifest package.json > pkgguard.sarif
```

## How does the risk scoring work?

| Signal | Weight | Notes |
|---|---|---|
| Package does not exist | +70 | An AI suggested a name that isn't real |
| On known-hallucination corpus | +60 | Documented in public research |
| Confirmed typosquat | +60 | Close spelling **and** under 1% of target's downloads |
| Conflation (weak reputation only) | +30 | Cannot reach BLOCK alone — by design |
| Age 30 days or less | +30 | |
| Unresolved typosquat (no download data) | +30 | Fails toward caution |
| Age 120 days or less | +15 | |
| Single published version | +15 | |
| Under 1,000 monthly downloads | +15 | |
| No source repository | +10 | |

`BLOCK` at 60+ · `REVIEW` at 25+ · otherwise `ALLOW`

A registry failure never returns `ALLOW` — it returns `REVIEW` with the error
surfaced. Failing toward caution is deliberate.

## Refreshing the popularity corpora

Conflation and typosquat detection are only as good as the popularity index.

```bash
python scripts/refresh_corpus.py --ecosystem npm --limit 3000
python scripts/refresh_corpus.py --ecosystem pypi --limit 3000
python scripts/refresh_corpus.py --ecosystem crates --limit 1500
```

Quarterly is plenty. Note that npm's search API is lossy — it omitted `lodash`,
`jscodeshift`, and `react-codemod` from an 11,000-name harvest — so
`data/must_include.json` is merged in unconditionally.

## Frequently asked questions

### Does pkgguard scan package contents for malware?

No. pkgguard verifies the **name**, before installation. Content scanning is a
different layer — pair it with a tool that does that. pkgguard covers the
pre-install window that content scanners largely do not.

### Which ecosystems are supported?

npm, PyPI, and crates.io. npm and crates.io expose download counts directly,
while pkgguard supplements PyPI metadata with pypistats.org's recent-download
API. Registry availability and the quality of each ecosystem's metadata still
affect confidence.

### Does it need an API key or a paid data feed?

No. All three registries expose free, unauthenticated, public JSON APIs. That is
deliberate — it keeps the tool free to run and free to self-host.

### Can it run offline?

Partially. The popularity corpora ship with the repo, so conflation and
typosquat matching work offline. Existence and reputation checks require
registry access.

### Why does it block a package that doesn't exist yet?

Because a nonexistent name is not permanently safe. Models reproduce the same
hallucinations across runs, so an unclaimed hallucinated name is a standing
target an attacker can register tomorrow.

### Will it flag my legitimate new package?

Possibly, as `REVIEW` — not `BLOCK`. A genuinely new, low-adoption package that
blends common tokens looks structurally similar to a slopsquat. That is the
intended trade-off, not a bug. Established packages with real release history
are not flagged.

### Is pkgguard free to use commercially?

Yes. pkgguard is released under Apache License 2.0, including for commercial
CI/CD, internal developer platforms, hosted services, and products. Review the
[LICENSE](./LICENSE) for the complete terms.

### How is this different from Socket, Snyk, or Aikido?

Those scan installed dependencies for malicious *behavior*. pkgguard analyzes
the *name* before install, and specifically detects conflation — the blend
pattern that similarity-based scanners structurally miss. Complementary, not a
replacement.

## Limitations

Read these before relying on it.

- **Conflation cannot distinguish a hallucination from a legitimate new
  package** that blends common tokens. This is why it is gated behind
  reputation.
- **The known-hallucination corpus holds only 3 entries**, because it contains
  only names with a citable public source. Do not pad it with guesses — a false
  entry produces a confident, wrong `BLOCK`.
- **Download statistics are supplemental.** pypistats.org can be unavailable
  or delayed, so PyPI decisions fall back to reputation signals when needed.
- **This is one layer of defense**, not a complete supply-chain security
  program.

## License

pkgguard is released under the **Apache License 2.0**, a permissive,
commercially friendly open-source license with an explicit patent grant.

---

**Built by [Blvkware](https://blvkware.dev)** — solo-built developer and
security tooling.
