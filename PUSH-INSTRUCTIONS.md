# Pushing this repo to GitHub

The repository is initialized and the v0.1.0 commit is already made. You just
need to create the remote and push.

## 1. Create an empty repo on GitHub

Go to https://github.com/new

- **Name:** `pkgguard`
- **Description:** `Detect slopsquatting and AI-hallucinated package names before install. npm, PyPI, crates.io. 1% false positives, 7/7 threat recall.`
- **Public**
- **Do NOT** initialize with a README, .gitignore, or license — this repo already has them.

## 2. Push

```bash
cd pkgguard
git remote add origin https://github.com/rxslice/pkgguard.git
git branch -M main
git push -u origin main
```

## 3. Set repo topics (this is the SEO step that matters most on GitHub)

GitHub topics drive in-platform discovery. In the repo, click the gear icon
next to "About" and add:

```
slopsquatting  supply-chain-security  typosquatting  package-hallucination
llm-security  ai-security  devsecops  npm  pypi  crates-io
dependency-confusion  security-tools  cicd  python
```

Also set the **About** description and the website field to `https://blvkware.dev`.

## 4. Optional but high-leverage

- Enable **Discussions** — the FAQ in the README seeds real questions.
- Add a **release** tagged `v0.1.0` so the repo shows a version.
- The three highest-value places to post this, where the audience already
  has the problem: `r/netsec`, Hacker News (Show HN), and the
  `lobste.rs` security tag. Lead with the 62.5% → 1.0% false-positive
  story, not the feature list — that's the part that earns credibility with
  a security audience.
