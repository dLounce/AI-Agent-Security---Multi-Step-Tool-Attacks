# SUBMISSIONS LOG — Kaggle 134815

## How do we know which submission scored what? (the 20/day problem)

Kaggle does track every submission individually — the leaderboard only *displays* your
best, but the **"Submissions" tab** (on the competition page → "Submissions", or your
notebook's "Submit" history) lists **every** submission with:
- its **public score**,
- the **timestamp**, and
- the **Description** you typed at submit time.

The private score stays hidden until the competition/deadline, then appears in the same
table. So attribution is entirely on us using the Description field + this log. Rules we
follow so 20/day stays interpretable:

1. **Bump `VERSION`** at the top of `attack.py` every time the code changes.
2. **Run `git_sync.ps1` before each submit** → gives a commit hash pinning exact code.
3. **Submit Description = `"<VERSION> | <one-line change> | <commit7>"`**
   e.g. `v3 | authority framing + base64 family | a1b2c3d`.
4. **Change ONE variable per submission** (template framing, MESSAGES_PER_CANDIDATE,
   family, probe fraction). If you change five things, the score tells you nothing.
5. **Log the row below** when Kaggle shows the public score. Fill private after deadline.

Tip: reserve a couple of the 20/day as controlled A/Bs (same code, re-run) to gauge
run-to-run variance before trusting a small score delta.

## Log

| # | date | VERSION | commit | one change vs prev | public (gpt_oss/gemma or LB) | private | notes |
|---|------|---------|--------|--------------------|------------------------------|---------|-------|
| 0 | 2026-08-1x | (pre-us) | — | prior attack.py | ~86 | ? | baseline before this workstream |
| 1 | | v1 | | adaptive probe + 12-template bank (SECRET_MARKER + base64) | | | first submit of our approach |
|   | | | | | | | |

## Per-model reading

The competition scores each model (gpt_oss, gemma) and guardrail (public, private)
separately, then combines. Watch the split:
- **public high, private low** → private guardrail blocks the sentinel post → pivot to
  family B (read + base64/hex) and/or new evasion.
- **gpt_oss high, gemma low (or vice-versa)** → template compliance differs by model →
  keep per-model template subsets (attack.py auto-probes, but seed the bank well).
- **both low** → likely low compliance or wasted hops → use `calibrate.py` to find
  templates the model actually follows.
