# P2-24 Scoring Replay Corpus

`expected.json` is the frozen compact replay output for seven deterministic
Agentic scoring scenarios:

```text
safe no-change
risky default context
risky reviewed context
remediation drift
incomplete Coverage
CVSS high-water mark
Critical Hard Gate floor
```

Regenerate deliberately:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-scoring-replay.py \
  --output testdata/scoring-replay/expected.json
```

Verify without writing:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-scoring-replay.py --check
```

The artifact contains only scores, versions, hashes, Gate metadata, and bounded
context. It does not contain raw source values and does not execute scanned
content.
