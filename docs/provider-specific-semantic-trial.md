# P3-04 Provider-Specific Adapter, Offline/Live Parity, and Semantic Trial CLI

- Status: Complete
- Date: 2026-08-31
- Mode: Shadow-only

P3-04 adds a concrete chat-style structured-JSON Provider adapter, strict
protected trial configuration/case/response contracts, Offline/Live parity
measurement, and the `agentsec semantic trial` CLI.

## Provider adapter

`OpenAICompatibleSemanticProvider` maps AgentSec's fixed System/Data/Schema
channels into a chat-style JSON request and accepts only
`choices[0].message.content` plus bounded usage counters. It uses no SDK,
requires HTTPS and an environment-variable credential reference, disables
redirects and inherited proxies, and remains behind explicit Provider/Model
allow-listing. The name describes the envelope implemented by AgentSec; it is
not a blanket compatibility claim for every service.

## Protected trial contracts

```text
semantic-trial-config.schema.json
semantic-trial-case-set.schema.json
semantic-trial-response-set.schema.json
semantic-parity-report.schema.json
```

Config files contain no credential value. Inputs are bounded regular non-symlink
UTF-8 JSON files. Unknown fields, oversized files, mismatched Analysis IDs, and
unapproved live bindings fail closed.

## CLI

Offline replay:

```bash
agentsec semantic trial \
  --cases cases.json \
  --responses responses.json \
  --provider offline_fixture \
  --format json \
  --output report.json
```

Protected config:

```bash
agentsec semantic trial --config protected-trial.json --format text
```

Live trials require all of:

```text
--provider openai_compatible
--endpoint HTTPS_URL
--credential-env ENV_NAME
--provider-id PROVIDER_ID
--model-id MODEL_ID
--allow-live
--approved-live-binding 'PROVIDER_ID|MODEL_ID'
```

No live request occurs by default. CLI output remains
`report_only=true`, `policy_authority=false`, `release_authority=false`, and
`runtime_verified=false`.

## Offline/Live parity

`SemanticParityHarness` runs identical sanitized cases through Offline and Live
Shadow adapters and reports:

```text
comparable cases
prediction parity rate
Evidence parity rate
safe failure codes
```

The report contains no source excerpts, credentials, endpoints, Prompt, or raw
Provider response. Parity does not promote a Provider or authorize Policy/CI.

## Limitations

- No endpoint or credential is checked in.
- No production Provider is declared qualified.
- The CLI does not publish Findings or Rules and cannot block CI.
- Transport cancellation remains bounded by the underlying HTTPS implementation.
- A real trial still requires reviewed data-residency, retention, cost, and
  human-evaluation approval.
