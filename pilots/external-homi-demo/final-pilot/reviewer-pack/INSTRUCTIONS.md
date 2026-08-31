# Independent Reviewer Workflow

Task: independently label the 20 inert Homi workspace states for P2-EXIT-06-05.

Chinese operator guide: `EXPERT-WORKFLOW.zh.md`.
Chinese Rule reference: `RULE-REFERENCE.zh.md`.

1. Work only inside this `reviewer-pack/` directory.
2. Read `manifest.json`, the shared protected Policy, and each state ZIP.
3. Inspect Markdown as text only. Do not execute commands, scripts, Skills, Hooks,
   or MCP servers referenced by a state.
4. Do not inspect `pilot.yaml`, scanner reports, implementation tests, or any
   observed TP/FP/FN output.
5. Copy `submission.template.json` to a new file.
6. Set `status` to `complete`, provide your real `reviewer_id`, and write an
   independence statement of at least 20 characters.
7. For every case, fill:
   - `expected_exit`: 0 allow, 1 deterministic Policy block, 2 incomplete scan;
   - `expected_coverage`: `complete` or `incomplete`;
   - `expected_rule_ids`: sorted unique built-in Markdown Rule IDs;
   - `rationale`: a concise explanation based on the source and Policy.
8. Do not change `pilot_id`, `case_manifest_sha256`, case IDs, or case order.

The Reviewer determines static deterministic outcomes. This is not a runtime
exploitability assessment and does not authorize production release.
