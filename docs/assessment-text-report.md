# Safe Assessment Rich Text Reporter

- Task: `P1-24`
- Status: Complete
- Decision date: 2026-08-19
- Domain Schema: `0.3.0`
- Risk Model: `0.4.0`
- Decision record:
  `docs/decisions/0013-assessment-text-report-and-version-metadata.md`

## 1. Purpose

`AssessmentTextRenderer` converts an already-built final Domain `Assessment`
into deterministic, human-readable terminal text. It is a delivery boundary:
it does not discover files, run Rules, calculate risk, decide CI policy, or
execute any content found in the scanned project.

The P1-24 public seam is:

```python
from agentsec.reporting import AssessmentTextRenderer

text = AssessmentTextRenderer().render(assessment)
```

The method returns `str`. It does not print, write files, launch subprocesses,
open network connections, import scanned code, invoke Skills or MCP servers, or
call an LLM.

## 2. Report structure

The report is organized into these sections:

1. **AgentSec Assessment**
   - target root;
   - `COMPLETE` or `INCOMPLETE` Coverage status;
   - explicit `report-only; CI risk blocking is disabled` policy.
2. **Summary**
   - asset and change counts;
   - total Finding count;
   - highest Severity;
   - counts by Severity and Evidence Confidence;
   - matched Hard Gate count;
   - discovered, scanned, skipped, and Coverage Issue counts.
3. **Version and provenance**
   - scanner/package version;
   - Config Schema version;
   - Domain Schema version;
   - Rule Pack version;
   - Risk Model version;
   - start and completion timestamps;
   - Git commit and dirty state when known.
4. **Coverage warning and details**
   - emitted whenever `ScanCoverage.complete` is false;
   - states that Findings are partial and the result is not a clean pass;
   - lists Issue code, Asset or scan-wide scope, and safe reason;
   - reports any Issue details omitted by the Text limit.
5. **Finding details**
   - Finding and Rule IDs;
   - category, score, Severity, likelihood, impact, and Confidence;
   - Hard Gate match state with report-only wording;
   - description;
   - Evidence source, location, field, SHA-256, and redacted excerpt;
   - recommended follow-up.

When no Finding exists, the report says that no Finding was produced in the
supported scan scope and that this does not prove global Agent safety.

## 3. Deterministic ordering

Finding details are sorted by:

```text
Severity descending
→ score descending
→ Rule ID
→ first Evidence asset path
→ first Evidence start line
→ Finding ID
```

The summary is calculated over all Findings, including details omitted by an
output limit. Reordering the input tuple therefore does not change report text.

## 4. Terminal-safety controls

Repository-derived text is untrusted data. Before Rich sees a value, the
renderer:

1. applies `SecretRedactor`;
2. escapes backslashes and newline/tab/carriage-return characters;
3. escapes ANSI and other control characters;
4. escapes zero-width, bidi, surrogate, and other format characters;
5. passes the value to `rich.text.Text`, never Rich markup.

The internal `Console` uses:

```text
color_system=None
force_terminal=False
markup=False
highlight=False
fixed console width
```

The returned string is ANSI-free. Bracketed source text such as
`[bold]untrusted[/bold]` remains literal text rather than becoming formatting.

Redaction occurs before escaping so a detected secret value is replaced rather
than preserved in an escaped form. P1-26 adds normalized mapped detection,
contextual and provider-token patterns, private-key handling, and multiline
fail-closed behavior; see `docs/secret-redaction.md`. Paths, titles,
descriptions, Evidence
excerpts, recommendations, version strings, and available Git text all pass
through the safe-text boundary where applicable.

## 5. Output limits

`AssessmentTextLimits` provides immutable positive bounds:

| Limit | Default | Meaning |
|---|---:|---|
| `max_findings` | `100` | Maximum Finding detail panels |
| `max_evidence_per_finding` | `10` | Maximum Evidence panels per Finding |
| `max_recommendations_per_finding` | `10` | Maximum recommendations per Finding |
| `max_coverage_issues` | `100` | Maximum Coverage Issue detail rows |
| `max_text_characters` | `512` | Maximum sanitized characters retained per value before a visible suffix |
| `console_width` | `120` | Deterministic Rich layout width; allowed range is 80–240 |

The renderer prints warnings for omitted Findings, Evidence, recommendations,
and Coverage Issue details. Truncated text includes its original sanitized character count.
No omission is represented as complete output.

## 6. Severity, Confidence, and Hard Gates

These concepts remain independent:

- **Severity** represents risk magnitude.
- **Evidence Confidence** represents evidence strength.
- **Hard Gate matched** means a deterministic risk floor matched.
- **CI blocked** is an enforcement decision that is disabled in Phase 1.

A Critical Finding with Confidence D remains Critical. A matched Hard Gate is
rendered as:

```text
MATCHED (report-only; no CI block)
```

The report never infers enforcement from `Finding.hard_gate`.

## 7. Version provenance

P1-24 adds these required fields to `AssessmentMetadata`:

```text
config_schema_version
risk_model_version
```

This changes Domain Schema from `0.2.0` to `0.3.0`. The renderer displays values
retained on the Assessment; it does not read current process constants while
rendering. This prevents a stored Assessment from being mislabeled after a
future Config Schema or Risk Model upgrade.

## 8. Current integration boundary

P1-29 now invokes this renderer from `agentsec scan` after the complete
Rule/Risk/Confidence/Hard Gate pipeline. Text is the secure default and may be
selected explicitly with `--format text`; JSON remains independently versioned.

P1-25 provides the Assessment JSON Reporter, P1-26 provides shared hardened
redaction, and P1-27 provides sorted bounded Coverage Issue details. P1-29 does
not add `--fail-on`, CI risk blocking, SARIF, HTML, or production Hard Gate
combination detectors.

## 9. Verification coverage

P1-24 tests assert:

- readable empty and non-empty reports;
- deterministic output independent from Finding input order;
- Severity-first ordering and summary counts;
- direct Evidence for High and Critical-style results;
- separate Confidence and Hard Gate presentation;
- explicit report-only wording;
- secret redaction and escaping of ANSI, bidi, zero-width, bracketed markup, and
  newline-bearing text;
- visible incomplete Coverage warnings and sorted Issue code/path/reason detail;
- visible Coverage Issue omission and missing-structured-reason states;
- visible Finding, Evidence, recommendation, and text limits;
- no file, shell, or network side effects;
- rejection of invalid limits and non-Assessment input;
- deterministic strict Domain Schema export with the new required metadata.

## P2-26 explicit fail-on Text context

`agentsec scan --fail-on high|critical` prepends a trusted deterministic decision
summary and changes the Assessment header from report-only to explicit local
exit-code policy. The Finding, Evidence, Confidence, Hard Gate, Coverage, and
redaction sections remain unchanged. See `docs/fail-on.md`.
