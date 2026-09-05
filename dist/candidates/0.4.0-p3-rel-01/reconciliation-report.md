# P3-REL-03 Byte-level Candidate Artifact Reconciliation

- Status: `reconciled`
- Package: `0.4.0`
- Source inventory SHA-256: `76dec9847464a2bcb8b1788dcd74509d4b202ac269b058b7a82931d76309e4dc`
- Candidate directory: `dist/candidates/0.4.0-p3-rel-01`

## Result

All current `src/agentsec` Python modules, JSON Schemas, and release
metadata are byte-for-byte identical to their copies in the newly built
candidate artifacts. The preserved historical candidate was not
overwritten.

## Artifact checks

- source_package_files_in_wheel: `True`
- source_package_files_in_sdist: `True`
- schemas_in_sdist: `True`
- required_attack_graph_files_in_wheel: `True`
- required_reconciliation_files_in_sdist: `True`
- metadata_version: `True`
- console_script: `True`
- wheel_content_matches_source: `True`
- sdist_content_matches_source: `True`
- schemas_match_source: `True`
- metadata_matches_source: `True`

## Byte-level content evidence

- Archive member bytes are compared without printing source content.
- Mismatch evidence is limited to relative member paths.

## Installed CLI smoke

- version: `True`
- root_help: `True`
- attack_graph_help: `True`
- score_help: `True`
- attack_graph_json: `True`
- score_attack_path_context: `True`
- homi_context_risk: `True`
- homi_directional_drift: `True`
- homi_html_report: `True`

## Boundary

- The historical candidate remains immutable and separately addressable.
- The smoke test uses `--no-index`; no network or real Provider is used.
- Only inert static analysis commands are run; scanned project content is never executed.
- Artifact signatures and SLSA provenance remain `not_claimed`.

