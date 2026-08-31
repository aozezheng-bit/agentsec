# External Homi Agent Demo

This package contains report-only evidence derived from a user-supplied Homi
workspace export. The source ZIP and deployed Markdown are untrusted input and
were never executed.

Canonical evidence uses the P2-EXIT-06-03A calibrated Homi stack:

```text
Adapter                  0.2.0
Profile model            0.2.0
Pilot format             0.2.0
Simulation model         0.2.0
Heartbeat template       example_only
```

The baseline and ten PR/change snapshots remain `acceptance_ready=false` because
independent human labels, 20 total scans, Waiver evidence, and final external
Pilot acceptance are still pending.

Pre-calibration evidence is preserved under:

```text
review-history/pre-heartbeat-calibration-20260826/
```
