# ADR-0085: Provider-Specific Adapter, Parity, and Trial CLI

- Status: Accepted
- Date: 2026-08-31
- Task: P3-04

Implement one explicit chat-style structured JSON adapter without adding an SDK,
add strict protected trial file contracts, compare Offline and Live predictions
with value-free parity metrics, and expose an explicit `agentsec semantic trial`
command. Default operation is Offline replay; Live use requires a flag and exact
Provider/Model binding. All outputs remain Shadow-only and carry no Policy, CI,
Provider-promotion, runtime, or release authority.
