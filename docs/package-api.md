# AgentSec Supported Python API

The supported Python API for the 0.4.x development line is exposed from
`agentsec.api`. Internal module paths are implementation details unless they are
listed here or in a task-specific contract.

```python
from agentsec.api import (
    AgentAnalysisPipeline,
    AgentAnalysisRequest,
    DeterministicHomiReportOnlyPilot,
    DeterministicHomiSafeSimulationEngine,
    ExitCode,
    HomiAdapter,
)
```

## Supported surfaces

```text
agentsec.__version__
agentsec.api
agentsec.cli
agentsec.exit_codes
agentsec.frameworks     adapter/profile/combination/simulation/pilot contracts
agentsec.application    analysis orchestration contracts
```

The package contains `agentsec/py.typed` and declares it as package data. Type
checkers may therefore consume the shipped annotations. The API does not imply
runtime authorization: all Homi analysis and simulation contracts remain static
or report-only.

## Compatibility policy

- Public symbols in `agentsec.api` are supported for the 0.4.x line.
- Versioned schemas and report formats retain their own compatibility contracts.
- `src/agentsec/*` implementation modules not re-exported by `agentsec.api` may
  change without a public API guarantee.
- `agentsec.cli` is the supported command surface; CLI exit codes are also
  available from `agentsec.exit_codes` without importing CLI initialization.
- LLM output, if added later, remains candidate evidence and is not part of the
  authorization API.
