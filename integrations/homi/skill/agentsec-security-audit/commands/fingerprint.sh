#!/usr/bin/env bash
set -u

# Print the AgentSec package/build identity before a Homi scan.  This command
# does not inspect or execute the target workspace.
exec agentsec homi fingerprint --format json
