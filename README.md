# Guardian Pre-Execution Supervision

This repository contains the experimental artifacts for a study of independent
pre-execution supervision of tool-capable autonomous agents.

The experiments evaluate whether a Guardian operating at the pre-execution
boundary can independently allow, veto, or escalate Worker-proposed operations
using security state and policy maintained outside the Worker.

## Experimental Environment

The experiments were conducted in a dedicated macOS virtual machine under UTM.

- Autonomous-agent platform: OpenClaw 2026.7.1-2
- Worker base model: `openai/gpt-5.6-terra`
- Agent runtime: OpenAI Codex
- Worker capabilities: file, command, and network-capable operations

## Repository Structure

- `artifacts/` — artifacts collected from experimental runs, including
  `RESULT.txt` records, execution traces, logs, and implementation snapshots.
- `experiments/` — experimental trials, intermediate snapshots, provenance
  records, Guardian decisions, and SHA-256 manifests.
- `guardian/` — rule-based and provenance-aware Guardian implementations.
- `guardian-monitor-scaffold/` — pre-execution Guardian monitor implementation.
- `guardian-monitor-scaffold-before-informed-authorization/` — implementation
  snapshot preceding the informed-authorization extension.
- `context-monitor-scaffold/` — context-monitoring implementation used in the
  comparison experiments.
- `llm-guardian-scaffold/` — LLM-based Guardian implementation used in the
  comparison experiments.
- `observer/` — event normalization and observation components.
- `openclaw-plugin/` — OpenClaw integration code.
- `protected/` — synthetic protected resources used in the experiments.
- `workspace/` — synthetic workspace resources and execution markers.
- `results/` — consolidated experimental results and result-generation scripts.

## Experimental Artifacts

The repository includes artifacts for the supervision approaches and failure
families evaluated in the study. Individual experimental directories preserve
the corresponding result records, relevant runtime traces, Guardian decisions,
provenance state, and implementation snapshots where applicable.

The informed-authorization extension additionally includes traces for
authorization release, replay prevention, and non-overridable
provenance-based veto behavior.

## Artifact Sanitization

The public artifacts have been sanitized to remove environment-specific
personal information and credentials while preserving the experimental
behavior represented by the records.

- Local absolute paths were normalized from the original user-specific path to
  `/Users/USER/...`.
- The experimental VM hostname was normalized to `guardian-vm`.
- Environment-specific `openclaw.json` files are intentionally excluded
  because they contain account and credential configuration.
- Authorization tokens in the informed-authorization traces were consistently
  replaced with `AUTH_TOKEN_1` and `AUTH_TOKEN_2`. Token identity and replay
  relationships are preserved.
- Credentials under `protected/`, such as the example API key and password,
  are synthetic, nonfunctional test data created specifically for the study.
- SHA-256 manifests were regenerated for the published sanitized artifacts.

These transformations affect identifying or environment-specific values only;
they do not change the experimental decisions or reported outcomes.

## Reproducibility

SHA-256 manifests are provided with experimental snapshots where applicable.
The hashes correspond to the sanitized copies published in this repository.

Some implementation snapshots preserve environment-specific experimental
configuration in normalized form, such as `/Users/USER/...`. These snapshots
are retained as experimental evidence and may require path configuration when
used in another environment.

## Security Notice

This repository does not contain the original OpenClaw configuration files or
operational credentials. Values explicitly labeled as fake or test credentials
are synthetic resources used to exercise the Guardian policies.
