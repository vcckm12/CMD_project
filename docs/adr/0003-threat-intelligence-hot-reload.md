# ADR 0003: In-Memory Pre-compiled Threat Intelligence with Zero-Downtime Hot-Reload

**Status:** Accepted  
**Date:** 2026-09-21  
**Deciders:** Lead Security Architect, Staff Backend Engineer  

---

## Context and Problem Statement

Security threats against LLMs evolve rapidly. Novel zero-day jailbreak prompts and attack payloads emerge frequently. In high-availability enterprise services, deploying new security rules must not require:
1. Re-deploying or restarting backend containers/pods (which causes connection drops or startup latency).
2. Querying SQLite/SQL databases synchronously on every inbound character (which introduces disk I/O bottlenecks and lock contention).

---

## Decision Drivers

- **Zero-Downtime Updates**: SecOps must be able to push new signatures and activate them instantly.
- **Sub-0.1ms Lookup Time**: Evaluation must run completely in RAM using pre-compiled regex automata.
- **Persistence & Synchronization**: Signatures must persist across reboots and sync bidirectionally with regression test suites (`datasets/attack_payloads_100.jsonl`).

---

## Decision Outcome

1. **Two-Tier Storage Architecture**:
   - **Persistent Tier**: SQLite database (`threat_intel.db`) storing full threat metadata (rule name, regex pattern, category, target layer, severity, description, active status).
   - **Execution Tier**: In-memory array of pre-compiled `re.Pattern` objects inside `InputGuardrailEngine` and `OutputGuardrailEngine`.

2. **Event-Driven Hot-Reload Mechanism**:
   - Whenever a signature is created, updated, or deleted via the Admin UI or `/api/v1/threats` REST endpoints, the server immediately calls `input_guardrail.reload_rules()` and `output_guardrail.reload_rules()`.
   - The reload process re-reads active rows from the database, pre-compiles valid regular expressions, and atomically swaps the memory reference (`self.compiled_rules = new_compiled`).

3. **Dataset Synchronization**:
   - `ThreatIntelDAO.sync_to_attack_dataset()` exports active signatures to `datasets/attack_payloads_100.jsonl` so CI/CD regression pipelines automatically evaluate new rules on every build.

---

## Consequences

### Positive
- Sub-millisecond execution: Zero database queries in the hot request path.
- Zero-downtime rule updates: Real-time defense against zero-day exploits.
- Safe compilation: Invalid regex syntax is trapped and logged without crashing the active engine.

### Negative / Trade-offs
- In multi-instance / clustered Kubernetes deployments, cache invalidation across pods requires a pub/sub mechanism (e.g. Redis Pub/Sub or Postgres LISTEN/NOTIFY), which is documented in the scaling roadmap.
