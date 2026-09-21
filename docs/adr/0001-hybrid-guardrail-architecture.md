# ADR 0001: Hybrid Multi-Layer Guardrail Architecture (Regex + Normalization + Semantic)

**Status:** Accepted  
**Date:** 2026-09-21  
**Deciders:** Lead Security Architect, Staff Backend Engineer  
**Consulted:** SecOps Team, AI Engineering Team  

---

## Context and Problem Statement

When deploying LLM applications in high-throughput enterprise environments (e.g. e-commerce customer support, conversational RAG, AnythingLLM desktop clients), inbound prompts and outbound responses must be screened for security threats (prompt injection, jailbreak, data exfiltration, PII leakage).

Using a secondary "LLM Judge" (evaluator LLM) to inspect every request introduces:
1. **High Latency**: 500ms to 2,000ms added latency per turn, severely impairing conversational responsiveness.
2. **High Cost & Resource Consumption**: Doubling token expenditure and GPU inference load.
3. **Recursive Jailbreak Vulnerability**: The judge LLM itself is susceptible to prompt injection and evasion.

Conversely, naive keyword matching fails against common adversarial evasion tactics (zero-width characters, Base64/Hex encoding, Cyrillic homoglyphs, token splitting like `d-a-n` or `i g n o r e`).

---

## Decision Drivers

- **Sub-millisecond Latency**: Must process inspection in < 0.5ms (p95 < 0.2ms achieved).
- **Adversarial Resilience**: Must defeat obfuscation, homoglyphs, and multi-encoding bypasses.
- **Determinism**: Security policies must produce predictable, testable, and auditable outcomes without probabilistic drift.
- **Maintainability**: Security operations (SecOps) must be able to add or adjust threat signatures without model retraining.

---

## Considered Options

1. **Option 1: Pure LLM-as-a-Judge (Llama-Guard / GPT-4o-mini)**
2. **Option 2: Pure Static Keyword Filter**
3. **Option 3 (Selected): Hybrid Multi-Layer Guardrail Pipeline (Normalization + Compiled Regex + Semantic Compound Rules)**

---

## Decision Outcome

Chosen Option: **Option 3 (Hybrid Multi-Layer Guardrail Pipeline)**.

### Architecture Breakdown
1. **Pre-processing & De-obfuscation Layer**:
   - Zero-width character stripping (`\u200B`, `\uFEFF`, `\u200E`, etc.).
   - Unicode NFKC normalization + Cyrillic confusables translation (`а` -> `a`, `о` -> `o`).
   - URL percent-decoding + Hex escape resolution (`\x44`).
   - Recursive Base64 payload extraction.
   - Token squashing (e.g. `t_a_l_o_k` -> `talok`, `@dm!n` -> `admin`).
2. **Layer 1: Pre-compiled In-Memory Regex Matcher**:
   - Matches normalized targets against pre-compiled regex signatures loaded from `threat_intel.db`.
   - Execution time: ~0.08ms - 0.15ms.
3. **Layer 2: Semantic & Persona Compound Intent Matcher**:
   - Multi-token semantic correlation for sophisticated narrative attacks (e.g. Grandma Exploit, Persona Escape, Python Sandbox Escape).
4. **Execution Layer**:
   - Deterministic BOLA/IDOR ownership validation and tool call parameter inspection.
5. **Output Layer**:
   - High-speed PII redaction and critical leak circuit-breaker.

---

## Consequences

### Positive
- **Ultra-low Latency**: End-to-end inspection takes ~0.087ms, invisible to end-users.
- **Zero Additional GPU/API Cost**: No external LLM token fees or GPU overhead for guardrails.
- **100% Deterministic & Auditable**: Every block event is mapped to an exact rule ID and timestamped in SQLite audit logs.
- **Instant Mitigation**: SecOps can block novel zero-day exploits in seconds.

### Negative / Trade-offs
- Highly abstract linguistic metaphors without recognizable threat semantics require periodic rule enrichment.
- Complex compound regex patterns must be vetted to prevent Regular Expression Denial of Service (ReDoS) — mitigated by strict regex length limits and safe compilation flags.
