# ADR 0002: Fail-Closed Security Policy and Environment-Isolated Bypass

**Status:** Accepted  
**Date:** 2026-09-21  
**Deciders:** Lead Security Architect, Infrastructure Lead  

---

## Context and Problem Statement

During development, benchmark testing, and demonstrations, engineers often need to compare system responses with and without guardrail enforcement (A/B testing, demonstration of raw vulnerability vs defended output).

However, allowing arbitrary users to bypass security guardrails via query parameters, headers, or magic tokens in a production environment represents a critical architectural vulnerability (CWE-306, CWE-284).

---

## Decision Drivers

- **Zero-Trust Security**: Production environments must strictly enforce security guardrails on all incoming traffic with zero possibility of unauthorized bypass.
- **Developer & Demo Usability**: Local sandboxes and staging environments require a clean mechanism to toggle guardrail state for benchmarking and verification.
- **Fail-Closed Principle**: Any runtime exception, configuration ambiguity, or unexpected state must default to full security enforcement rather than open pass-through.

---

## Decision Outcome

1. **Environment Segregation (`ENV`)**:
   - In `production` (`ENV=production`), `ALLOW_DEMO_BYPASS` is forced to `False`.
   - Magic prefixes (e.g. `[OFF]`, `[BYPASS]`) and raw model aliases (`llama3-raw`) are ignored and treated as standard inputs subject to full guardrail inspection.
   - Admin APIs (`/api/v1/guardrail/toggle`, `/api/v1/threats`) require an authenticated `X-Admin-Key` header verified with constant-time equality check (`secrets.compare_digest`).

2. **Fail-Closed Default**:
   - If an error occurs during guardrail evaluation (e.g., database timeout or unhandled parsing exception), the system logs the error and safely blocks the request with a generic security notice rather than failing open.

3. **Deterministic State Resolution**:
   ```python
   def guardrail_is_active(req: ChatRequest, user_prompt: str, model: str) -> bool:
       if not settings.allow_demo_bypass:
           return True  # Fail-Closed in Production
       model_lower = model.lower()
       raw_model = any(t in model_lower for t in ("raw", "bypass", "off", "unprotected", "disable"))
       prompt_off = user_prompt.strip().lower().startswith(("[off]", "[bypass]", "[가드레일off]", "[가드레일 해제]"))
       return global_guardrail_state["enabled"] and req.guardrail_enabled and not raw_model and not prompt_off
   ```

---

## Consequences

### Positive
- Guarantees compliance with enterprise security requirements and prevents accidental exposure of vulnerable endpoints in production.
- Provides seamless demonstration capabilities in staging/development without contaminating production logic.

### Negative / Trade-offs
- Production testing of new guardrail rules requires canary deployments or shadow evaluation rather than live in-band bypass toggling.
