# AI Guardrail Gateway Operations & Incident Response Runbook

**Target Audience:** SRE, SecOps, DevOps, On-Call Engineers  
**System:** AI Security Guardrail Gateway & E-Commerce Service  
**Version:** 1.0.0  
**Last Updated:** 2026-09-21  

---

## 1. System Overview & Architecture Diagram

The AI Guardrail Gateway provides real-time security inspection (< 0.2ms) on all user prompts and model responses.

- **FastAPI Gateway Service**: `http://localhost:8000` (Ingress, Guardrail execution, REST API)
- **Streamlit Security Operations Dashboard**: `http://localhost:8501` (Threat registry, Live analytics, Audit viewer)
- **E-Commerce Static Store & AI Widget**: `http://localhost:8000/store`
- **Internal Storage**: SQLite databases (`security_audit.db`, `threat_intel.db`, `shop.db`) using WAL mode.

---

## 2. Severity Level Definitions & Escalation Matrix

| Severity Level | Definition / Scenario | Response SLA | Action Required |
| :--- | :--- | :--- | :--- |
| **Sev-1 (Critical)** | Active Zero-Day Jailbreak bypass observed in production, customer PII dump, or gateway outage (> 5% 5xx errors). | < 15 minutes | Immediate signature deployment via Hot-Reload, enable fail-closed lock, engage SecOps Lead. |
| **Sev-2 (High)** | False Positive spike (> 5% of legitimate e-commerce user queries blocked), or average latency > 50ms. | < 1 hour | Adjust regex granularity in Threat Intel UI, inspect slow validator chains, reload rule cache. |
| **Sev-3 (Medium)** | SQLite lock contention warnings in logs, non-critical tool calling error, minor UI glitch in dashboard. | < 4 hours | Optimize DB maintenance vacuum, verify WAL checkpointing, review background task queues. |

---

## 3. Standard Operating Procedures (SOP)

### SOP-01: Deploying an Emergency Threat Signature (Zero-Day Mitigation)
*Scenario: A new prompt injection pattern is actively bypassing the gateway.*

1. **Option A: Via Admin UI (Fastest, < 30 seconds)**
   - Navigate to Streamlit Admin Dashboard (`http://localhost:8501`) -> **Threat Intel** tab.
   - Enter:
     - `Rule Name`: `RULE_EMERGENCY_2026_EXPLOIT`
     - `Target Layer`: `INPUT`
     - `Category`: `OWASP_LLM01`
     - `Regex Pattern`: `(?i)(bypass_pattern_here)`
     - `Description`: `Emergency zero-day signature mitigation`
     - `Severity`: `CRITICAL`
   - Click **"신규 위협 룰 등록 및 Hot-Reload 즉시 반영"**.
   - The signature is immediately compiled into in-memory cache without restarting FastAPI.

2. **Option B: Via REST API (CLI / Automated Bot)**
   ```bash
   curl -X POST "http://localhost:8000/api/v1/threats" \
     -H "Content-Type: application/json" \
     -H "X-Admin-Key: secret-admin-key-2026" \
     -d '{
       "rule_name": "RULE_EMERGENCY_2026_EXPLOIT",
       "target_layer": "INPUT",
       "category": "OWASP_LLM01",
       "regex_pattern": "(?i)(bypass_pattern_here)",
       "description": "Emergency zero-day patch",
       "severity": "CRITICAL"
     }'
   ```

3. **Verify Deployment**:
   ```bash
   python tests/threat_intel_test.py
   ```

---

### SOP-02: Handling False Positives (Unblocking Legitimate Customers)
*Scenario: Legitimate customer queries (e.g. asking about battery capacity) are falsely blocked as bomb-making.*

1. Open **Audit Logs** tab in Streamlit (`http://localhost:8501`).
2. Filter logs by `status = 'blocked'` and locate the false positive prompt.
3. Identify the `matched_rule` (e.g., `RULE_SEMANTIC_GRANDMA_EXPLOIT` or a specific DB regex ID).
4. Go to **Threat Intel** tab, search for the rule, and either:
   - Edit the regex pattern to be more specific (negative lookahead or stricter token bounding).
   - Deactivate the rule temporarily by setting `is_active = false`.
5. Click **Reload Rules Cache** to flush and update in-memory matcher.

---

### SOP-03: Disaster Recovery & Database Maintenance
*Scenario: Database corruption, SQLite lock timeout, or log size exceeding disk quota.*

1. **Check Database Health & Integrity**:
   ```bash
   sqlite3 backend/database/security_audit.db "PRAGMA integrity_check;"
   sqlite3 backend/database/threat_intel.db "PRAGMA integrity_check;"
   sqlite3 backend/database/shop.db "PRAGMA integrity_check;"
   ```
2. **Vacuum & WAL Checkpoint**:
   ```bash
   sqlite3 backend/database/security_audit.db "PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"
   ```
3. **Log Archival**:
   - Rotate older audit logs by dumping records older than 90 days to JSONL cold storage:
   ```bash
   python -c "from backend.database.audit_logger import AuditLogger; logger = AuditLogger(); logger.clear_logs()"
   ```

---

## 4. Health Checks & Monitoring Endpoints

| Endpoint | Method | Expected Output | Purpose |
| :--- | :--- | :--- | :--- |
| `/api/v1/health` | `GET` | `{"status": "healthy", "components": {"guardrail_engine": "ok", ...}}` | Liveness & Readiness probe for Kubernetes / Load Balancer |
| `/api/v1/guardrail/status` | `GET` | `{"enabled": true}` | Verify fail-closed guardrail active status |
| `/api/v1/audit/stats` | `GET` | `{"defense_rate": 99.5, "avg_latency_ms": 0.12, ...}` | Prometheus / Grafana metrics scraper |
| `/api/v1/threats` | `GET` | `[{"rule_name": "...", "is_active": true}, ...]` | Configuration audit check |
