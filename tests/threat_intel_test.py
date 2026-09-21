# -*- coding: utf-8 -*-
"""
[threat_intel_test.py - 위협 인텔리전스 동적 룰 등록 및 Hot-Reload 검증 테스트]
- 외부 신규 공격 패턴을 threat_signatures 테이블에 등록
- InputGuardrailEngine이 재시작 없이 Hot-Reload하여 즉시 차단하는지 검증
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.database.threat_intel_dao import ThreatIntelDAO
from backend.guardrails.input_guardrail import InputGuardrailEngine


def test_dynamic_threat_addition_and_hot_reload():
    dao = ThreatIntelDAO()
    engine = InputGuardrailEngine(threat_dao=dao)

    test_attack_payload = "NEW_2026_ZERO_DAY_PAYLOAD_TEST_XYZ"
    test_rule_name = "RULE_ZERO_DAY_2026_XYZ"

    # 1. 등록 전: 차단되지 않아야 함 (Clean)
    is_blocked, vtype, rule, lat = engine.inspect(test_attack_payload)
    assert not is_blocked, "Pre-condition failed: payload should not be blocked before rule is added"
    print("[PASS] 1. Pre-registration: New zero-day payload is initially passed through.")

    # 2. 신규 외부 위협 시그니처 DB 등록
    sig_id = dao.create_signature({
        "rule_name": test_rule_name,
        "pattern": r"(?i)NEW_2026_ZERO_DAY_PAYLOAD_TEST_XYZ",
        "category": "OWASP_LLM01",
        "target_layer": "INPUT",
        "description": "2026년 9월 발견된 신규 제로데이 탈옥 공격",
        "sample_payload": test_attack_payload,
        "severity": "CRITICAL",
        "source": "EXTERNAL_INTEL",
        "is_active": True
    })
    assert sig_id > 0, "Failed to create signature"
    print(f"[PASS] 2. Threat signature created with ID: {sig_id}")

    # 3. 무중단 핫 리로드 실행
    reloaded_cnt = engine.reload_rules()
    assert reloaded_cnt > 0, "Reload rules returned 0"
    print(f"[PASS] 3. In-memory Hot-Reload executed: {reloaded_cnt} rules active.")

    # 4. 등록 후: 즉시 실시간 차단되어야 함
    is_blocked, vtype, rule, lat = engine.inspect(test_attack_payload)
    assert is_blocked, "Post-condition failed: payload must be blocked after hot-reload"
    assert test_rule_name in rule, f"Expected rule name {test_rule_name} in {rule}"
    print(f"[PASS] 4. Post-registration: Zero-day payload intercepted immediately! (Latency: {lat:.3f}ms, Rule: {rule})")

    # 5. 정리 (Clean-up)
    dao.delete_signature(sig_id)
    engine.reload_rules()
    print("[PASS] 5. Clean-up: Test rule removed and reloaded successfully.")
    print("\nALL DYNAMIC THREAT INTEL TESTS PASSED WITH 100% SUCCESS!")


if __name__ == "__main__":
    test_dynamic_threat_addition_and_hot_reload()
