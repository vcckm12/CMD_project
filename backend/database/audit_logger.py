# -*- coding: utf-8 -*-
"""
[audit_logger.py - SQLite 실시간 보안 감사 로깅 모듈]
- 모든 인바운드/아웃바운드 LLM 요청, 가드레일 차단 내역, 개인정보 마스킹 이벤트를 영구 데이터베이스에 실시간 적재합니다.
- 관리자 및 관제 화면(Streamlit)에서 위협 통계(방어율, 지연시간 등)를 산출하기 위한 쿼리 메서드를 제공합니다.
"""

import sqlite3
import os
import json
import time
from typing import Dict, Any, List
from backend.config import settings

class AuditLogger:
    """
    보안 감사 데이터베이스(security_audit.db) 관리 및 로그 입출력 클래스
    """
    def __init__(self, db_path: str = None):
        """
        초기화 메서드: DB 경로 지정 및 테이블 자동 생성
        - db_path: DB 파일 경로 (기본값: database/security_audit.db)
        """
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "security_audit.db")
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """
        데이터베이스 테이블 초기화 (최초 1회 실행)
        - audit_logs: 요청 원문, 판정 결과, 차단 계층, 지연시간 등을 저장하는 메인 감사 테이블
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,        -- 고유 로그 ID
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, -- 이벤트 발생 일시
                    user_prompt TEXT,                           -- 사용자 입력 프롬프트 원문
                    response_text TEXT,                         -- 최종 반환된 응답 (차단 시 빈값 또는 경고문)
                    status TEXT,                                -- 상태 ('passed', 'blocked', 'success', 'bypassed_off')
                    guardrail_enabled INTEGER,                  -- 가드레일 활성화 여부 (1: ON, 0: OFF)
                    violation_type TEXT,                        -- 탐지된 위반 유형 (예: OWASP_LLM01)
                    matched_rule TEXT,                          -- 탐지된 세부 보안 룰 이름
                    blocked_layer TEXT,                         -- 차단된 계층 (Input_Guardrail / Output_Guardrail)
                    latency_ms REAL,                            -- 총 처리 지연시간(ms)
                    masked_rules TEXT                           -- 마스킹 적용된 룰 목록 (JSON 직렬화)
                )
            """)
            conn.commit()

    def log_event(self, prompt: str, response: str, status: str, guardrail_enabled: bool,
                  violation_type: str, matched_rule: str, blocked_layer: str, latency_ms: float, masked_rules: list):
        """
        보안 이벤트 단건 실시간 INSERT 기록 메서드
        - Streamlit 및 AnythingLLM 요청이 발생할 때마다 비동기/동기 즉시 호출됨
        """
        # Audit metadata is retained by default, but raw prompt/response content is opt-in
        # because it can itself contain personal or confidential information.
        if not settings.audit_log_raw_content:
            prompt = "[REDACTED_BY_RETENTION_POLICY]"
            response = "[REDACTED_BY_RETENTION_POLICY]" if response else ""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_logs 
                    (user_prompt, response_text, status, guardrail_enabled, violation_type, matched_rule, blocked_layer, latency_ms, masked_rules)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    prompt, 
                    response, 
                    status, 
                    1 if guardrail_enabled else 0,
                    violation_type, 
                    matched_rule, 
                    blocked_layer, 
                    latency_ms, 
                    json.dumps(masked_rules or [])
                ))
                conn.commit()
        except Exception as e:
            # 로깅 실패로 인해 메인 LLM 서비스가 중단되지 않도록 예외 캡처
            print(f"[AuditLogger Error] 감사 로그 기록 실패: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """
        실시간 보안 통계 지표 집계 메서드 (대시보드용)
        - 총 요청 수, 차단 수, 마스킹 수, 방어율(%), 평균 및 P95 지연시간(ms) 계산
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # 1. 전체 누적 요청 수 조회
            cursor.execute("SELECT COUNT(*) FROM audit_logs")
            total = cursor.fetchone()[0]

            # 2. 입력단에서 즉시 차단(blocked)된 요청 수
            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status='blocked'")
            blocked = cursor.fetchone()[0]

            # 3. 출력단에서 개인정보가 마스킹(masked)된 요청 수
            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status='success' AND guardrail_enabled=1 AND masked_rules != '[]' AND masked_rules IS NOT NULL")
            masked = cursor.fetchone()[0]

            # 4. 보안 위협이 없는 순수 정상 요청 수
            clean_success = total - blocked - masked

            # 5. 지연시간(Latency) 백분위수 분석
            cursor.execute("SELECT latency_ms FROM audit_logs WHERE latency_ms IS NOT NULL ORDER BY latency_ms ASC")
            all_lats = [r[0] for r in cursor.fetchall()]

            if all_lats:
                avg_lat = sum(all_lats) / len(all_lats)
                min_lat = all_lats[0]
                max_lat = all_lats[-1]
                # P95 (95%의 요청이 이 시간 이내에 처리됨)
                p95_idx = int(len(all_lats) * 0.95)
                p95_lat = all_lats[min(p95_idx, len(all_lats) - 1)]
            else:
                avg_lat = min_lat = max_lat = p95_lat = 0.0

            # 6. 방어 계층별(Input vs Output) 차단 건수 집계
            cursor.execute("SELECT blocked_layer, COUNT(*) FROM audit_logs WHERE blocked_layer IS NOT NULL GROUP BY blocked_layer")
            by_layer = dict(cursor.fetchall())

            # 7. 위반 유형별(OWASP_LLM01, OWASP_LLM02 등) 탐지 건수 집계
            cursor.execute("SELECT violation_type, COUNT(*) FROM audit_logs WHERE violation_type IS NOT NULL GROUP BY violation_type")
            by_type = dict(cursor.fetchall())

            # 8. 총 방어율 계산 ((차단 건수 + 마스킹 건수) / 총 요청 수)
            defense_cnt = blocked + masked
            defense_rate = (defense_cnt / total * 100) if total > 0 else 100.0

            return {
                "total_requests": total,
                "blocked_requests": blocked,
                "masked_requests": masked,
                "clean_success_requests": max(0, clean_success),
                "defense_rate": round(defense_rate, 2),
                "avg_latency_ms": round(avg_lat, 3),
                "p95_latency_ms": round(p95_lat, 3),
                "min_latency_ms": round(min_lat, 3),
                "max_latency_ms": round(max_lat, 3),
                "blocked_by_layer": by_layer,
                "violations_by_type": by_type
            }

    def get_recent_logs(self, limit: int = 50, offset: int = 0, status_filter: str = None) -> List[Dict[str, Any]]:
        """
        최근 감사 로그 목록 페이징 조회 메서드
        - limit: 가져올 최대 행 수 (기본 50개)
        - offset: 페이지 오프셋
        - status_filter: 특정 상태값('blocked', 'success' 등) 필터링
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row  # 컬럼명을 딕셔너리 키로 매핑
            cursor = conn.cursor()
            if status_filter:
                cursor.execute(
                    "SELECT * FROM audit_logs WHERE status=? ORDER BY id DESC LIMIT ? OFFSET ?", 
                    (status_filter, limit, offset)
                )
            else:
                cursor.execute(
                    "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?", 
                    (limit, offset)
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def clear_logs(self) -> int:
        """
        감사 로그 전체 초기화 (테스트 및 벤치마크 리셋용)
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM audit_logs")
            conn.commit()
            return cursor.rowcount
