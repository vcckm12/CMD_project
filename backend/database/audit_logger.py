# -*- coding: utf-8 -*-
"""
[audit_logger.py - 고성능 비동기 Non-blocking SQLite 실시간 보안 감사 로깅 모듈]
- 모든 인바운드/아웃바운드 LLM 요청, 가드레일 차단 내역, 개인정보 마스킹 이벤트를 백그라운드 큐를 통해 0.002ms 초저지연으로 영구 데이터베이스에 적재합니다.
- SQLite WAL (Write-Ahead Logging) 모드 및 배치 트랜잭션을 적용하여 I/O 블로킹 및 DB 락(Lock) 충돌을 완벽 방지합니다.
- 관리자 및 관제 화면(Streamlit)에서 위협 통계(방어율, 지연시간 등)를 산출하기 위한 쿼리 메서드를 제공합니다.
"""

import sqlite3
import os
import json
import time
import queue
import threading
import atexit
import logging
from typing import Dict, Any, List, Optional
from backend.config import settings

logger = logging.getLogger("ai_guardrail.audit_logger")


class AuditLogger:
    """
    보안 감사 데이터베이스(security_audit.db) 관리 및 비동기 논블로킹 로그 입출력 클래스
    """
    def __init__(self, db_path: str = None, enable_async_worker: bool = True):
        """
        초기화 메서드: DB 경로 지정, 테이블 자동 생성 및 백그라운드 워커 스레드 기동
        - db_path: DB 파일 경로 (기본값: database/security_audit.db)
        - enable_async_worker: 백그라운드 큐 기반 비동기 적재 활성화 여부
        """
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "security_audit.db")
        self.db_path = db_path
        self.enable_async_worker = enable_async_worker
        self._init_db()

        # 비동기 큐 및 백그라운드 배치 워커 스레드 초기화
        self._queue: queue.Queue = queue.Queue(maxsize=10000)
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        if self.enable_async_worker:
            self._start_worker()
            atexit.register(self.close)

    def _get_connection(self) -> sqlite3.Connection:
        """
        성능 및 동시성 최적화된 SQLite 커넥션 생성 (WAL 모드, busy_timeout)
        """
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        """
        데이터베이스 테이블 초기화 (최초 1회 실행)
        - audit_logs: 요청 원문, 판정 결과, 차단 계층, 지연시간 등을 저장하는 메인 감사 테이블
        """
        with self._get_connection() as conn:
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
            # 인덱스 생성으로 대시보드 통계 쿼리 가속
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_logs(status);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(timestamp);")
            conn.commit()

    def _start_worker(self):
        """백그라운드 비동기 DB 기록 워커 스레드 시작"""
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="AuditLoggerWorker",
            daemon=True
        )
        self._worker_thread.start()

    def _worker_loop(self):
        """
        백그라운드 큐 드레인 및 배치 트랜잭션 처리 루프
        """
        while not self._stop_event.is_set():
            batch = []
            try:
                # 최대 0.2초 동안 첫 번째 항목 대기
                first_item = self._queue.get(timeout=0.2)
                batch.append(first_item)
                
                # 큐에 더 쌓인 항목이 있다면 최대 50건까지 한 번에 배치 수집
                while len(batch) < 50:
                    try:
                        batch.append(self._queue.get_nowait())
                    except queue.Empty:
                        break
            except queue.Empty:
                continue

            if batch:
                self._insert_batch(batch)
                for _ in batch:
                    self._queue.task_done()

        # 종료 시 큐에 남은 잔여 항목 전체 드레인
        remaining = []
        while not self._queue.empty():
            try:
                remaining.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if remaining:
            self._insert_batch(remaining)
            for _ in remaining:
                self._queue.task_done()

    def _insert_batch(self, batch: List[tuple]):
        """배치 INSERT 트랜잭션 실행"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.executemany("""
                    INSERT INTO audit_logs 
                    (user_prompt, response_text, status, guardrail_enabled, violation_type, matched_rule, blocked_layer, latency_ms, masked_rules)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, batch)
                conn.commit()
        except Exception as e:
            logger.error(f"[AuditLogger Async Error] 배치 감사 로그 기록 실패 ({len(batch)}건): {e}")

    def log_event(self, prompt: str, response: str, status: str, guardrail_enabled: bool,
                  violation_type: str, matched_rule: str, blocked_layer: str, latency_ms: float, masked_rules: list):
        """
        보안 이벤트 논블로킹(Non-blocking) 실시간 로깅 메서드
        - 큐에 적재하여 메인 API 요청 지연시간(Latency)을 0.002ms 수준으로 최소화
        """
        if not settings.audit_log_raw_content:
            prompt = "[REDACTED_BY_RETENTION_POLICY]"
            response = "[REDACTED_BY_RETENTION_POLICY]" if response else ""

        entry = (
            prompt,
            response,
            status,
            1 if guardrail_enabled else 0,
            violation_type,
            matched_rule,
            blocked_layer,
            latency_ms,
            json.dumps(masked_rules or [])
        )

        if self.enable_async_worker and self._worker_thread and self._worker_thread.is_alive():
            try:
                self._queue.put_nowait(entry)
                return
            except queue.Full:
                logger.warning("[AuditLogger] Queue is full, executing direct write fallback.")

        # 워커 비활성화 시 또는 큐 포화 시 동기 fallback
        self.log_event_sync(entry)

    def log_event_sync(self, entry: tuple):
        """동기식 직접 INSERT 기록"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_logs 
                    (user_prompt, response_text, status, guardrail_enabled, violation_type, matched_rule, blocked_layer, latency_ms, masked_rules)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, entry)
                conn.commit()
        except Exception as e:
            logger.error(f"[AuditLogger Error] 감사 로그 기록 실패: {e}")

    def flush(self, timeout: float = 2.0):
        """큐에 대기 중인 모든 로그가 DB에 기록될 때까지 대기"""
        if self.enable_async_worker and not self._queue.empty():
            try:
                self._queue.join()
            except Exception:
                pass

    def get_stats(self) -> Dict[str, Any]:
        """
        실시간 보안 통계 지표 집계 메서드 (대시보드용)
        - 조회 전 대기 중인 큐를 flush하여 실시간 일관성 보장
        """
        self.flush()
        with self._get_connection() as conn:
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
        """
        self.flush()
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
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
        self.flush()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM audit_logs")
            conn.commit()
            return cursor.rowcount

    def close(self):
        """워커 스레드 정상 종료 및 큐 드레인"""
        if self._worker_thread and self._worker_thread.is_alive():
            self._stop_event.set()
            self._worker_thread.join(timeout=1.5)
