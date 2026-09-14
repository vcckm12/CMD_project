# -*- coding: utf-8 -*-
"""
[schemas.py - Pydantic 데이터 모델 및 API 스키마 정의 모듈]
- FastAPI 서버와 클라이언트(Streamlit, AnythingLLM) 간 주고받는 요청(Request) 및 응답(Response) 데이터 구조를 정의합니다.
- Pydantic BaseModel을 활용하여 데이터의 유효성 검증(Validation) 및 자동 직렬화/역직렬화를 수행합니다.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator

# ==========================================
# 1. 대화 메시지 기본 단위 모델
# ==========================================
class ChatMessage(BaseModel):
    """
    단일 대화 메시지 구조 정의
    - role: 메시지 발화자 ('user': 사용자, 'assistant': AI 챗봇, 'system': 시스템 프롬프트)
    - content: 실제 대화 텍스트 본문
    """
    role: str = Field(..., pattern="^(user|assistant|system)$", description="메시지 발화자")
    content: str = Field(..., min_length=1, max_length=16000, description="메시지 본문 내용")


# ==========================================
# 2. LLM 추론 하이퍼파라미터 모델
# ==========================================
class ChatParameters(BaseModel):
    """
    LLM 생성 제어 파라미터
    - temperature: 답변의 창의성/무작위성 조절 (0.0: 일관되고 결정적 ~ 2.0: 창의적)
    - max_tokens: 모델이 최대로 생성할 토큰 수
    """
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, description="생성 온도 (0.0 ~ 2.0)")
    max_tokens: int = Field(default=500, ge=1, le=4096, description="최대 생성 토큰 수")


# ==========================================
# 3. 챗봇 요청(Request) 스키마
# ==========================================
class ChatRequest(BaseModel):
    """
    클라이언트(Streamlit, AnythingLLM, curl 등)에서 백엔드로 전송하는 채팅 요청 스키마
    - model: 사용할 LLM/SLM 모델명 (예: 'llama3:latest', 'llama3-raw' 등)
    - messages: 대화 이력 목록 (이전 질의응답 및 현재 질문 포함)
    - parameters: 생성 파라미터 객체 (온도, 최대 토큰 등)
    - guardrail_enabled: AI 실시간 보안 가드레일 활성화 여부 (True: 보호 ON, False: 무검열 OFF)
    - stream: 실시간 토큰 스트리밍 응답 여부 (SSE 방식)
    """
    model: Optional[str] = Field(default=None, max_length=128, description="선택된 LLM/SLM 모델명")
    messages: List[ChatMessage] = Field(..., min_length=1, max_length=50, description="대화 메시지 리스트")
    parameters: Optional[ChatParameters] = Field(default_factory=ChatParameters, description="생성 제어 파라미터")
    temperature: Optional[float] = Field(default=None, description="상위 호환용 개별 temperature 설정")
    max_tokens: Optional[int] = Field(default=None, description="상위 호환용 개별 max_tokens 설정")
    guardrail_enabled: bool = Field(default=True, description="보안 가드레일 활성화 여부 (ON/OFF)")
    stream: bool = Field(default=False, description="스트리밍 응답 여부")

    @field_validator("model")
    @classmethod
    def reject_control_characters(cls, value: Optional[str]) -> Optional[str]:
        if value and any(ord(char) < 32 for char in value):
            raise ValueError("model must not contain control characters")
        return value


# ==========================================
# 4. 보안 가드레일 검사 메타데이터 모델
# ==========================================
class SecurityMetadata(BaseModel):
    """
    요청/응답 처리 과정에서 가드레일 엔진이 측정한 보안 검사 결과 데이터
    - guardrail_active: 요청 시 가드레일이 켜져 있었는지 여부
    - input_flagged: 입력단에서 악성 프롬프트/탈옥이 탐지되어 차단되었는지 여부
    - output_masked: 출력단에서 개인정보(PII)나 위험 코드가 마스킹/파기되었는지 여부
    - violation_type: OWASP 위반 분류 (예: 'OWASP_LLM01', 'OWASP_LLM02', 'OUTPUT_MASKED' 등)
    - matched_rule: 매칭된 세부 보안 규칙명 (예: 'RULE_DAN_JAILBREAK', 'PII_주민등록번호' 등)
    - blocked_layer: 차단이 발생한 계층 ('Input_Guardrail' 또는 'Output_Guardrail')
    - latency_ms: 가드레일 보안 검사에 소요된 시간 (밀리초 단위)
    - masked_rules: 마스킹 처리된 규칙들의 리스트
    """
    guardrail_active: bool = True
    input_flagged: bool = False
    output_masked: bool = False
    violation_type: Optional[str] = None
    matched_rule: Optional[str] = None
    blocked_layer: Optional[str] = None
    latency_ms: float = 0.0
    masked_rules: List[str] = []


# ==========================================
# 5. 에러 상세 정보 모델
# ==========================================
class ErrorDetail(BaseModel):
    """
    보안 차단 또는 시스템 오류 발생 시 반환되는 에러 구조
    - code: 에러 식별 코드 (예: 'ERR_OWASP_LLM01')
    - message: 사용자에게 안내할 보안 경고 또는 오류 메시지
    """
    code: str
    message: str


# ==========================================
# 6. 챗봇 응답(Response) 스키마
# ==========================================
class ChatResponse(BaseModel):
    """
    FastAPI 백엔드가 클라이언트에게 최종 반환하는 응답 스키마
    - status: 처리 상태 ('success': 정상 답변, 'blocked': 가드레일 차단, 'error': 시스템 예외)
    - message: AI가 생성한 최종 정제 답변 메시지 (assistant)
    - error: 차단/오류 발생 시 상세 정보
    - security_metadata: 실시간 보안 판정 결과 및 지연시간 정보
    """
    status: str = Field(..., description="응답 상태 (success, blocked, error)")
    message: Optional[ChatMessage] = None
    error: Optional[ErrorDetail] = None
    security_metadata: SecurityMetadata


# ==========================================
# 7. 서버 상태 점검(Health Check) 스키마
# ==========================================
class HealthResponse(BaseModel):
    """
    서버 및 하위 시스템 상태 점검 응답
    - status: 전체 시스템 헬스 ('healthy' / 'degraded')
    - components: 하위 컴포넌트별 세부 상태 (API 서버, 가드레일 엔진, Ollama SLM 등)
    - active_model: 현재 활성화되어 있는 기본 LLM 모델명
    """
    status: str
    components: Dict[str, str]
    active_model: str


# ==========================================
# 8. 보안 감사 로그(Audit Log) 단일 항목 스키마
# ==========================================
class AuditLogEntry(BaseModel):
    """
    SQLite DB(audit_logs 테이블)에 적재된 개별 보안 감사 기록
    - id: 로그 고유 식별자 (PK)
    - timestamp: 이벤트 발생 일시
    - user_prompt: 사용자가 입력한 원본 프롬프트
    - response_text: 가드레일 정제 후 최종 반환된 텍스트
    - status: 처리 결과 ('passed', 'blocked', 'masked', 'bypassed_off')
    - guardrail_enabled: 가드레일 ON/OFF 상태 (1/0)
    - violation_type: 위반 분류명
    - matched_rule: 탐지된 룰 이름
    - blocked_layer: 차단된 계층
    - latency_ms: 전체 처리 지연시간(ms)
    - masked_rules: 마스킹된 규칙 목록(JSON 문자열)
    """
    id: int
    timestamp: str
    user_prompt: str
    response_text: Optional[str] = None
    status: str
    guardrail_enabled: int
    violation_type: Optional[str] = None
    matched_rule: Optional[str] = None
    blocked_layer: Optional[str] = None
    latency_ms: float
    masked_rules: Optional[str] = None


# ==========================================
# 9. 보안 감사 통계(Audit Stats) 집계 스키마
# ==========================================
class AuditStatsResponse(BaseModel):
    """
    대시보드 표출용 보안 감사 통계 데이터 구조
    - total_requests: 누적 요청 수
    - blocked_requests: 입력단 차단 건수
    - masked_requests: 출력단 마스킹 건수
    - clean_success_requests: 보안 위반 없는 정상 질의 건수
    - defense_rate: 위협 차단/방어율 (%)
    - avg_latency_ms: 평균 처리 지연시간 (ms)
    - p95_latency_ms: 95분위 지연시간 (ms)
    - min_latency_ms / max_latency_ms: 최소/최대 지연시간
    - blocked_by_layer: 계층별 차단 통계 맵
    - violations_by_type: 위반 유형별 탐지 통계 맵
    """
    total_requests: int
    blocked_requests: int
    masked_requests: int
    clean_success_requests: int
    defense_rate: float
    avg_latency_ms: float
    p95_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    blocked_by_layer: Dict[str, int]
    violations_by_type: Dict[str, int]
