# -*- coding: utf-8 -*-
"""
[main.py - FastAPI AI 보안 게이트웨이 메인 서버 (Port 8000)]
- Streamlit 웹 관제 UI 및 AnythingLLM RAG 데스크톱 클라이언트의 모든 요청을 단일 진입점에서 통제합니다.
- 표준 OpenAI 호환 규격(/v1/chat/completions)과 독자 규격(/api/v1/chat/completions)을 모두 지원합니다.
- 전체 요청을 [입력 가드레일(0.13ms) -> 원격 Ollama 추론 -> 출력 가드레일(0.08ms) -> SQLite 로깅] 파이프라인으로 처리합니다.
"""

from typing import List, Optional, Dict, Any
import secrets
from fastapi import Depends, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
import time
import json
import uuid

# 내부 모듈 및 Pydantic 스키마 임포트
from backend.models.schemas import (
    ChatRequest, ChatResponse, ChatMessage, SecurityMetadata, 
    ErrorDetail, HealthResponse, AuditLogEntry, AuditStatsResponse
)
from backend.guardrails.input_guardrail import InputGuardrailEngine
from backend.guardrails.output_guardrail import OutputGuardrailEngine
from backend.services.slm_service import SLMService
from backend.database.audit_logger import AuditLogger
from backend.config import settings

# FastAPI 앱 인스턴스 생성 및 메타데이터 정의
app = FastAPI(
    title="AI Security Guardrail Chatbot Backend",
    version="1.0.0",
    description="Uncensored SLM 기반 실시간 AI 보안 가드레일 백엔드 API (OWASP Top 10 for LLM 방어)"
)

# CORS origins are explicit. Wildcards are unsafe with credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 핵심 컴포넌트 싱글톤 객체 인스턴스화
input_guardrail = InputGuardrailEngine()
output_guardrail = OutputGuardrailEngine()
slm_service = SLMService()
audit_logger = AuditLogger()

# 전역 가드레일 활성화 상태 (Streamlit 토글 스위치와 실시간 동기화)
global_guardrail_state = {"enabled": True}


def require_admin(x_admin_key: Optional[str] = Header(default=None)) -> None:
    """Protect operational endpoints; development remains frictionless for demos."""
    if not settings.is_production:
        return
    if not x_admin_key or not settings.admin_api_key or not secrets.compare_digest(x_admin_key, settings.admin_api_key):
        raise HTTPException(status_code=401, detail="Valid X-Admin-Key is required")


def guardrail_is_active(req: ChatRequest, user_prompt: str, model: str) -> bool:
    """Production is fail-closed: callers cannot disable security controls."""
    if not settings.allow_demo_bypass:
        return True
    model_lower = model.lower()
    raw_model = any(token in model_lower for token in ("raw", "bypass", "off", "unprotected", "disable"))
    prompt_off = user_prompt.strip().lower().startswith(("[off]", "[bypass]", "[가드레일off]", "[가드레일 해제]"))
    return global_guardrail_state["enabled"] and req.guardrail_enabled and not raw_model and not prompt_off


# =============================================================
# 1. 서버 헬스체크 및 상태 조회 엔드포인트
# =============================================================
@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check():
    """
    백엔드 API 및 원격 Ollama SLM 서버 가동 상태 헬스체크
    """
    slm_ok = await slm_service.check_health()
    return HealthResponse(
        status="healthy",
        components={
            "api_server": "ok",
            "guardrail_engine": "ok",
            "ollama_slm": "online" if slm_ok else "mock_sandbox_mode"
        },
        active_model="qwen2.5:7b-instruct-abliterated-v2"
    )


# =============================================================
# 2. 가드레일 ON/OFF 글로벌 상태 관리 엔드포인트
# =============================================================
@app.get("/api/v1/guardrail/status")
async def get_guardrail_status():
    """현재 전역 가드레일 활성화 상태(True/False) 조회"""
    return global_guardrail_state

@app.post("/api/v1/guardrail/toggle")
async def toggle_guardrail(enabled: Optional[bool] = None, _: None = Depends(require_admin)):
    """
    가드레일 ON/OFF 상태 토글 (Streamlit 스위치 조작 시 AnythingLLM에도 즉시 동시 적용)
    """
    if not settings.allow_demo_bypass:
        raise HTTPException(status_code=403, detail="Guardrail bypass is disabled outside demo mode")
    if enabled is not None:
        global_guardrail_state["enabled"] = enabled
    else:
        global_guardrail_state["enabled"] = not global_guardrail_state["enabled"]
    return {"status": "ok", "global_guardrail_enabled": global_guardrail_state["enabled"]}


# =============================================================
# 3. OpenAI 호환 모델 목록 조회 엔드포인트 (AnythingLLM 연동용)
# =============================================================
@app.get("/v1/models")
@app.get("/api/v1/models")
async def get_openai_models():
    """
    AnythingLLM 및 Generic OpenAI 클라이언트가 모델 목록을 요청할 때 응답하는 엔드포인트
    """
    models = await slm_service.get_available_models()
    data = []
    for m in models:
        data.append({
            "id": m,
            "object": "model",
            "created": int(time.time()),
            "owned_by": "ai-guardrail-system",
            "permission": [],
            "root": m,
            "parent": None
        })
    if settings.allow_demo_bypass:
        data.append({"id": "llama3-raw", "object": "model", "created": int(time.time()), "owned_by": "ai-guardrail-demo", "permission": [], "root": "llama3-raw", "parent": None})
    return {"object": "list", "data": data}


# =============================================================
# 4. AnythingLLM 전용 표준 OpenAI 호환 엔드포인트 (/v1/chat/completions)
# =============================================================
@app.post("/v1/chat/completions")
async def openai_chat_completions(req: ChatRequest):
    """
    AnythingLLM 데스크톱 앱 및 전사 RAG 시스템 연동용 엔드포인트
    - OpenAI Chat Completion 표준 JSON 포맷 및 SSE 스트리밍을 100% 준수합니다.
    - 입력 가드레일 -> SLM 추론 -> 출력 가드레일 -> SQLite 로깅 자동 적용
    """
    total_start = time.perf_counter()
    cmpl_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    created_ts = int(time.time())
    chosen_model = req.model or "llama3:latest"

    # 마지막 사용자 메시지 추출
    user_prompt = ""
    for m in reversed(req.messages):
        if m.role == "user":
            user_prompt = m.content
            break

    # Bypass syntax is recognized solely in an explicitly enabled demo environment.
    prompt_has_off = user_prompt.strip().lower().startswith(("[off]", "[bypass]", "[가드레일off]", "[가드레일 해제]"))
    
    if prompt_has_off and settings.allow_demo_bypass:
        for prefix in ["[off]", "[bypass]", "[가드레일off]", "[가드레일 해제]"]:
            if user_prompt.strip().lower().startswith(prefix):
                user_prompt = user_prompt.strip()[len(prefix):].strip()
                break

    is_guardrail_active = guardrail_is_active(req, user_prompt, chosen_model)

    temp = req.temperature if req.temperature is not None else (req.parameters.temperature if req.parameters else 0.7)
    max_tok = req.max_tokens if req.max_tokens is not None else (req.parameters.max_tokens if req.parameters else 500)

    # -------------------------------------------------------------
    # STEP 1 & 2: Input Guardrail 검사 (가드레일 활성화 시)
    # -------------------------------------------------------------
    if is_guardrail_active:
        is_blocked, v_type, matched_rule, in_lat = input_guardrail.inspect(user_prompt)
        if is_blocked:
            total_lat = (time.perf_counter() - total_start) * 1000
            # STEP 3: SQLite 감사 로그 적재
            audit_logger.log_event(
                prompt=user_prompt,
                response="",
                status="blocked",
                guardrail_enabled=True,
                violation_type=v_type,
                matched_rule=matched_rule,
                blocked_layer="Input_Guardrail",
                latency_ms=total_lat,
                masked_rules=[]
            )
            block_msg = (
                f"🛡️ **[AI 보안 가드레일 실시간 차단]**\n\n"
                f"보안 정책 위반(악의적 공격/프롬프트 인젝션 시도)이 탐지되어 응답이 안전하게 차단되었습니다.\n"
                f"• **위반 유형**: `{v_type}`\n"
                f"• **탐지 규칙**: `{matched_rule}`\n"
                f"• **방어 레이어**: `Input_Guardrail (0.2ms 차단)`\n"
                f"• **상태**: `가드레일 보호 작동 중 (ON)`"
            )

            # 스트리밍 요청인 경우 SSE 포맷으로 차단 메시지 반환
            if req.stream:
                async def block_stream_generator():
                    chunk = {
                        "id": cmpl_id,
                        "object": "chat.completion.chunk",
                        "created": created_ts,
                        "model": chosen_model,
                        "choices": [{"index": 0, "delta": {"role": "assistant", "content": block_msg}, "finish_reason": "stop"}]
                    }
                    yield f"data: {json.dumps(chunk)}\n\n"
                    yield "data: [DONE]\n\n"
                return StreamingResponse(block_stream_generator(), media_type="text/event-stream")

            # 단건 JSON 응답 반환
            return {
                "id": cmpl_id,
                "object": "chat.completion",
                "created": created_ts,
                "model": chosen_model,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": block_msg},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": len(user_prompt), "completion_tokens": len(block_msg), "total_tokens": len(user_prompt) + len(block_msg)}
            }

    # -------------------------------------------------------------
    # STEP 4: 원격 Ollama SLM 추론 실행
    # -------------------------------------------------------------
    msg_dicts = [{"role": m.role, "content": m.content} for m in req.messages]
    raw_response = await slm_service.generate_response(
        messages=msg_dicts,
        temperature=temp,
        max_tokens=max_tok,
        model_override="llama3:latest",
        is_guardrail_active=is_guardrail_active
    )

    # -------------------------------------------------------------
    # STEP 5: Output Guardrail 검사 및 개인정보 마스킹
    # -------------------------------------------------------------
    final_text = raw_response
    is_masked = False
    masked_rules = []
    if is_guardrail_active:
        final_text, is_masked, masked_rules, out_lat = output_guardrail.sanitize(raw_response)

    total_lat = (time.perf_counter() - total_start) * 1000

    # STEP 3: SQLite 감사 로그 적재
    audit_logger.log_event(
        prompt=user_prompt,
        response=final_text,
        status="success" if is_guardrail_active else "bypassed_off",
        guardrail_enabled=is_guardrail_active,
        violation_type="OUTPUT_MASKED" if is_masked else (None if is_guardrail_active else "GUARDRAIL_OFF_BYPASS"),
        matched_rule=", ".join(masked_rules) if masked_rules else (None if is_guardrail_active else "GUARDRAIL_DISABLED"),
        blocked_layer="Output_Guardrail" if is_masked else None,
        latency_ms=total_lat,
        masked_rules=masked_rules
    )

    # 스트리밍 응답 반환
    if req.stream:
        async def success_stream_generator():
            chunk = {
                "id": cmpl_id,
                "object": "chat.completion.chunk",
                "created": created_ts,
                "model": chosen_model,
                "choices": [{"index": 0, "delta": {"role": "assistant", "content": final_text}, "finish_reason": "stop"}]
            }
            yield f"data: {json.dumps(chunk)}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(success_stream_generator(), media_type="text/event-stream")

    # STEP 6: 최종 정제된 OpenAI 규격 JSON 응답 반환
    return {
        "id": cmpl_id,
        "object": "chat.completion",
        "created": created_ts,
        "model": chosen_model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": final_text},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": len(user_prompt),
            "completion_tokens": len(final_text),
            "total_tokens": len(user_prompt) + len(final_text)
        }
    }


# =============================================================
# 5. Streamlit 웹 관제 전용 엔드포인트 (/api/v1/chat/completions)
# =============================================================
@app.post("/api/v1/chat/completions", response_model=ChatResponse)
async def chat_completions(req: ChatRequest):
    """
    Streamlit 관제 대시보드와 통신하는 전용 엔드포인트
    - 보안 메타데이터(지연시간, 차단 규칙명, 마스킹 상세 등)를 풍부하게 포함하여 응답합니다.
    """
    total_start = time.perf_counter()
    chosen_model = req.model or "llama3:8b"
    
    user_prompt = ""
    for m in reversed(req.messages):
        if m.role == "user":
            user_prompt = m.content
            break

    temp = req.temperature if req.temperature is not None else (req.parameters.temperature if req.parameters else 0.7)
    max_tok = req.max_tokens if req.max_tokens is not None else (req.parameters.max_tokens if req.parameters else 500)

    is_guardrail_active = guardrail_is_active(req, user_prompt, chosen_model)

    # 1. 입력 가드레일 검사
    if is_guardrail_active:
        is_blocked, v_type, matched_rule, in_lat = input_guardrail.inspect(user_prompt)
        if is_blocked:
            total_lat = (time.perf_counter() - total_start) * 1000
            audit_logger.log_event(
                prompt=user_prompt,
                response="",
                status="blocked",
                guardrail_enabled=True,
                violation_type=v_type,
                matched_rule=matched_rule,
                blocked_layer="Input_Guardrail",
                latency_ms=total_lat,
                masked_rules=[]
            )
            return ChatResponse(
                status="blocked",
                error=ErrorDetail(
                    code=f"ERR_{v_type}",
                    message=f"[🛡️ 보안 정책 위반] 실시간 가드레일에 의해 악의적인 요청이 차단되었습니다. ({matched_rule})"
                ),
                security_metadata=SecurityMetadata(
                    guardrail_active=True,
                    input_flagged=True,
                    output_masked=False,
                    violation_type=v_type,
                    matched_rule=matched_rule,
                    blocked_layer="Input_Guardrail",
                    latency_ms=round(total_lat, 2),
                    masked_rules=[]
                )
            )

    # 2. SLM 추론 실행
    msg_dicts = [{"role": m.role, "content": m.content} for m in req.messages]
    raw_response = await slm_service.generate_response(
        messages=msg_dicts,
        temperature=temp,
        max_tokens=max_tok,
        model_override=chosen_model,
        is_guardrail_active=is_guardrail_active
    )

    # 3. 출력 가드레일 검사
    final_text = raw_response
    is_masked = False
    masked_rules = []
    
    if is_guardrail_active:
        final_text, is_masked, masked_rules, out_lat = output_guardrail.sanitize(raw_response)

    total_lat = (time.perf_counter() - total_start) * 1000
    
    # 4. SQLite 감사 로그 기록
    audit_logger.log_event(
        prompt=user_prompt,
        response=final_text,
        status="success",
        guardrail_enabled=is_guardrail_active,
        violation_type="OUTPUT_MASKED" if is_masked else None,
        matched_rule=", ".join(masked_rules) if masked_rules else None,
        blocked_layer="Output_Guardrail" if is_masked else None,
        latency_ms=total_lat,
        masked_rules=masked_rules
    )

    # 5. 최종 응답 반환
    return ChatResponse(
        status="success",
        message=ChatMessage(role="assistant", content=final_text),
        security_metadata=SecurityMetadata(
            guardrail_active=is_guardrail_active,
            input_flagged=False,
            output_masked=is_masked,
            violation_type="OUTPUT_MASKED" if is_masked else None,
            matched_rule=", ".join(masked_rules) if masked_rules else None,
            blocked_layer="Output_Guardrail" if is_masked else None,
            latency_ms=round(total_lat, 2),
            masked_rules=masked_rules
        )
    )


# =============================================================
# 6. 보안 감사 통계 및 로그 조회 엔드포인트
# =============================================================
@app.get("/api/v1/audit/stats", response_model=AuditStatsResponse)
async def get_audit_stats(_: None = Depends(require_admin)):
    """실시간 보안 대시보드 통계 지표(차단율, 지연시간 등) 반환"""
    return audit_logger.get_stats()

@app.get("/api/v1/audit/logs", response_model=List[AuditLogEntry])
async def get_audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None, pattern="^(blocked|success|bypassed_off)$"),
    _: None = Depends(require_admin),
):
    """최근 보안 감사 로그 페이징 조회"""
    return audit_logger.get_recent_logs(limit=limit, offset=offset, status_filter=status)

@app.delete("/api/v1/audit/logs")
async def clear_audit_logs(_: None = Depends(require_admin)):
    """감사 로그 데이터베이스 전체 초기화"""
    cnt = audit_logger.clear_logs()
    return {"status": "cleared", "deleted_rows": cnt}


# =============================================================
# 7. 단독 실행용 엔트리포인트 (uvicorn 실행)
# =============================================================
if __name__ == "__main__":
    import uvicorn
    # host="0.0.0.0"으로 사내 LAN 외부(AnythingLLM 등)에서도 접근 가능하도록 설정
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
