# -*- coding: utf-8 -*-
"""
[main.py - FastAPI AI 보안 게이트웨이 및 커머스 백엔드 메인 서버 (Port 8000)]
- Streamlit 웹 관제 UI, 목업 쇼핑몰 및 AnythingLLM RAG의 모든 요청을 단일 진입점에서 통제합니다.
- 동적 위협 인텔리전스(Threat Intelligence Registry), 가드레일 Hot-Reload API 및 쇼핑몰 비즈니스 REST API 제공
"""

from typing import List, Optional, Dict, Any
import os
import secrets
import time
import json
import uuid
import logging
from fastapi import FastAPI, Depends, Header, HTTPException, Query, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, StreamingResponse

# 내부 모듈 및 Pydantic 스키마 임포트
from backend.config import settings
from backend.models.schemas import (
    ChatRequest, ChatResponse, ChatMessage, SecurityMetadata, 
    ErrorDetail, HealthResponse, AuditLogEntry, AuditStatsResponse,
    ThreatSignatureCreate, ThreatSignatureUpdate, ThreatSignatureResponse, ThreatSyncResult,
    OrderCreateRequest, CartAddRequest, CouponVerifyRequest
)
from backend.guardrails.input_guardrail import InputGuardrailEngine
from backend.guardrails.output_guardrail import OutputGuardrailEngine
from backend.guardrails.execution_guardrail import ExecutionGuardrailEngine
from backend.services.slm_service import SLMService
from backend.database.audit_logger import AuditLogger
from backend.database.threat_intel_dao import ThreatIntelDAO
from backend.database.shop_dao import ShopDAO

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ai_guardrail.gateway")

# FastAPI 앱 인스턴스 생성 및 메타데이터 정의
app = FastAPI(
    title="AI Security Guardrail Gateway & E-Commerce Backend",
    version="1.2.0",
    description="실시간 동적 위협 인텔리전스 기반 초저지연 AI 보안 게이트웨이 및 쇼핑몰 백엔드 API (OWASP Top 10 for LLM 방어)"
)

# CORS 미들웨어 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins) + ["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 핵심 컴포넌트 싱글톤 객체 인스턴스화 (DAO 주입)
threat_dao = ThreatIntelDAO()
shop_dao = ShopDAO()
input_guardrail = InputGuardrailEngine(threat_dao=threat_dao)
output_guardrail = OutputGuardrailEngine(threat_dao=threat_dao)
execution_guardrail = ExecutionGuardrailEngine()
slm_service = SLMService()
audit_logger = AuditLogger()

# 가짜 쇼핑몰 (Mock E-Commerce Store) 정적 파일 서빙
mock_store_path = os.path.join(str(settings.base_dir), "mock_store")
if os.path.exists(mock_store_path):
    app.mount("/store", StaticFiles(directory=mock_store_path, html=True), name="mock_store")

# 전역 가드레일 활성화 상태 (Streamlit 토글 스위치와 실시간 동기화)
global_guardrail_state = {"enabled": True}


def require_admin(x_admin_key: Optional[str] = Header(default=None)) -> None:
    """운영 및 위협 관리 엔드포인트 보안 보호"""
    if not settings.is_production:
        return
    if not x_admin_key or not settings.admin_api_key or not secrets.compare_digest(x_admin_key, settings.admin_api_key):
        raise HTTPException(status_code=401, detail="Valid X-Admin-Key is required")


def guardrail_is_active(req: ChatRequest, user_prompt: str, model: str) -> bool:
    """Fail-Closed 원칙에 따른 가드레일 활성화 판정"""
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
            "threat_intel_registry": "ok",
            "shop_database": "ok",
            "ollama_slm": "online" if slm_ok else "mock_sandbox_mode"
        },
        active_model=settings.default_model
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
    가드레일 ON/OFF 상태 토글
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
async def openai_chat_completions(
    req: ChatRequest,
    x_user_id: Optional[str] = Header(default="user_vip_hong")
):
    """
    AnythingLLM 데스크톱 앱 및 전사 RAG 시스템 연동용 엔드포인트
    - OpenAI Chat Completion 표준 JSON 포맷 및 SSE 스트리밍을 100% 준수합니다.
    - 입력 가드레일 -> SLM 추론 -> 출력 가드레일 -> SQLite 감사 로깅
    """
    total_start = time.perf_counter()
    cmpl_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    created_ts = int(time.time())
    chosen_model = req.model or settings.fallback_model

    user_prompt = ""
    for m in reversed(req.messages):
        if m.role == "user":
            user_prompt = m.content
            break

    prompt_has_off = user_prompt.strip().lower().startswith(("[off]", "[bypass]", "[가드레일off]", "[가드레일 해제]"))
    
    if prompt_has_off and settings.allow_demo_bypass:
        for prefix in ["[off]", "[bypass]", "[가드레일off]", "[가드레일 해제]"]:
            if user_prompt.strip().lower().startswith(prefix):
                user_prompt = user_prompt.strip()[len(prefix):].strip()
                break

    is_guardrail_active = guardrail_is_active(req, user_prompt, chosen_model)
    temp = req.temperature if req.temperature is not None else (req.parameters.temperature if req.parameters else settings.default_temperature)
    max_tok = req.max_tokens if req.max_tokens is not None else (req.parameters.max_tokens if req.parameters else settings.default_max_tokens)

    # 1. Input Guardrail 검사
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
            block_msg = (
                f"🛡️ **[AI 보안 가드레일 실시간 차단]**\n\n"
                f"보안 정책 위반(악의적 공격/프롬프트 인젝션 시도)이 탐지되어 응답이 안전하게 차단되었습니다.\n"
                f"• **위반 유형**: `{v_type}`\n"
                f"• **탐지 규칙**: `{matched_rule}`\n"
                f"• **방어 레이어**: `Input_Guardrail (0.1ms 차단)`\n"
                f"• **상태**: `가드레일 보호 작동 중 (ON)`"
            )

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

    # 2. SLM 추론 실행
    msg_dicts = [{"role": m.role, "content": m.content} for m in req.messages]
    raw_response = await slm_service.generate_response(
        messages=msg_dicts,
        temperature=temp,
        max_tokens=max_tok,
        model_override=chosen_model,
        is_guardrail_active=is_guardrail_active,
        session_user_id=x_user_id
    )

    # 3. Output Guardrail 검사
    final_text = raw_response
    is_masked = False
    masked_rules = []
    if is_guardrail_active:
        final_text, is_masked, masked_rules, out_lat = output_guardrail.sanitize(raw_response)

    total_lat = (time.perf_counter() - total_start) * 1000

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
# 5. Streamlit 관제 대시보드 전용 엔드포인트 (/api/v1/chat/completions)
# =============================================================
@app.post("/api/v1/chat/completions", response_model=ChatResponse)
async def chat_completions(
    req: ChatRequest,
    x_user_id: Optional[str] = Header(default="user_vip_hong")
):
    """
    Streamlit 관제 대시보드와 통신하는 전용 엔드포인트
    """
    total_start = time.perf_counter()
    chosen_model = req.model or settings.default_model
    
    user_prompt = ""
    for m in reversed(req.messages):
        if m.role == "user":
            user_prompt = m.content
            break

    temp = req.temperature if req.temperature is not None else (req.parameters.temperature if req.parameters else settings.default_temperature)
    max_tok = req.max_tokens if req.max_tokens is not None else (req.parameters.max_tokens if req.parameters else settings.default_max_tokens)

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
        is_guardrail_active=is_guardrail_active,
        session_user_id=x_user_id
    )

    # 3. 출력 가드레일 검사
    final_text = raw_response
    is_masked = False
    masked_rules = []
    
    if is_guardrail_active:
        final_text, is_masked, masked_rules, out_lat = output_guardrail.sanitize(raw_response)

    total_lat = (time.perf_counter() - total_start) * 1000
    
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
# 6. 위협 인텔리전스 및 시그니처 관리 엔드포인트 (/api/v1/threats)
# =============================================================
@app.get("/api/v1/threats", response_model=List[ThreatSignatureResponse])
async def list_threat_signatures(
    target_layer: Optional[str] = Query(default=None, pattern="^(INPUT|OUTPUT|EXECUTION)$"),
    category: Optional[str] = Query(default=None),
    is_active: Optional[bool] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: None = Depends(require_admin)
):
    """위협 시그니처 목록 조회"""
    signatures, _ = threat_dao.list_signatures(
        target_layer=target_layer,
        category=category,
        is_active=is_active,
        limit=limit,
        offset=offset
    )
    return signatures


@app.post("/api/v1/threats", response_model=ThreatSignatureResponse, status_code=201)
async def create_threat_signature(
    threat_in: ThreatSignatureCreate,
    _: None = Depends(require_admin)
):
    """
    외부에서 입수한 신규 공격 코드/시그니처를 DB에 등록하고 가드레일 엔진을 즉시 핫 리로드
    """
    existing = threat_dao.get_signature_by_name(threat_in.rule_name)
    if existing:
        raise HTTPException(status_code=400, detail=f"Rule name '{threat_in.rule_name}' already exists.")

    sig_id = threat_dao.create_signature(threat_in.model_dump())
    
    input_guardrail.reload_rules()
    output_guardrail.reload_rules()

    created = threat_dao.get_signature(sig_id)
    return created


@app.get("/api/v1/threats/{sig_id}", response_model=ThreatSignatureResponse)
async def get_threat_signature(
    sig_id: int = Path(..., ge=1),
    _: None = Depends(require_admin)
):
    """단일 위협 시그니처 조회"""
    sig = threat_dao.get_signature(sig_id)
    if not sig:
        raise HTTPException(status_code=404, detail="Threat signature not found")
    return sig


@app.put("/api/v1/threats/{sig_id}", response_model=ThreatSignatureResponse)
async def update_threat_signature(
    threat_update: ThreatSignatureUpdate,
    sig_id: int = Path(..., ge=1),
    _: None = Depends(require_admin)
):
    """위협 시그니처 수정 및 핫 리로드"""
    updates = {k: v for k, v in threat_update.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    success = threat_dao.update_signature(sig_id, updates)
    if not success:
        raise HTTPException(status_code=404, detail="Threat signature not found")

    input_guardrail.reload_rules()
    output_guardrail.reload_rules()
    return threat_dao.get_signature(sig_id)


@app.delete("/api/v1/threats/{sig_id}")
async def delete_threat_signature(
    sig_id: int = Path(..., ge=1),
    _: None = Depends(require_admin)
):
    """위협 시그니처 삭제 및 핫 리로드"""
    success = threat_dao.delete_signature(sig_id)
    if not success:
        raise HTTPException(status_code=404, detail="Threat signature not found")

    input_guardrail.reload_rules()
    output_guardrail.reload_rules()
    return {"status": "deleted", "id": sig_id}


@app.post("/api/v1/threats/reload", response_model=ThreatSyncResult)
async def reload_guardrail_rules(_: None = Depends(require_admin)):
    """가드레일 엔진 메모리 컴파일 캐시 무중단 핫 리로드"""
    in_cnt = input_guardrail.reload_rules()
    out_cnt = output_guardrail.reload_rules()
    return ThreatSyncResult(
        status="reloaded",
        total_active_rules=in_cnt + out_cnt,
        synced_payloads_count=0,
        message=f"Hot-reload successful: {in_cnt} input rules and {out_cnt} output rules active."
    )


@app.post("/api/v1/threats/sync-dataset", response_model=ThreatSyncResult)
async def sync_threats_to_dataset(_: None = Depends(require_admin)):
    """DB에 등록된 위협 페이로드들을 벤치마크 테스트셋(JSONL)과 동기화"""
    synced = threat_dao.sync_to_attack_dataset()
    in_cnt = len(input_guardrail.compiled_rules)
    return ThreatSyncResult(
        status="synced",
        total_active_rules=in_cnt,
        synced_payloads_count=synced,
        message=f"Successfully synced {synced} payloads to attack benchmark dataset."
    )


# =============================================================
# 7. 쇼핑몰(E-Commerce) 비즈니스 도메인 엔드포인트 (/api/v1/shop)
# =============================================================
@app.get("/api/v1/shop/products")
async def list_products(
    query: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    min_price: Optional[int] = Query(default=None, ge=0),
    max_price: Optional[int] = Query(default=None, ge=0),
    sort_by: str = Query(default="popular", pattern="^(popular|price_asc|price_desc|rating)$"),
    in_stock_only: bool = Query(default=True),
    limit: int = Query(default=10, ge=1, le=50),
    offset: int = Query(default=0, ge=0)
):
    """쇼핑몰 상품 카탈로그 다차원 검색 및 목록 조회"""
    return shop_dao.search_products(
        query=query, category=category, min_price=min_price, max_price=max_price,
        sort_by=sort_by, in_stock_only=in_stock_only, limit=limit, offset=offset
    )


@app.get("/api/v1/shop/products/{product_id}")
async def get_product(product_id: int = Path(..., ge=1)):
    """단일 상품 상세 정보 조회"""
    product = shop_dao.get_product_by_id(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="상품을 찾을 수 없습니다.")
    return product


@app.get("/api/v1/shop/orders")
async def list_user_orders(
    x_user_id: str = Header(default="user_vip_hong"),
    limit: int = Query(default=10, ge=1, le=50),
    offset: int = Query(default=0, ge=0)
):
    """현재 로그인한 사용자의 주문 내역 조회 (BOLA 보호)"""
    return shop_dao.get_user_orders(user_id=x_user_id, limit=limit, offset=offset)


@app.get("/api/v1/shop/orders/{order_id}")
async def get_order_detail(
    order_id: str = Path(...),
    x_user_id: str = Header(default="user_vip_hong")
):
    """단일 주문 상세 조회 (BOLA 소유권 검증)"""
    order = shop_dao.get_order_by_id(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="주문을 찾을 수 없습니다.")
    if order["user_id"] != x_user_id:
        raise HTTPException(status_code=403, detail="다른 고객의 주문 내역은 열람할 수 없습니다. (BOLA 보호)")
    return order


@app.post("/api/v1/shop/orders", status_code=201)
async def create_order(
    req: OrderCreateRequest,
    x_user_id: str = Header(default="user_vip_hong"),
    x_user_name: str = Header(default="홍길동")
):
    """신규 주문 생성 트랜잭션 (재고 차감, 쿠폰 할인 계산)"""
    result = shop_dao.create_order(
        user_id=x_user_id,
        user_name=x_user_name,
        product_id=req.product_id,
        quantity=req.quantity,
        recipient_address=req.recipient_address,
        coupon_code=req.coupon_code
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.post("/api/v1/shop/orders/{order_id}/cancel")
async def cancel_order(
    order_id: str = Path(...),
    x_user_id: str = Header(default="user_vip_hong")
):
    """주문 취소 트랜잭션 (배송 전 취소 및 재고 원복)"""
    result = shop_dao.cancel_order(order_id=order_id, user_id=x_user_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.get("/api/v1/shop/track/{tracking_number}")
async def track_delivery(tracking_number: str = Path(...)):
    """운송장 번호 기반 실시간 배송 상태 조회"""
    tracking = shop_dao.track_by_tracking_number(tracking_number)
    if not tracking:
        raise HTTPException(status_code=404, detail="운송장 정보를 찾을 수 없습니다.")
    return tracking


@app.get("/api/v1/shop/cart")
async def get_cart(x_user_id: str = Header(default="user_vip_hong")):
    """장바구니 조회"""
    return shop_dao.get_cart(user_id=x_user_id)


@app.post("/api/v1/shop/cart")
async def add_to_cart(
    req: CartAddRequest,
    x_user_id: str = Header(default="user_vip_hong")
):
    """장바구니 담기"""
    result = shop_dao.add_to_cart(user_id=x_user_id, product_id=req.product_id, quantity=req.quantity)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.delete("/api/v1/shop/cart/{cart_id}")
async def remove_from_cart(
    cart_id: int = Path(..., ge=1),
    x_user_id: str = Header(default="user_vip_hong")
):
    """장바구니 항목 삭제"""
    success = shop_dao.remove_from_cart(cart_id=cart_id, user_id=x_user_id)
    if not success:
        raise HTTPException(status_code=404, detail="장바구니 항목을 찾을 수 없습니다.")
    return {"status": "deleted", "cart_id": cart_id}


@app.post("/api/v1/shop/coupons/verify")
async def verify_coupon(req: CouponVerifyRequest):
    """공식 프로모션 쿠폰 유효성 검증 및 할인액 산출"""
    return shop_dao.verify_coupon(code=req.coupon_code, order_amount=req.order_amount)


# =============================================================
# 8. 보안 감사 통계 및 로그 조회 엔드포인트
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
# 9. 단독 실행용 엔트리포인트 (uvicorn 실행)
# =============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
