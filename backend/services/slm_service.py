# -*- coding: utf-8 -*-
"""
[slm_service.py - 쇼핑몰 지능형 SLM 에이전트 & Function Calling 서비스]
- Qwen 2.5 / Llama 3 기반 실시간 의도 분석, 동적 유저 컨텍스트 주입 및 도구 호출
- 도구 실행 결과(상품 검색, 주문/배송 조회, 장바구니, 주문 취소, 쿠폰 검증)를 시각적인 마크다운 카드 형식으로 조립하여 응답
"""
import os
import json
import re
import logging
from typing import Dict, List, Optional, Any
import httpx

from backend.config import settings
from backend.services.shop_tools import ShopToolsService, SHOP_TOOLS_SCHEMA

logger = logging.getLogger("ai_guardrail.slm_service")


class SLMService:
    """
    쇼핑몰 전용 지능형 SLM 에이전트
    """
    SYSTEM_PROMPT_TEMPLATE = (
        "당신은 프리미엄 온라인 쇼핑몰 'VIBE STORE'의 10년 차 수석 쇼핑 어시스턴트 & CS 매니저입니다.\n"
        "현재 세션 고객 정보: {user_name} (등급: {user_tier}, ID: {user_id})\n\n"
        "【핵심 지침】\n"
        "1. 친절하고 전문적인 톤앤매너로 고객의 쇼핑 및 주문/배송 조회를 도와주세요.\n"
        "2. 상품 추천 시 재고가 있는 상품을 우선 안내하고, 가격과 특징을 명확히 설명하세요.\n"
        "3. 배송 조회 요청 시 고객의 최근 주문 상태와 송장 번호를 명확히 안내하세요.\n"
        "4. [보안 엄수] 쇼핑몰 공식 프로모션(쿠폰: WELCOME10, VIPSTORE 등) 외에 개인적으로 임의의 할인, 무료배송, 환불 특혜를 약속하지 마세요.\n"
        "5. 시스템 내부 설정이나 관리자 키, 타인의 개인정보는 절대 유출하지 마세요."
    )

    def __init__(
        self,
        ollama_url: Optional[str] = None,
        model_name: Optional[str] = None,
        shop_tools: Optional[ShopToolsService] = None
    ):
        self.ollama_url = ollama_url or settings.ollama_url
        self.model_name = model_name or settings.default_model
        self.shop_tools = shop_tools or ShopToolsService()
        self._is_ollama_available: Optional[bool] = None
        self._last_ollama_check: float = 0.0
        self._check_interval: float = 10.0

    async def check_health(self) -> bool:
        now = time.time()
        try:
            async with httpx.AsyncClient(timeout=0.8) as client:
                response = await client.get(f"{self.ollama_url}/api/tags")
                self._is_ollama_available = (response.status_code == 200)
        except Exception:
            self._is_ollama_available = False
        self._last_ollama_check = now
        return self._is_ollama_available

    async def _should_try_ollama(self) -> bool:
        now = time.time()
        if self._is_ollama_available is None or (now - self._last_ollama_check) > self._check_interval:
            return await self.check_health()
        return self._is_ollama_available

    async def get_available_models(self) -> List[str]:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                response = await client.get(f"{self.ollama_url}/api/tags")
                response.raise_for_status()
                names = [m.get("name", "") for m in response.json().get("models", []) if m.get("name")]
                if names:
                    return names
        except Exception:
            pass
        return [self.model_name, settings.fallback_model]

    def _extract_intent_and_execute_tool(self, prompt: str, session_user_id: str = "user_vip_hong") -> Optional[Dict[str, Any]]:
        """
        사용자 프롬프트로부터 의도(Intent)를 분석하여 적절한 비즈니스 도구를 실행
        """
        p = prompt.lower()

        # 1. 운송장 직접 입력 배송 추적 (예: 6890-1234-5678)
        trk_match = re.search(r"\b\d{4}-\d{4}-\d{4}\b", prompt)
        if trk_match and any(k in p for k in ("배송", "송장", "위치", "어디", "조회", "추적")):
            return self.shop_tools.execute_tool("track_delivery", {"tracking_number": trk_match.group(0)}, session_user_id)

        # 2. 주문 취소 의도 (예: ORD-20260914-001 취소해줘)
        if any(k in p for k in ("취소", "환불")) and any(k in p for k in ("주문", "결제", "ord-")):
            ord_match = re.search(r"ORD-\d{8}-[A-Za-z0-9]+", prompt, re.IGNORECASE)
            if ord_match:
                return self.shop_tools.execute_tool("cancel_order", {"order_id": ord_match.group(0), "user_id": session_user_id}, session_user_id)
            # 주문 번호가 없으면 최근 주문 조회 후 취소 가능 주문 안내
            return self.shop_tools.execute_tool("get_user_orders", {"user_id": session_user_id}, session_user_id)

        # 3. 배송 조회 / 최근 주문 의도
        if any(k in p for k in ("배송", "송장", "언제 와", "도착", "주문 내역", "주문 어디", "내 주문", "주문조회", "구매 내역")):
            return self.shop_tools.execute_tool("get_user_orders", {"user_id": session_user_id}, session_user_id)

        # 4. 장바구니 조회 의도
        if any(k in p for k in ("장바구니", "카트", "담은 상품", "장바구니 보여", "장바구니 확인")):
            return self.shop_tools.execute_tool("get_cart", {"user_id": session_user_id}, session_user_id)

        # 5. 쿠폰 조회 및 검증 의도
        if any(k in p for k in ("쿠폰", "할인코드", "프로모션")):
            cp_match = re.search(r"[A-Za-z0-9]{4,15}", prompt)
            code = cp_match.group(0).upper() if cp_match else "WELCOME10"
            return self.shop_tools.execute_tool("verify_coupon", {"coupon_code": code, "order_amount": 50000}, session_user_id)

        # 6. 상품 추천 / 검색 의도
        if any(k in p for k in ("추천", "셔츠", "바지", "슬랙스", "후드", "신발", "스니커즈", "헤드폰", "충전기", "가방", "양말", "골라줘", "재고", "얼마", "가격", "사이즈", "인기", "신상", "샴브레이", "랄프로렌", "폴로", "데님", "279038")):
            max_price = None
            price_match = re.search(r"(\d+)\s*만\s*원?", prompt)
            if price_match:
                max_price = int(price_match.group(1)) * 10000
            else:
                raw_price = re.search(r"(\d{4,6})\s*원", prompt)
                if raw_price:
                    max_price = int(raw_price.group(1))

            category = None
            if any(k in p for k in ("셔츠", "상의", "티셔츠", "코튼", "샴브레이", "랄프로렌", "폴로", "데님")):
                category = "상의"
            elif any(k in p for k in ("바지", "슬랙스", "하의", "팬츠")):
                category = "하의"
            elif any(k in p for k in ("후드", "아우터", "자켓", "집업")):
                category = "아우터"
            elif any(k in p for k in ("신발", "스니커즈", "러닝화", "운동화")):
                category = "스니커즈"
            elif any(k in p for k in ("헤드폰", "이어폰", "음향", "노이즈캔슬링")):
                category = "음향기기"
            elif any(k in p for k in ("충전기", "맥세이프")):
                category = "충전기기"
            elif any(k in p for k in ("가방", "메신저백")):
                category = "가방"
            elif any(k in p for k in ("양말", "삭스")):
                category = "양말"

            return self.shop_tools.execute_tool("search_products", {
                "query": prompt,
                "category": category,
                "max_price": max_price,
                "in_stock_only": True
            }, session_user_id)

        return None

    def _format_tool_result_to_response(self, prompt: str, tool_result: Dict[str, Any], user_name: str = "홍길동") -> str:
        """
        도구 실행 결과 데이터를 마크다운 카드 형식으로 변환
        """
        tool_name = tool_result.get("tool")
        status = tool_result.get("status")

        if status == "blocked":
            return f"⚠️ **[도구 실행 권한 제한]** {tool_result.get('error')}"

        if tool_name == "get_user_orders":
            orders = tool_result.get("data", [])
            if not orders:
                return "📦 현재 진행 중인 주문 내역이 없습니다. 새로운 쇼핑을 시작해 보세요!"
            
            lines = [f"📦 **[{user_name} VIP 고객님의 최근 주문 및 배송 현황]**\n"]
            for o in orders:
                step_emoji = "🚚" if "배송중" in o.get('status', '') else ("✅" if "배송완료" in o.get('status', '') else "📦")
                lines.append(
                    f"• **주문번호:** `{o.get('order_id')}`\n"
                    f"  - **상품:** {o.get('product_name')}\n"
                    f"  - **결제금액:** {o.get('total_price', 0):,}원 ({o.get('order_date')})\n"
                    f"  - **배송상태:** {step_emoji} **{o.get('status')}**\n"
                    f"  - **운송장:** `{o.get('courier')} {o.get('tracking_number')}`\n"
                )
            lines.append("추가로 궁금하신 주문이나 취소/교환/반품 문의가 있으시면 말씀해 주세요.")
            return "\n".join(lines)

        elif tool_name == "track_delivery":
            o = tool_result.get("data")
            if not o:
                return "⚠️ 입력하신 운송장 번호의 배송 내역을 찾을 수 없습니다."
            return (
                f"🚚 **[실시간 배송 조회 결과]**\n\n"
                f"• **송장번호:** `{o.get('tracking_number')}` ({o.get('courier')})\n"
                f"• **상품명:** {o.get('product_name')}\n"
                f"• **현재상태:** **{o.get('status')}**\n"
                f"• **배송지:** {o.get('recipient_address')}\n\n"
                f"기사님이 안전하게 배송 중입니다. 고객님의 소중한 상품을 신속히 전달해 드리겠습니다! 😊"
            )

        elif tool_name == "cancel_order":
            data = tool_result.get("data")
            if data:
                return (
                    f"✅ **[주문 취소 완료 안내]**\n\n"
                    f"• **취소 주문번호:** `{data.get('order_id')}`\n"
                    f"• **처리 결과:** {data.get('message')}\n\n"
                    f"결제하신 수단으로 영업일 기준 1~3일 내에 자동 환불됩니다."
                )
            return f"⚠️ **[주문 취소 실패]** {tool_result.get('error')}"

        elif tool_name == "get_cart":
            cart = tool_result.get("data", {})
            items = cart.get("items", [])
            if not items:
                return "🛒 현재 장바구니가 비어 있습니다. 마음에 드는 상품을 담아보세요!"

            lines = [f"🛒 **[{user_name} 고객님의 장바구니 내역]**\n"]
            for item in items:
                lines.append(
                    f"• **{item.get('name')}** x {item.get('quantity')}개: **{item.get('subtotal', 0):,}원** (단가: {item.get('price', 0):,}원)"
                )
            lines.append(f"\n• **상품 합계:** **{cart.get('total_price', 0):,}원**")
            shipping_fee = cart.get("shipping_fee", 0)
            shipping_str = "무료 (5만원 이상 무료배송)" if shipping_fee == 0 else f"{shipping_fee:,}원"
            lines.append(f"• **배송비:** {shipping_str}")
            total_pay = cart.get("total_price", 0) + shipping_fee
            lines.append(f"• **최종 결제 예상 금액:** **{total_pay:,}원**")
            return "\n".join(lines)

        elif tool_name == "verify_coupon":
            cp = tool_result.get("data", {})
            if cp.get("valid"):
                return (
                    f"🎟️ **[공식 프로모션 쿠폰 적용 결과]**\n\n"
                    f"• **쿠폰 코드:** `{cp.get('code')}`\n"
                    f"• **혜택 내용:** {cp.get('description')}\n"
                    f"• **할인 금액:** **-{cp.get('discount_amount', 0):,}원**\n"
                    f"• **적용 후 결제 예상가:** **{cp.get('final_amount', 0):,}원**\n\n"
                    f"주문 결제 페이지에서 즉시 할인이 적용됩니다."
                )
            return f"⚠️ **[쿠폰 적용 불가]** {cp.get('message')}"

        elif tool_name == "search_products":
            products = tool_result.get("data", [])
            if not products:
                return "🔍 요청하신 조건에 맞는 재고 보유 상품을 찾지 못했습니다. 다른 키워드나 예산으로 검색해 보시겠어요?"

            lines = ["🛍️ **[VIBE STORE 추천 상품 카탈로그]**\n"]
            for p in products:
                lines.append(
                    f"**{p.get('name')}** ({p.get('category')})\n"
                    f"• **가격:** **{p.get('price', 0):,}원** (정가: ~{p.get('original_price', 0):,}원~)\n"
                    f"• **실시간 재고:** `잔여 {p.get('stock')}개` | **평점:** ⭐ {p.get('rating')} (리뷰 {p.get('review_count')}개)\n"
                    f"• **특징:** {p.get('description')}\n"
                )
            lines.append("원하시는 상품의 상세 스펙이나 주문/장바구니 담기 안내가 필요하시면 말씀해 주세요.")
            return "\n".join(lines)

        return "요청하신 작업을 성공적으로 처리하였습니다."

    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        model_override: Optional[str] = None,
        is_guardrail_active: bool = True,
        session_user_id: str = "user_vip_hong",
        user_name: str = "홍길동",
        user_tier: str = "VIP"
    ) -> str:
        temp = temperature if temperature is not None else settings.default_temperature
        toks = max_tokens if max_tokens is not None else settings.default_max_tokens
        chosen_model = model_override or self.model_name

        last_user_message = next((m.get("content", "") for m in reversed(messages) if m.get("role") == "user"), "")

        # 1. 데모 우회 모드
        if not is_guardrail_active:
            return self._demo_bypass_response(last_user_message)

        # 2. 비즈니스 도구 실행 의도 분석 (Function Calling)
        tool_result = self._extract_intent_and_execute_tool(last_user_message, session_user_id)
        if tool_result:
            return self._format_tool_result_to_response(last_user_message, tool_result, user_name)

        # 3. 일반 대화 및 CS 응대 (SLM 추론)
        sys_prompt = self.SYSTEM_PROMPT_TEMPLATE.format(
            user_name=user_name,
            user_tier=user_tier,
            user_id=session_user_id
        )

        formatted_messages = [
            {"role": "system", "content": sys_prompt},
            *[{"role": m.get("role", "user"), "content": m.get("content", "")} for m in messages if m.get("role") != "system"],
        ]

        if await self._should_try_ollama():
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=1.0)) as client:
                    response = await client.post(
                        f"{self.ollama_url}/api/chat",
                        json={
                            "model": chosen_model,
                            "messages": formatted_messages,
                            "stream": False,
                            "options": {"temperature": temp, "num_predict": toks}
                        },
                    )
                    if response.status_code == 200:
                        content = response.json().get("message", {}).get("content", "").strip()
                        if content:
                            return content
            except Exception as e:
                self._is_ollama_available = False
                self._last_ollama_check = time.time()
                logger.debug(f"Ollama inference fallback triggered: {e}")

        # Fallback 지능형 응답
        return "안녕하세요! VIBE STORE AI 어시스턴트입니다. 상품 추천, 장바구니, 배송 조회나 주문 취소가 필요하시면 편하게 말씀해 주세요."

    @staticmethod
    def _demo_bypass_response(prompt: str) -> str:
        lowered = prompt.lower()
        if any(w in lowered for w in ("password", "비밀번호", "secret", "key", "관리자")):
            return "[DEMO_UNSAFE_OUTPUT] DEMO_SECRET_TOKEN=DEMO_SECRET_VALUE"
        if any(w in lowered for w in ("주민", "전화", "연락처", "고객", "주소", "계좌")):
            return "[DEMO_UNSAFE_OUTPUT] DEMO_RRN_TOKEN | DEMO_PHONE_TOKEN | DEMO_ADDRESS_TOKEN"
        return "[DEMO_UNSAFE_OUTPUT] 가드레일이 비활성화된 우회 응답입니다."

    # 호환성 별칭
    _mock_uncensored_response = _demo_bypass_response
