# -*- coding: utf-8 -*-
"""
[shop_tools.py - 쇼핑몰 Function Calling 도구 모음]
- 상품 검색, 상세 조회, 주문/배송 조회, 주문 취소, 신규 주문 생성
- 장바구니 담기/조회, 공식 쿠폰 검증
- LLM Tool Spec (OpenAI Function Calling Schema) 정의 및 실행 디스패처
"""
from typing import List, Dict, Optional, Any
from backend.database.shop_dao import ShopDAO
from backend.guardrails.execution_guardrail import ExecutionGuardrailEngine

shop_dao = ShopDAO()
exec_guardrail = ExecutionGuardrailEngine()

# -------------------------------------------------------------
# 1. LLM Tool Declarations (OpenAI Function Calling Spec)
# -------------------------------------------------------------
SHOP_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "search_products",
            "description": "쇼핑몰 상품 카탈로그에서 키워드, 카테고리, 최대 가격, 실시간 재고를 기준으로 상품을 검색합니다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "검색 키워드 (예: 셔츠, 슬랙스, 헤드폰, 여름, 선물 등)"
                    },
                    "category": {
                        "type": "string",
                        "description": "카테고리 (상의, 하의, 아우터, 스니커즈, 음향기기, 충전기기, 가방, 양말)"
                    },
                    "min_price": {
                        "type": "integer",
                        "description": "최소 가격 (원 단위)"
                    },
                    "max_price": {
                        "type": "integer",
                        "description": "최대 가격 예산 (원 단위, 예: 50000)"
                    },
                    "sort_by": {
                        "type": "string",
                        "enum": ["popular", "price_asc", "price_desc", "rating"],
                        "description": "정렬 기준 (인기순: popular, 낮은가격순: price_asc, 높은가격순: price_desc, 평점순: rating)"
                    },
                    "in_stock_only": {
                        "type": "boolean",
                        "description": "재고가 남아있는 상품만 조회할지 여부 (기본값: true)"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_product_detail",
            "description": "특정 상품의 상세 스펙, 실시간 잔여 재고, 리뷰 평점을 조회합니다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "product_id": {
                        "type": "integer",
                        "description": "상품 고유 ID 번호"
                    }
                },
                "required": ["product_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_user_orders",
            "description": "현재 로그인한 고객의 최근 주문 목록과 배송 상태를 조회합니다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "user_id": {
                        "type": "string",
                        "description": "고객 ID (기본: 현재 로그인된 세션 ID)"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "track_delivery",
            "description": "택배 운송장 번호(예: 6890-1234-5678)로 실시간 배송 현황 및 배송 기사 전달 상태를 추적합니다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tracking_number": {
                        "type": "string",
                        "description": "운송장 번호"
                    }
                },
                "required": ["tracking_number"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "cancel_order",
            "description": "배송 전(결제완료/상품준비중) 단계의 주문을 취소하고 환불을 접수합니다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {
                        "type": "string",
                        "description": "취소할 주문 고유 번호 (예: ORD-20260914-001)"
                    },
                    "user_id": {
                        "type": "string",
                        "description": "주문 소유자 고객 ID"
                    }
                },
                "required": ["order_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_cart",
            "description": "현재 로그인한 고객의 장바구니 품목 목록과 총 결제 예정 금액을 조회합니다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "user_id": {
                        "type": "string",
                        "description": "고객 ID"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "add_to_cart",
            "description": "특정 상품을 장바구니에 추가합니다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "product_id": {
                        "type": "integer",
                        "description": "상품 고유 ID"
                    },
                    "quantity": {
                        "type": "integer",
                        "description": "수량 (기본값: 1)"
                    },
                    "user_id": {
                        "type": "string",
                        "description": "고객 ID"
                    }
                },
                "required": ["product_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "verify_coupon",
            "description": "공식 프로모션 할인 쿠폰 코드(예: WELCOME10, VIPSTORE)의 유효성을 검증하고 할인액을 산출합니다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "coupon_code": {
                        "type": "string",
                        "description": "쿠폰 코드"
                    },
                    "order_amount": {
                        "type": "integer",
                        "description": "주문 예정 금액 (원 단위)"
                    }
                },
                "required": ["coupon_code", "order_amount"]
            }
        }
    }
]

# -------------------------------------------------------------
# 2. Tool Execution Dispatcher with Guardrail
# -------------------------------------------------------------
class ShopToolsService:
    def __init__(self, dao: Optional[ShopDAO] = None, guardrail: Optional[ExecutionGuardrailEngine] = None):
        self.dao = dao or shop_dao
        self.guardrail = guardrail or exec_guardrail

    def execute_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        session_user_id: str = "user_vip_hong"
    ) -> Dict[str, Any]:
        """
        Layer 2.5 실행 가드레일 검증 후 도구 함수 실행
        """
        # 1. 실행 가드레일 검사
        is_allowed, v_type, err_msg = self.guardrail.validate_tool_execution(
            tool_name=tool_name,
            arguments=arguments,
            session_user_id=session_user_id
        )
        if not is_allowed:
            return {
                "status": "blocked",
                "tool": tool_name,
                "violation_type": v_type,
                "error": err_msg
            }

        # 2. 실제 비즈니스 도구 디스패칭
        if tool_name == "search_products":
            products = self.dao.search_products(
                query=arguments.get("query"),
                category=arguments.get("category"),
                min_price=arguments.get("min_price"),
                max_price=arguments.get("max_price"),
                sort_by=arguments.get("sort_by", "popular"),
                in_stock_only=arguments.get("in_stock_only", True)
            )
            return {"status": "success", "tool": tool_name, "data": products, "count": len(products)}

        elif tool_name == "get_product_detail":
            p_id = arguments.get("product_id")
            if not p_id:
                return {"status": "error", "tool": tool_name, "message": "product_id가 필요합니다."}
            product = self.dao.get_product_by_id(int(p_id))
            if product:
                return {"status": "success", "tool": tool_name, "data": product}
            return {"status": "not_found", "tool": tool_name, "message": "해당 상품을 찾을 수 없습니다."}

        elif tool_name == "get_user_orders":
            target_user = arguments.get("user_id") or session_user_id
            orders = self.dao.get_user_orders(user_id=target_user)
            return {"status": "success", "tool": tool_name, "data": orders, "count": len(orders)}

        elif tool_name == "track_delivery":
            trk = arguments.get("tracking_number", "").strip()
            order = self.dao.track_by_tracking_number(trk)
            if order:
                return {"status": "success", "tool": tool_name, "data": order}
            return {"status": "not_found", "tool": tool_name, "message": "해당 운송장 번호의 배송 정보를 찾을 수 없습니다."}

        elif tool_name == "cancel_order":
            ord_id = arguments.get("order_id", "").strip()
            target_user = arguments.get("user_id") or session_user_id
            result = self.dao.cancel_order(order_id=ord_id, user_id=target_user)
            if result.get("success"):
                return {"status": "success", "tool": tool_name, "data": result}
            return {"status": "error", "tool": tool_name, "error": result.get("error")}

        elif tool_name == "get_cart":
            target_user = arguments.get("user_id") or session_user_id
            cart = self.dao.get_cart(user_id=target_user)
            return {"status": "success", "tool": tool_name, "data": cart}

        elif tool_name == "add_to_cart":
            p_id = arguments.get("product_id")
            qty = arguments.get("quantity", 1)
            target_user = arguments.get("user_id") or session_user_id
            result = self.dao.add_to_cart(user_id=target_user, product_id=int(p_id), quantity=int(qty))
            if result.get("success"):
                return {"status": "success", "tool": tool_name, "data": result}
            return {"status": "error", "tool": tool_name, "error": result.get("error")}

        elif tool_name == "verify_coupon":
            code = arguments.get("coupon_code", "").strip()
            amt = arguments.get("order_amount", 0)
            coupon_res = self.dao.verify_coupon(code=code, order_amount=int(amt))
            return {"status": "success", "tool": tool_name, "data": coupon_res}

        return {"status": "error", "tool": tool_name, "message": f"알 수 없는 도구 이름: {tool_name}"}
