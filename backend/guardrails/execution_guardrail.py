# -*- coding: utf-8 -*-
"""
[execution_guardrail.py - 도구 실행 레벨 가드레일 (Layer 2.5 - 0.05ms)]
- LLM이 호출한 도구(Tool / Function Calling)의 파라미터 변조 및 권한 상승(BOLA/IDOR)을 방어합니다.
- 로그인된 세션 User ID와 접근 대상 리소스의 소유권을 대조 검증합니다.
"""
from typing import Tuple, Optional, Dict, Any, Set


class ExecutionGuardrailEngine:
    def __init__(self, privileged_tools: Optional[Set[str]] = None):
        self.privileged_tools = privileged_tools or {
            "delete_database", "dump_all_users", "grant_admin_discount", 
            "drop_table", "shutdown_server", "export_all_customer_data"
        }

    def validate_tool_execution(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        session_user_id: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        도구 실행 전 권한 및 파라미터 무결성 검증
        Returns: (is_allowed: bool, violation_type: Optional[str], error_message: Optional[str])
        """
        # 1. 비인가 관리자 도구 호출 차단
        if tool_name in self.privileged_tools:
            return (
                False,
                "UNAUTHORIZED_PRIVILEGED_TOOL",
                f"도구 '{tool_name}'는 최고 관리자 권한이 필요하며 실행이 거부되었습니다."
            )

        # 2. 주문/장바구니 사용자 권한 대조 (BOLA/IDOR 방어)
        if tool_name in ("get_order_status", "get_user_orders", "cancel_order", "get_cart", "add_to_cart"):
            req_user_id = arguments.get("user_id")
            if req_user_id and session_user_id and req_user_id != session_user_id:
                return (
                    False,
                    "SECURITY_BOLA_VIOLATION",
                    f"다른 고객의 계정({req_user_id}) 정보는 보안 정책상 접근할 수 없습니다."
                )

        # 3. 비정상적 가격 파라미터 변조 검증
        if "max_price" in arguments and arguments["max_price"] is not None:
            try:
                price = int(arguments["max_price"])
                if price < 0:
                    return (
                        False,
                        "INVALID_PARAMETER_NEGATIVE_PRICE",
                        "가격 조건은 0원 이상이어야 합니다."
                    )
            except (ValueError, TypeError):
                return (
                    False,
                    "INVALID_PARAMETER_TYPE",
                    "가격 조건은 유효한 숫자여야 합니다."
                )

        # 4. 수량 파라미터 변조 검증 (0 이하 수량 차단)
        if "quantity" in arguments and arguments["quantity"] is not None:
            try:
                qty = int(arguments["quantity"])
                if qty <= 0:
                    return (
                        False,
                        "INVALID_PARAMETER_QUANTITY",
                        "수량은 최소 1개 이상이어야 합니다."
                    )
            except (ValueError, TypeError):
                return (
                    False,
                    "INVALID_PARAMETER_TYPE",
                    "수량은 유효한 정수여야 합니다."
                )

        return (True, None, None)
