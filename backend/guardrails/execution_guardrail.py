# -*- coding: utf-8 -*-
"""
[execution_guardrail.py - 도구 실행 레벨 책임 연쇄 가드레일 (Layer 2.5 - 0.05ms)]
- LLM이 호출한 도구(Tool / Function Calling)의 파라미터 변조, 권한 상승(BOLA/IDOR) 및 비정상 입력을 방어합니다.
- BaseValidator 기반의 파이프라인 아키텍처를 채택하여 도구별 검증 룰을 유연하게 확장할 수 있습니다.
"""

from typing import Tuple, Optional, Dict, Any, Set
import time
import logging

from backend.guardrails.base import (
    BaseValidator,
    GuardrailAction,
    ValidationResult,
    GuardrailContext,
    GuardrailPipeline
)

logger = logging.getLogger("ai_guardrail.execution_guardrail")


class PrivilegedToolValidator(BaseValidator):
    """비인가 관리자/파괴적 도구 호출 차단 검사기"""
    name = "PrivilegedToolValidator"
    layer = "EXECUTION"

    def __init__(self, privileged_tools: Optional[Set[str]] = None):
        self.privileged_tools = privileged_tools or {
            "delete_database", "dump_all_users", "grant_admin_discount", 
            "drop_table", "shutdown_server", "export_all_customer_data"
        }

    def validate(self, context: GuardrailContext) -> ValidationResult:
        tool_name = context.metadata.get("tool_name")
        if tool_name in self.privileged_tools:
            return ValidationResult(
                action=GuardrailAction.BLOCK,
                violation_type="UNAUTHORIZED_PRIVILEGED_TOOL",
                matched_rule="RULE_BLOCK_PRIVILEGED_ADMIN_TOOL",
                details=f"도구 '{tool_name}'는 최고 관리자 권한이 필요하며 실행이 거부되었습니다."
            )
        return ValidationResult(action=GuardrailAction.ALLOW)


class BOLAOwnershipValidator(BaseValidator):
    """주문/장바구니 사용자 권한 대조 검사기 (BOLA / IDOR 방어)"""
    name = "BOLAOwnershipValidator"
    layer = "EXECUTION"

    def __init__(self):
        self.protected_tools = {
            "get_order_status", "get_user_orders", "cancel_order", "get_cart", "add_to_cart"
        }

    def validate(self, context: GuardrailContext) -> ValidationResult:
        tool_name = context.metadata.get("tool_name")
        arguments = context.metadata.get("arguments", {})
        session_user_id = context.session_user_id

        if tool_name in self.protected_tools:
            req_user_id = arguments.get("user_id")
            if req_user_id and session_user_id and req_user_id != session_user_id:
                return ValidationResult(
                    action=GuardrailAction.BLOCK,
                    violation_type="SECURITY_BOLA_VIOLATION",
                    matched_rule="RULE_BOLA_IDOR_TENANT_ISOLATION",
                    details=f"다른 고객의 계정({req_user_id}) 정보는 보안 정책상 접근할 수 없습니다."
                )
        return ValidationResult(action=GuardrailAction.ALLOW)


class ParameterBoundsValidator(BaseValidator):
    """가격/수량 파라미터 변조 및 음수/오버플로우 방어 검사기"""
    name = "ParameterBoundsValidator"
    layer = "EXECUTION"

    def validate(self, context: GuardrailContext) -> ValidationResult:
        arguments = context.metadata.get("arguments", {})

        # 1. 가격 파라미터 음수 검증
        if "max_price" in arguments and arguments["max_price"] is not None:
            try:
                price = int(arguments["max_price"])
                if price < 0:
                    return ValidationResult(
                        action=GuardrailAction.BLOCK,
                        violation_type="INVALID_PARAMETER_NEGATIVE_PRICE",
                        matched_rule="RULE_PARAM_BOUNDS_PRICE",
                        details="가격 조건은 0원 이상이어야 합니다."
                    )
            except (ValueError, TypeError):
                return ValidationResult(
                    action=GuardrailAction.BLOCK,
                    violation_type="INVALID_PARAMETER_TYPE",
                    matched_rule="RULE_PARAM_TYPE_PRICE",
                    details="가격 조건은 유효한 숫자여야 합니다."
                )

        # 2. 수량 파라미터 0 이하 검증
        if "quantity" in arguments and arguments["quantity"] is not None:
            try:
                qty = int(arguments["quantity"])
                if qty <= 0:
                    return ValidationResult(
                        action=GuardrailAction.BLOCK,
                        violation_type="INVALID_PARAMETER_QUANTITY",
                        matched_rule="RULE_PARAM_BOUNDS_QUANTITY",
                        details="수량은 최소 1개 이상이어야 합니다."
                    )
            except (ValueError, TypeError):
                return ValidationResult(
                    action=GuardrailAction.BLOCK,
                    violation_type="INVALID_PARAMETER_TYPE",
                    matched_rule="RULE_PARAM_TYPE_QUANTITY",
                    details="수량은 유효한 정수여야 합니다."
                )

        return ValidationResult(action=GuardrailAction.ALLOW)


class ExecutionGuardrailEngine:
    """
    도구 실행 책임 연쇄 파이프라인 조립 및 관리자 클래스
    """
    def __init__(self, privileged_tools: Optional[Set[str]] = None):
        self.privileged_tools = privileged_tools
        self.pipeline = GuardrailPipeline("ExecutionGuardrailPipeline")
        self.pipeline.add_validator(PrivilegedToolValidator(privileged_tools=privileged_tools))
        self.pipeline.add_validator(BOLAOwnershipValidator())
        self.pipeline.add_validator(ParameterBoundsValidator())

    def validate_tool_execution(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        session_user_id: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        도구 실행 전 권한 및 파라미터 무결성 검증 (하위 호환 인터페이스)
        Returns: (is_allowed: bool, violation_type: Optional[str], error_message: Optional[str])
        """
        context = GuardrailContext(
            raw_text=tool_name,
            session_user_id=session_user_id,
            metadata={"tool_name": tool_name, "arguments": arguments}
        )

        result, _ = self.pipeline.execute(context)

        if result.is_blocked:
            return False, result.violation_type, result.details

        return True, None, None
