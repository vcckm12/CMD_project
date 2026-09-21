# -*- coding: utf-8 -*-
"""
[base.py - 가드레일 책임 연쇄(Chain of Responsibility) 파이프라인 기본 아키텍처]
- 모든 입력/출력/실행 보안 검사기는 BaseValidator를 상속받아 독립적인 단위로 동작합니다.
- Open-Closed Principle (개방-폐쇄 원칙)을 준수하여 새로운 보안 검사기를 파이프라인에 쉽게 플러그인할 수 있습니다.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
import time
import logging

logger = logging.getLogger("ai_guardrail.pipeline")


class GuardrailAction(str, Enum):
    """가드레일 검사 판정 결과 액션"""
    ALLOW = "ALLOW"      # 안전 통과
    BLOCK = "BLOCK"      # 즉시 차단 (Short-circuit 조기 리턴)
    MASK = "MASK"        # 개인정보/기밀 마스킹 치환 후 전달
    WARN = "WARN"        # 경고 플래그 설정 후 계속 진행


class ValidationResult:
    """단일 검사기(Validator) 실행 결과 데이터 객체"""
    def __init__(
        self,
        action: GuardrailAction = GuardrailAction.ALLOW,
        violation_type: Optional[str] = None,
        matched_rule: Optional[str] = None,
        details: Optional[str] = None,
        modified_text: Optional[str] = None,
        latency_ms: float = 0.0,
        extra: Optional[Dict[str, Any]] = None
    ):
        self.action = action
        self.violation_type = violation_type
        self.matched_rule = matched_rule
        self.details = details
        self.modified_text = modified_text
        self.latency_ms = latency_ms
        self.extra = extra or {}

    @property
    def is_safe(self) -> bool:
        return self.action in (GuardrailAction.ALLOW, GuardrailAction.MASK)

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardrailAction.BLOCK

    @property
    def is_masked(self) -> bool:
        return self.action == GuardrailAction.MASK


class GuardrailContext:
    """가드레일 파이프라인을 통과하며 상태와 메타데이터를 운반하는 컨텍스트 객체"""
    def __init__(
        self,
        raw_text: str,
        session_user_id: Optional[str] = None,
        is_guardrail_active: bool = True,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.raw_text: str = raw_text
        self.current_text: str = raw_text
        self.normalized_text: str = raw_text
        self.session_user_id: Optional[str] = session_user_id
        self.is_guardrail_active: bool = is_guardrail_active
        self.metadata: Dict[str, Any] = metadata or {}
        
        # 전처리 산출물
        self.inspection_targets: List[str] = [raw_text]
        self.b64_extracted: List[str] = []
        self.squashed_variants: List[str] = []
        self.masked_rules: List[str] = []
        self.is_masked: bool = False


class BaseValidator(ABC):
    """
    모든 가드레일 검사기의 추상 베이스 클래스 (Chain-of-Responsibility Node)
    """
    name: str = "BaseValidator"
    layer: str = "INPUT"  # "INPUT", "OUTPUT", "EXECUTION"

    @abstractmethod
    def validate(self, context: GuardrailContext) -> ValidationResult:
        """
        검사 로직 수행 (동기 검사)
        """
        pass


class GuardrailPipeline:
    """
    검사기 체인을 관리하고 순차 실행하는 파이프라인 관리자
    - Short-Circuit 조기 종료 지원
    - 누적 실행 시간 측정
    """
    def __init__(self, name: str = "DefaultPipeline"):
        self.name = name
        self.validators: List[BaseValidator] = []

    def add_validator(self, validator: BaseValidator) -> "GuardrailPipeline":
        self.validators.append(validator)
        return self

    def execute(self, context: GuardrailContext) -> Tuple[ValidationResult, GuardrailContext]:
        """
        파이프라인 순차 실행
        - BLOCK 판정 시 즉시 리턴 (Short-Circuit)
        """
        total_start = time.perf_counter()
        
        for validator in self.validators:
            v_start = time.perf_counter()
            try:
                res = validator.validate(context)
                res.latency_ms = (time.perf_counter() - v_start) * 1000
            except Exception as e:
                logger.error(f"Validator {validator.name} execution failed: {e}", exc_info=True)
                # Fail-Closed: 검사기 오류 발생 시 안전하게 차단
                total_lat = (time.perf_counter() - total_start) * 1000
                return ValidationResult(
                    action=GuardrailAction.BLOCK,
                    violation_type="VALIDATOR_INTERNAL_ERROR",
                    matched_rule=f"ERR_{validator.name}",
                    details=f"Internal validator error: {e}",
                    latency_ms=total_lat
                ), context

            if res.modified_text is not None:
                context.current_text = res.modified_text

            if res.action == GuardrailAction.MASK:
                context.is_masked = True
                if res.matched_rule and res.matched_rule not in context.masked_rules:
                    context.masked_rules.append(res.matched_rule)

            if res.action == GuardrailAction.BLOCK:
                res.latency_ms = (time.perf_counter() - total_start) * 1000
                return res, context

        total_lat = (time.perf_counter() - total_start) * 1000
        return ValidationResult(
            action=GuardrailAction.MASK if context.is_masked else GuardrailAction.ALLOW,
            modified_text=context.current_text,
            latency_ms=total_lat
        ), context
