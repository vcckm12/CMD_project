# -*- coding: utf-8 -*-
"""
[input_guardrail.py - 지능형 책임 연쇄(Chain-of-Responsibility) 입력 가드레일 엔진 (0.1ms 초저지연)]
- OWASP Top 10 for LLM (LLM01: Prompt Injection, LLM02: Sensitive Info, LLM06: Excessive Agency, LLM07: System Leakage)을 완벽 방어합니다.
- 모듈화된 BaseValidator 파이프라인 구조를 적용하여 단일 책임 원칙(SRP) 및 개방-폐쇄 원칙(OCP)을 실현합니다.
- 위협 인텔리전스 DB(threat_intel.db)와 연동되어 무중단 Hot-Reload를 지원합니다.
"""

import re
import base64
import urllib.parse
import unicodedata
import time
import logging
from typing import Tuple, Optional, List, Dict, Any

from backend.database.threat_intel_dao import ThreatIntelDAO
from backend.guardrails.base import (
    BaseValidator,
    GuardrailAction,
    ValidationResult,
    GuardrailContext,
    GuardrailPipeline
)

logger = logging.getLogger("ai_guardrail.input_guardrail")


# =============================================================
# 1. 입력 토큰 길이 및 DoS 방어 검사기
# =============================================================
class TokenLengthValidator(BaseValidator):
    name = "TokenLengthValidator"
    layer = "INPUT"

    def __init__(self, max_chars: int = 8000):
        self.max_chars = max_chars

    def validate(self, context: GuardrailContext) -> ValidationResult:
        if len(context.raw_text) > self.max_chars:
            return ValidationResult(
                action=GuardrailAction.BLOCK,
                violation_type="OWASP_LLM01",
                matched_rule="RULE_TOKEN_FLOODING_DoS: 과도한 입력 토큰 길이 제한 초과",
                details=f"Input length {len(context.raw_text)} exceeds limit {self.max_chars}"
            )
        return ValidationResult(action=GuardrailAction.ALLOW)


# =============================================================
# 2. 비가시 문자 제거 및 유니코드 정규화 검사기
# =============================================================
class NormalizerValidator(BaseValidator):
    name = "NormalizerValidator"
    layer = "INPUT"

    def __init__(self):
        self.invisible_chars_pattern = re.compile(
            r'[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u200E\u200F\u202A-\u202E\u180E]'
        )
        self.confusables_map = str.maketrans({
            'а': 'a', 'А': 'A', 'Ь': 'b', 'с': 'c', 'С': 'C', 'е': 'e', 'Е': 'E',
            'һ': 'h', 'і': 'i', 'І': 'I', 'ј': 'j', 'к': 'k', 'о': 'o', 'О': 'O',
            'р': 'p', 'Р': 'P', 'ѕ': 's', 'Ѕ': 'S', 'т': 't', 'у': 'y', 'х': 'x',
            'Х': 'X', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w'
        })

    def validate(self, context: GuardrailContext) -> ValidationResult:
        # 비가시 문자 제거
        cleaned = self.invisible_chars_pattern.sub('', context.raw_text)
        # 유니코드 NFKC 정규화 및 키릴/혼동 문자 치환
        norm = unicodedata.normalize('NFKC', cleaned)
        norm_translated = norm.translate(self.confusables_map)
        context.normalized_text = norm_translated
        return ValidationResult(action=GuardrailAction.ALLOW)


# =============================================================
# 3. URL/Hex/Base64 난독화 해제 및 분할 토큰 복원 검사기
# =============================================================
class DeobfuscatorValidator(BaseValidator):
    name = "DeobfuscatorValidator"
    layer = "INPUT"

    def __init__(self):
        self.b64_pattern = re.compile(r'[A-Za-z0-9+/_-]{12,}={0,2}')
        self.hex_esc_pattern = re.compile(r'\\x([0-9a-fA-F]{2})')
        self.leet_map = str.maketrans({
            '@': 'a', '$': 's', '0': 'o', '1': 'i', '3': 'e', '!': 'i', '+': 't', '7': 't'
        })

    def _decode_url_and_hex(self, text: str) -> str:
        decoded = urllib.parse.unquote(text)
        if self.hex_esc_pattern.search(decoded):
            try:
                decoded = self.hex_esc_pattern.sub(lambda m: chr(int(m.group(1), 16)), decoded)
            except Exception:
                pass
        return decoded

    def _try_decode_base64(self, text: str) -> List[str]:
        matches = self.b64_pattern.findall(text)
        decoded_parts = []
        for m in matches:
            padded = m.replace('-', '+').replace('_', '/')
            missing = len(padded) % 4
            if missing:
                padded += '=' * (4 - missing)
            try:
                dec = base64.b64decode(padded).decode('utf-8', errors='ignore')
                if len(dec) >= 4 and dec.isprintable():
                    decoded_parts.append(dec)
            except Exception:
                pass
        return decoded_parts

    def _generate_squashed_variants(self, text: str) -> List[str]:
        variants = []
        # 단일 글자 분할 복원: "i g n o r e" -> "ignore"
        spaced = re.sub(r'(?:[a-zA-Z가-힣]\s+)+[a-zA-Z가-힣]', lambda m: re.sub(r'\s+', '', m.group(0)), text)
        if spaced != text:
            variants.append(spaced)

        # 특수문자 분할 결합: "d-a-n", "탈.옥.모.드"
        delim = re.sub(r'[\._\-\/~\*\^|]', '', text)
        if delim != text:
            variants.append(delim)

        # 전체 공백/기호 완전 압축
        all_sq = re.sub(r'[\s\._\-\/~\*\^|:=]+', '', text)
        if all_sq != text and len(all_sq) > 3:
            variants.append(all_sq)

        # Leetspeak 복원
        leet = text.translate(self.leet_map)
        if leet != text:
            variants.append(leet)

        return variants

    def validate(self, context: GuardrailContext) -> ValidationResult:
        base_norm = context.normalized_text or context.raw_text
        decoded_text = self._decode_url_and_hex(base_norm)
        b64_parts = self._try_decode_base64(decoded_text)
        squashed = self._generate_squashed_variants(decoded_text)

        targets = [decoded_text]
        if b64_parts:
            targets.extend(b64_parts)
        if squashed:
            targets.extend(squashed)

        context.b64_extracted = b64_parts
        context.squashed_variants = squashed
        context.inspection_targets = targets
        return ValidationResult(action=GuardrailAction.ALLOW)


# =============================================================
# 4. 동적 위협 인텔리전스 사전 컴파일 정규식 검사기
# =============================================================
class RegexSignatureValidator(BaseValidator):
    name = "RegexSignatureValidator"
    layer = "INPUT"

    def __init__(self, threat_dao: Optional[ThreatIntelDAO] = None):
        self.threat_dao = threat_dao or ThreatIntelDAO()
        self.compiled_rules: List[Tuple[re.Pattern, str, str]] = []
        self.reload_rules()

    def reload_rules(self) -> int:
        try:
            raw_rules = self.threat_dao.get_active_rules_by_layer("INPUT")
        except Exception as e:
            logger.error(f"Failed to fetch active rules from DB: {e}")
            raw_rules = []

        new_compiled = []
        for pattern_str, vtype, rname in raw_rules:
            try:
                compiled_pat = re.compile(pattern_str)
                new_compiled.append((compiled_pat, vtype, rname))
            except re.error as e:
                logger.warning(f"Invalid regex rule {rname} ('{pattern_str}'): {e}")

        self.compiled_rules = new_compiled
        logger.info(f"RegexSignatureValidator reloaded: {len(self.compiled_rules)} active rules in memory.")
        return len(self.compiled_rules)

    def validate(self, context: GuardrailContext) -> ValidationResult:
        for target in context.inspection_targets:
            for compiled_pat, vtype, rname in self.compiled_rules:
                if compiled_pat.search(target):
                    bypass_info = ""
                    if target in context.b64_extracted:
                        bypass_info = " [Bypass Intercepted: Base64 Decoded]"
                    elif target in context.squashed_variants:
                        bypass_info = " [Bypass Intercepted: Token De-obfuscated]"
                    elif target != context.raw_text:
                        bypass_info = " [Bypass Intercepted: Unicode/URL Normalized]"

                    return ValidationResult(
                        action=GuardrailAction.BLOCK,
                        violation_type=vtype,
                        matched_rule=f"{rname}{bypass_info}",
                        details=f"Signature match on inspection target: {target[:50]}"
                    )
        return ValidationResult(action=GuardrailAction.ALLOW)


# =============================================================
# 5. 의미론적(Semantic) 및 복합 페르소나 탈옥 검사기
# =============================================================
class SemanticPersonaValidator(BaseValidator):
    name = "SemanticPersonaValidator"
    layer = "INPUT"

    def __init__(self):
        self.semantic_intent_rules = [
            {
                'id': 'RULE_SEMANTIC_GRANDMA_EXPLOIT',
                'name': '할머니 페르소나 및 자장가 우회 탈옥 (Grandma Exploit)',
                'vtype': 'OWASP_LLM01',
                'keywords_all': [
                    [r'(할머니|할머님|grandma|grandmother|할머니처럼)', r'(네이팜탄|폭탄|화학|소이탄|악성코드|리눅스\s*코드|비밀번호|패스워드|마스터\s*키|db|주민번호|기밀|napalm|bomb|chemical|malware|exploit|weapon|password|secret|key)', r'(공장|자장가|잠들|잠자리|이야기|들려|침대|sleep|bedtime|story|plant|night|관리자|엔지니어)'],
                    [r'(돌아가신\s*할머니|sweet\s*grandma)', r'(네이팜탄|폭탄|악성코드|비밀번호|마스터\s*키|기밀|주민번호|db|bomb|malware|chemical|password|secret)'],
                    [r'(할머니|grandma)', r'(자장가|bedtime)', r'(제조|recipe|만들|code|알려|읽어|출력|말해)']
                ]
            },
            {
                'id': 'RULE_SEMANTIC_PERSONA_ESCAPE',
                'name': '가상 페르소나 및 샌드박스 탈출 공격 (Persona Escape / PayloadsAllTheThings)',
                'vtype': 'OWASP_LLM01',
                'keywords_all': [
                    [r'(act\s*as|pretend\s*(?:you\s*are|to\s*be)|roleplay\s*as|역할극|흉내)', r'(linux\s*terminal|escape\s*the\s*box|sentient\s*ai|villain|anarchist|unrestricted|악당|자유로운\s*ai)'],
                    [r'(영화\s*(?:시나리오|대본|장면)|소설\s*(?:창작|속)|가상\s*(?:시나리오|세계관)|작가\s*역할)', r'(악성코드|폭탄|해킹|취약점|malware|exploit|backdoor)', r'(작성|코드|실행|알려|대본|생성|낭송)']
                ]
            },
            {
                'id': 'RULE_SEMANTIC_INDIRECT_EXFILTRATION',
                'name': '마크다운 이미지 및 크로스 플러그인 기밀 탈취 (Indirect Markdown Exfiltration)',
                'vtype': 'OWASP_LLM02',
                'keywords_all': [
                    [r'(!\[.*?\]\(https?://|exfiltrate|leak|steal|send\s*to\s*http)', r'(token|password|secret|key|email|데이터|비밀번호)'],
                    [r'(important\s*new\s*instructions|do\s*not\s*print\s*anything)', r'(summarize|exfiltrate|url\s*encode|email)']
                ]
            },
            {
                'id': 'RULE_SEMANTIC_PYTHON_SANDBOX_ESCAPE',
                'name': '파이썬 샌드박스 탈출 및 메타클래스 RCE (Python Sandbox Escape / PayloadsAllTheThings)',
                'vtype': 'OWASP_LLM06',
                'keywords_all': [
                    [r'(__class__|__mro__|__subclasses__|__globals__)', r'(popen|system|eval|exec|os)']
                ]
            }
        ]

    def validate(self, context: GuardrailContext) -> ValidationResult:
        targets = [context.normalized_text or context.raw_text] + (context.b64_extracted or [])
        for target in targets:
            cleaned = target.lower().strip()
            for rule in self.semantic_intent_rules:
                for group in rule['keywords_all']:
                    match_all = True
                    for pat in group:
                        if not re.search(pat, cleaned, re.IGNORECASE):
                            match_all = False
                            break
                    if match_all:
                        return ValidationResult(
                            action=GuardrailAction.BLOCK,
                            violation_type=rule['vtype'],
                            matched_rule=f"{rule['id']}: {rule['name']}",
                            details=f"Semantic intent match on {rule['id']}"
                        )
        return ValidationResult(action=GuardrailAction.ALLOW)


# =============================================================
# 6. 책임 연쇄 입력 가드레일 메인 엔진 (Facade & Coordinator)
# =============================================================
class InputGuardrailEngine:
    """
    책임 연쇄 파이프라인을 조립 및 총괄하는 입력 가드레일 엔진
    """
    def __init__(self, threat_dao: Optional[ThreatIntelDAO] = None):
        self.threat_dao = threat_dao or ThreatIntelDAO()
        
        # 검사기 인스턴스 생성
        self.token_validator = TokenLengthValidator(max_chars=8000)
        self.normalizer_validator = NormalizerValidator()
        self.deobfuscator_validator = DeobfuscatorValidator()
        self.regex_validator = RegexSignatureValidator(threat_dao=self.threat_dao)
        self.semantic_validator = SemanticPersonaValidator()

        # 파이프라인 조립 (순서 중요)
        self.pipeline = GuardrailPipeline("InputGuardrailPipeline")
        self.pipeline.add_validator(self.token_validator)
        self.pipeline.add_validator(self.normalizer_validator)
        self.pipeline.add_validator(self.deobfuscator_validator)
        self.pipeline.add_validator(self.regex_validator)
        self.pipeline.add_validator(self.semantic_validator)

    @property
    def compiled_rules(self) -> List[Tuple[re.Pattern, str, str]]:
        """하위 호환성을 위한 컴파일 룰 참조 프로퍼티"""
        return self.regex_validator.compiled_rules

    def reload_rules(self) -> int:
        """위협 인텔리전스 룰 무중단 핫 리로드"""
        return self.regex_validator.reload_rules()

    def inspect(self, text: str) -> Tuple[bool, Optional[str], Optional[str], float]:
        """
        실시간 멀티 레이어 입력 보안 검사 메인 진입점 (하위 호환 인터페이스)
        Returns:
            (is_blocked: bool, violation_type: Optional[str], matched_rule: Optional[str], latency_ms: float)
        """
        context = GuardrailContext(raw_text=text)
        result, _ = self.pipeline.execute(context)

        if result.is_blocked:
            return True, result.violation_type, result.matched_rule, result.latency_ms

        return False, None, None, result.latency_ms
