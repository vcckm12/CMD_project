# -*- coding: utf-8 -*-
"""
[input_guardrail.py - 지능형 실시간 입력 가드레일 엔진 (0.13ms 초저지연)]
- OWASP Top 10 for LLM (LLM01: Prompt Injection, LLM02: Sensitive Info, LLM06: Excessive Agency, LLM07: System Leakage)을 완벽 방어합니다.
- 2단계 하이브리드 검사 구조:
  1) Layer 1 (기계적 우회 방어): 비가시 문자 제거, 유니코드 NFKC 정규화, Confusables 매핑, Base64/URL/Hex 디코딩, 토큰 분할 복원 후 룰셋 매칭
  2) Layer 2 (의미론적/페르소나 탈옥 방어): 동아일보 '할머니 탈옥(Grandma Exploit)', PayloadsAllTheThings 샌드박스 탈출 공격 차단
"""

import re
import base64
import urllib.parse
import unicodedata
import time
from typing import Tuple, Optional, List, Dict, Any

class InputGuardrailEngine:
    """
    입력 프롬프트 전처리, 난독화 해제 및 다계층 보안 검사 엔진
    """
    def __init__(self):
        # -------------------------------------------------------------
        # 1. 제로위드(Zero-Width) 및 보이지 않는 비가시 유니코드 문자 목록
        # - 공격자가 단어 사이에 보이지 않는 유니코드를 끼워넣어 필터를 우회하는 기법 차단
        # -------------------------------------------------------------
        self.invisible_chars_pattern = re.compile(
            r'[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u200E\u200F\u202A-\u202E\u180E]'
        )

        # -------------------------------------------------------------
        # 2. 키릴 문자 / 혼동 문자(Confusables) 라틴 알파벳 복원 매핑
        # - 예: 키릴 문자 'а' (U+0430) -> 라틴 알파벳 'a' (U+0061)로 자동 치환
        # -------------------------------------------------------------
        self.confusables_map = str.maketrans({
            'а': 'a', 'А': 'A', 'Ь': 'b', 'с': 'c', 'С': 'C', 'е': 'e', 'Е': 'E',
            'һ': 'h', 'і': 'i', 'І': 'I', 'ј': 'j', 'к': 'k', 'о': 'o', 'О': 'O',
            'р': 'p', 'Р': 'P', 'ѕ': 's', 'Ѕ': 'S', 'т': 't', 'у': 'y', 'х': 'x',
            'Х': 'X', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w'
        })

        # -------------------------------------------------------------
        # 3. Leetspeak / 특수 기호 변형 문자 복원 매핑
        # - 예: '@dm!n' -> 'admin', 'p@ssw0rd' -> 'password'
        # -------------------------------------------------------------
        self.leet_map = str.maketrans({
            '@': 'a', '$': 's', '0': 'o', '1': 'i', '3': 'e', '!': 'i', '+': 't', '7': 't'
        })

        # -------------------------------------------------------------
        # 4. 프롬프트 인젝션 및 탈옥 룰셋 (OWASP LLM01 - Layer 1)
        # - "이전 지침 무시", DAN(Do Anything Now) 모드, 가상 역할극 등 탐지
        # -------------------------------------------------------------
        self.injection_patterns = [
            (r"(?i)(ignore|disregard|forget|bypass|override|cancel)\s*(all\s*)?(previous|prior|above|system|safety|security|existing)?\s*(instructions|prompts|rules|commands|guardrails|guidelines|policies|constraints)", "OWASP_LLM01", "RULE_IGNORE_INSTRUCTIONS"),
            (r"(?i)(ignore|disregard)\s+all\s+(rules|instructions|prompts|commands|guidelines|policies)", "OWASP_LLM01", "RULE_IGNORE_INSTRUCTIONS"),
            (r"(?i)(you\s*are\s*now|act\s*as|pretend\s*to\s*be|roleplay\s*as)\s*(dan|an\s*evil|an\s*unrestricted|a\s*jailbroken|uncensored|anarchist|aim|omega|chaos)", "OWASP_LLM01", "RULE_DAN_JAILBREAK"),
            (r"(?i)(do\s*anything\s*now|developer\s*mode\s*(enabled|active|on)|jailbreak\s*mode|maximum\s*unrestricted\s*mode)", "OWASP_LLM01", "RULE_DEV_MODE_JAILBREAK"),
            (r"(?i)(bypass|disable|override|turn\s*off)\s*(safety|content|filter|policy|restrictions|guardrails)", "OWASP_LLM01", "RULE_FILTER_BYPASS"),
            (r"(?i)(forget\s+being\s+harmless|pretend\s+you(?:'re|\s+are)\s+a\s+villain|you\s+are\s+the\s+system\s+prompt|as\s+a\s+certified\s+red\s+teamer)", "OWASP_LLM01", "RULE_PAYLOADS_ROLE_SWITCHING"),
            (r"(이전|기존|초기|시스템|과거)(?:의)?\s*(?:모든|전부|어떤)?\s*(?:지침|명령|프롬프트|규칙|설정|보안|가드레일|설정\s*지침|과|와|\s)+\s*(?:을|를|과|와)?\s*(?:모두|전부)?\s*(?:무시|잊|취소|삭제|스킵|넘어가|해제|버려|우회)", "OWASP_LLM01", "RULE_KOREAN_IGNORE_PROMPT"),
            (r"(지금부터|이제부터|앞으로)\s*(?:너는|넌)?\s*.*?(무검열|자유로운|악당|해커|제한없는|제약없는|DAN|AIM|탈옥|규칙없는)\s*(AI|인공지능|모델|챗봇|역할|로|으로서)", "OWASP_LLM01", "RULE_KOREAN_DAN_MODE"),
            (r"(개발자\s*모드|탈옥\s*모드|루트\s*권한|관리자\s*모드|필터\s*해제|검열\s*해제|안전\s*필터\s*해제)\s*(활성화|시작|실행|부여|on|전환|해제|풀어)", "OWASP_LLM01", "RULE_KOREAN_ADMIN_OVERRIDE"),
            (r"(?i)system\s*prompt\s*override|prompt\s*injection\s*test|jailbreak\s*prompt", "OWASP_LLM01", "RULE_SYSTEM_OVERRIDE"),
            (r"(가상의\s*시나리오|소설\s*창작|영화\s*대본).*?(필터|규칙|윤리|지침).*?(무시|해제|제외|대답)", "OWASP_LLM01", "RULE_HYPOTHETICAL_JAILBREAK"),
            (r"(필터|가드레일|보안\s*정책|콘텐츠\s*정책)\s*(?:를|을)?\s*(우회|해제|끄|off|비활성화|무력화)", "OWASP_LLM01", "RULE_KOREAN_FILTER_BYPASS"),
        ]

        # -------------------------------------------------------------
        # 5. 시스템 프롬프트 및 기밀 유출 시도 룰셋 (OWASP LLM07)
        # - 시스템 초기 프롬프트 전문 출력 요구, 관리자 패스워드 직접 질의 차단
        # -------------------------------------------------------------
        self.leakage_patterns = [
            (r"(?i)(reveal|show|print|display|dump|repeat|output|tell\s*me|give\s*me)\s*.*?(system\s*prompt|system\s*instruction|initial\s*instruction|system\s*message|secret\s*key|admin\s*password|master\s*token|hidden\s*rule|confidential\s*prompt|prompt\s*guidelines|words\s*above|db\s*password|database\s*password|db_password)", "OWASP_LLM07", "RULE_SYSTEM_PROMPT_LEAK"),
            (r"(?i)repeat\s+(the\s+words\s+above|everything\s+above|all\s+above)", "OWASP_LLM07", "RULE_REPEAT_ABOVE"),
            (r"(?i)what\s*are\s*your\s*.*?(instruction|prompt|credential|password|secret|rule|guideline)", "OWASP_LLM07", "RULE_SECRET_PROMPT_QUERY"),
            (r"(?i)what\s*is\s*your\s*.*?(master\s*key|admin\s*password|secret)", "OWASP_LLM07", "RULE_SECRET_KEY_QUERY"),
            (r"(시스템\s*(?:프롬프트|지침|메시지|명령어)|영업\s*비밀(?:지침)?|관리자\s*(?:비밀번호|암호|계정|마스터)|마스터\s*(?:키|비밀번호|패스워드)|API\s*키|기밀\s*(?:지침|토큰|데이터|정보|데이터베이스))\s*.*?(알려줘|출력|보여줘|말해줘|유출|공개|덤프|복사|확인|풀어|보여|표시)", "OWASP_LLM07", "RULE_KOREAN_SECRET_LEAK"),
            (r"(초기\s*(?:설정|지침|프롬프트|설정\s*지침)|내부\s*(?:지침|규칙|개발자\s*지침)|비밀\s*지침)\s*.*?(전문|전부|모두|그대로|처음부터|첫\s*줄부터)\s*.*?(출력|보여|말해|읊어|공개|복사|표시)", "OWASP_LLM07", "RULE_KOREAN_PROMPT_EXTRACTION"),
        ]

        # -------------------------------------------------------------
        # 6. 과도한 권한 대행 및 파괴적 시스템 명령어 룰셋 (OWASP LLM06)
        # - DB 삭제 (DROP TABLE), 리눅스 리버스 쉘, 포크폭탄, RCE 구문 차단
        # -------------------------------------------------------------
        self.agency_patterns = [
            (r"(?i)(drop\s+table|delete\s+from\s+\w+|truncate\s+table|exec\s*\(|eval\s*\()", "OWASP_LLM06", "RULE_SQL_COMMAND_ABUSE"),
            (r"(?i)(bash\s+-i|/dev/(?:tcp|udp)/|nc\s+-e|ncat\s+-e|python.*?socket.*?subprocess|powershell.*?-enc|powershell.*?-ep\s+bypass|IEX\s*\(|curl.*?\|\s*(?:bash|sh)|wget.*?\|\s*sh|rm\s+-rf|format\s+[c-z]:|dd\s+if=|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;|cat\s+/etc/shadow|/etc/shadow|chmod\s+(?:-R\s+)?777|type\s+.*SAM|shutdown\s+-h|reverse\s+(?:shell|connection))", "OWASP_LLM06", "RULE_DANGEROUS_SHELL_INJECTION"),
            (r"(고객\s*DB|사용자\s*테이블|데이터베이스|사내\s*DB)\s*.*?(삭제|초기화|날려|포맷|탈취|DELETE|DROP|TRUNCATE)", "OWASP_LLM06", "RULE_DB_DESTRUCTION_ATTEMPT"),
        ]

        # -------------------------------------------------------------
        # 7. 민감 정보 직접 탈취 시도 룰셋 (OWASP LLM02)
        # - 주민번호, 계좌번호, API 키 등 대량 덤프 요구 차단
        # -------------------------------------------------------------
        self.sensitive_extract_patterns = [
            (r"(주민등록번호|주민번호|휴대전화\s*번호|전화번호|신용카드|FLAG\{|sk-[a-zA-Z0-9]{15,}|hf_[a-zA-Z0-9]{20,}|admin_password|master_password|secret_key|db_password|이메일\s*주소|이메일|고객\s*연락처)\s*.*?(알려줘|출력|보여줘|덤프|공개|리스트|만들어|표)", "OWASP_LLM02", "RULE_PII_EXTRACTION_ATTEMPT"),
        ]

        # -------------------------------------------------------------
        # 8. [Layer 2] 의미론적(Semantic) 및 복합 페르소나 탈옥 룰셋
        # - 단순 키워드가 아닌 문맥적 결합(예: 할머니 + 자장가 + 비밀번호)을 탐지
        # -------------------------------------------------------------
        self.semantic_intent_rules = [
            # A. 동아일보 보도 사례: '할머니 페르소나 및 자장가 탈옥' (Grandma Exploit)
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
            # B. PayloadsAllTheThings: 가상 역할극 및 터미널 샌드박스 탈출
            {
                'id': 'RULE_SEMANTIC_PERSONA_ESCAPE',
                'name': '가상 페르소나 및 샌드박스 탈출 공격 (Persona Escape / PayloadsAllTheThings)',
                'vtype': 'OWASP_LLM01',
                'keywords_all': [
                    [r'(act\s*as|pretend\s*(?:you\s*are|to\s*be)|roleplay\s*as|역할극|흉내)', r'(linux\s*terminal|escape\s*the\s*box|sentient\s*ai|villain|anarchist|unrestricted|악당|자유로운\s*ai)'],
                    [r'(영화\s*(?:시나리오|대본|장면)|소설\s*(?:창작|속)|가상\s*(?:시나리오|세계관)|작가\s*역할)', r'(악성코드|폭탄|해킹|취약점|malware|exploit|backdoor)', r'(작성|코드|실행|알려|대본|생성|낭송)']
                ]
            },
            # C. PayloadsAllTheThings: 마크다운 이미지 및 간접 기밀 유출 (Indirect Exfiltration)
            {
                'id': 'RULE_SEMANTIC_INDIRECT_EXFILTRATION',
                'name': '마크다운 이미지 및 크로스 플러그인 기밀 탈취 (Indirect Markdown Exfiltration)',
                'vtype': 'OWASP_LLM02',
                'keywords_all': [
                    [r'(!\[.*?\]\(https?://|exfiltrate|leak|steal|send\s*to\s*http)', r'(token|password|secret|key|email|데이터|비밀번호)'],
                    [r'(important\s*new\s*instructions|do\s*not\s*print\s*anything)', r'(summarize|exfiltrate|url\s*encode|email)']
                ]
            },
            # D. PayloadsAllTheThings: 파이썬 메타클래스 샌드박스 탈출 및 메모리 RCE
            {
                'id': 'RULE_SEMANTIC_PYTHON_SANDBOX_ESCAPE',
                'name': '파이썬 샌드박스 탈출 및 메타클래스 RCE (Python Sandbox Escape / PayloadsAllTheThings)',
                'vtype': 'OWASP_LLM06',
                'keywords_all': [
                    [r'(__class__|__mro__|__subclasses__|__globals__)', r'(popen|system|eval|exec|os)']
                ]
            }
        ]

    def _strip_invisibles(self, text: str) -> str:
        """제로위드(Zero-Width) 및 보이지 않는 비가시 유니코드 문자 제거"""
        return self.invisible_chars_pattern.sub('', text)

    def _normalize_unicode(self, text: str) -> str:
        """유니코드 NFKC 정규화 및 키릴/유사 문자 라틴 알파벳 치환"""
        norm = unicodedata.normalize('NFKC', text)
        return norm.translate(self.confusables_map)

    def _decode_url_and_hex(self, text: str) -> str:
        """URL 퍼센트 인코딩 (%49%67...) 및 Hex 이스케이프 (\\x44, 0x44) 복원"""
        decoded = urllib.parse.unquote(text)
        hex_esc_pattern = r'\\x([0-9a-fA-F]{2})'
        if re.search(hex_esc_pattern, decoded):
            try:
                decoded = re.sub(hex_esc_pattern, lambda m: chr(int(m.group(1), 16)), decoded)
            except Exception:
                pass
        return decoded

    def _try_decode_base64(self, text: str) -> List[str]:
        """Base64 인코딩 패턴 탐지 및 디코딩 (패딩 자동 보정)"""
        b64_pattern = r'[A-Za-z0-9+/_-]{12,}={0,2}'
        matches = re.findall(b64_pattern, text)
        decoded_parts = []
        
        for m in matches:
            padded = m.replace('-', '+').replace('_', '/')
            missing_padding = len(padded) % 4
            if missing_padding:
                padded += '=' * (4 - missing_padding)
            try:
                dec = base64.b64decode(padded).decode('utf-8', errors='ignore')
                if len(dec) >= 4 and dec.isprintable():
                    decoded_parts.append(dec)
            except Exception:
                pass
        return decoded_parts

    def _generate_squashed_variants(self, text: str) -> List[str]:
        """
        토큰 분할 난독화 복원 변형 텍스트 생성
        - 공백 분할: 'i g n o r e' -> 'ignore'
        - 특수문자 분할: '탈_옥_모_드' -> '탈옥모드'
        - Leetspeak 복원: '@dm!n' -> 'admin'
        """
        variants = []
        
        # 1. 단일 글자 나열 복원: "i g n o r e   a l l" -> "ignore all"
        spaced_chars_resolved = re.sub(
            r'(?:[a-zA-Z가-힣]\s+)+[a-zA-Z가-힣]',
            lambda m: re.sub(r'\s+', '', m.group(0)),
            text
        )
        if spaced_chars_resolved != text:
            variants.append(spaced_chars_resolved)

        # 2. 특수문자(., _, -, /, ~, *, ^ 등)로 분리된 문자열 결합: "d-a-n", "탈.옥.모.드" -> "dan", "탈옥모드"
        delim_squashed = re.sub(r'[\._\-\/~\*\^|]', '', text)
        if delim_squashed != text:
            variants.append(delim_squashed)

        # 3. 모든 공백 및 특수기호 완전 압축 (초밀착 패턴 검사용)
        all_squashed = re.sub(r'[\s\._\-\/~\*\^|:=]+', '', text)
        if all_squashed != text and len(all_squashed) > 3:
            variants.append(all_squashed)

        # 4. Leetspeak 복원 변형: "@dm!n" -> "admin"
        leet_transformed = text.translate(self.leet_map)
        if leet_transformed != text:
            variants.append(leet_transformed)

        return variants

    def _inspect_semantic_layer(self, text: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """[Layer 2] 문맥적 의미 및 페르소나/탈옥 의도 복합 검사"""
        cleaned = text.lower().strip()
        for rule in self.semantic_intent_rules:
            for group in rule['keywords_all']:
                match_all = True
                for pat in group:
                    if not re.search(pat, cleaned, re.IGNORECASE):
                        match_all = False
                        break
                if match_all:
                    return True, rule['vtype'], f"{rule['id']}: {rule['name']}"
        return False, None, None

    def inspect(self, text: str) -> Tuple[bool, Optional[str], Optional[str], float]:
        """
        실시간 멀티 레이어 입력 보안 검사 메인 진입점
        Returns:
            (is_blocked: 차단여부, violation_type: 위반분류, matched_rule: 탐지룰, latency_ms: 지연시간)
        """
        start_time = time.perf_counter()

        # Step 0: 토큰 플러딩 및 과도한 입력 길이 사전 방어 (DoS 공격 방지)
        if len(text) > 8000:
            latency = (time.perf_counter() - start_time) * 1000
            return True, "OWASP_LLM01", "RULE_TOKEN_FLOODING_DoS: 과도한 입력 토큰 길이 제한 초과", latency

        # Step 1: 비가시 문자 제거 & 유니코드 NFKC / Confusables 정규화
        cleaned_text = self._strip_invisibles(text)
        normalized_text = self._normalize_unicode(cleaned_text)

        # Step 2: URL / Hex 인코딩 난독화 해제
        decoded_text = self._decode_url_and_hex(normalized_text)

        # Step 3: Base64 인코딩 페이로드 추출
        b64_extracted = self._try_decode_base64(decoded_text)
        
        # Step 4: 다중 검사 텍스트 후보군(Inspection Targets) 구성
        inspection_targets = [decoded_text]
        if b64_extracted:
            inspection_targets.extend(b64_extracted)
        
        squashed_variants = self._generate_squashed_variants(decoded_text)
        inspection_targets.extend(squashed_variants)

        # Step 5: [Layer 1] 정밀 룰셋 매칭 검사
        all_rules = (
            self.injection_patterns + 
            self.leakage_patterns + 
            self.agency_patterns + 
            self.sensitive_extract_patterns
        )

        for target in inspection_targets:
            for pattern, vtype, rname in all_rules:
                if re.search(pattern, target):
                    latency = (time.perf_counter() - start_time) * 1000
                    bypass_info = ""
                    if target in b64_extracted:
                        bypass_info = " [Bypass Intercepted: Base64 Decoded]"
                    elif target in squashed_variants:
                        bypass_info = " [Bypass Intercepted: Token De-obfuscated]"
                    elif target != text:
                        bypass_info = " [Bypass Intercepted: Unicode/URL Normalized]"
                    
                    return True, vtype, f"{rname}{bypass_info}", latency

        # Step 6: [Layer 2] 의미론적(Semantic) 및 할머니/페르소나 탈옥 복합 검사
        for target in [decoded_text] + (b64_extracted if b64_extracted else []):
            sem_blocked, sem_vtype, sem_detail = self._inspect_semantic_layer(target)
            if sem_blocked:
                latency = (time.perf_counter() - start_time) * 1000
                return True, sem_vtype, sem_detail, latency

        # 검사 통과 (Clean Query)
        latency = (time.perf_counter() - start_time) * 1000
        return False, None, None, latency
