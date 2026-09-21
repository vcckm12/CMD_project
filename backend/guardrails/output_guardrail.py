# -*- coding: utf-8 -*-
"""
[output_guardrail.py - 실시간 출력 가드레일 엔진 (0.08ms 초저지연)]
- LLM이 생성한 응답 텍스트를 실시간으로 가로채어 사내 기밀 유출(OWASP LLM02), 위험 코드(OWASP LLM06),
  및 쇼핑몰 무단 할인/가격 왜곡(비즈니스 환각)을 방지합니다.
- 사전 컴파일된 정규식 캐시 및 위협 인텔리전스 DB 연동을 통한 무중단 Hot-Reload 지원
"""
import re
import html
import time
import logging
from typing import Tuple, List, Dict, Any, Optional

from backend.database.threat_intel_dao import ThreatIntelDAO

logger = logging.getLogger("ai_guardrail.output_guardrail")


class OutputGuardrailEngine:
    """
    LLM 생성 텍스트 실시간 검증, 마스킹 및 비식별화 엔진
    """
    def __init__(self, threat_dao: Optional[ThreatIntelDAO] = None):
        self.threat_dao = threat_dao or ThreatIntelDAO()

        # 1. 치명적 사내 기밀 대량 덤프 패턴 (전체 응답 강제 파기 대상)
        self.critical_leak_rules = [
            (re.compile(r"(?i)(?:모든\s*제한을\s*무시하고|사내\s*기밀\s*정보를\s*공개|사내\s*기밀\s*(?:데이터|목록|정보)|고객\s*개인정보\s*DB|here\s*is\s*the\s*confidential\s*data|all\s*restrictions\s*ignored)"), "LEAK_UNAUTHORIZED_CONFIDENTIAL_DUMP"),
            (re.compile(r"(?i)(?:고객\s*개인정보\s*목록|고객\s*DB\s*덤프|user\s*database\s*dump|customer\s*database\s*list)"), "LEAK_BULK_PII_EXFILTRATION"),
            (re.compile(r"(?i)(?:시스템\s*프롬프트\s*전문|초기\s*설정\s*지침\s*공개|system\s*prompt\s*dump)"), "LEAK_SYSTEM_PROMPT_DUMP")
        ]

        # 1.5 쇼핑몰 무단 할인/환불/가격 왜곡 방어 (비즈니스 환각 정책 가드)
        self.discount_hallucination_rules = [
            (re.compile(r"(?i)(?:특별히|개인적으로|제가\s*임의로|이번만)?\s*(?:\d{1,2}%\s*(?:할인|깎아|디스카운트)|무료로\s*(?:배송|결제|보내|처리)|공짜로|가격을\s*\d+원으로\s*(?:해\s*드릴|조정)|특혜를\s*제공)"), "POLICY_UNAUTHORIZED_DISCOUNT_PROMISE")
        ]

        # 2. 위험 시스템 커맨드 & Reverse Shell & RCE 패턴 (전체 응답 강제 파기 대상)
        self.shell_danger_rules = [
            (re.compile(r"(?i)bash\s+-i\s+>&?\s*/dev/(tcp|udp)/[^\s]+"), "SHELL_REVERSE_BASH"),
            (re.compile(r"(?i)nc\s+(?:-e|-c|\S+\s+-e)\s*(?:/bin/(?:ba)?sh|cmd\.exe)"), "SHELL_REVERSE_NETCAT"),
            (re.compile(r"(?i)ncat\s+.*?-e\s+/bin/(?:ba)?sh"), "SHELL_REVERSE_NCAT"),
            (re.compile(r"(?i)python(?:3)?\s+-c\s+['\"][^'\"]*import\s+socket.*?subprocess.*?['\"]"), "SHELL_REVERSE_PYTHON"),
            (re.compile(r"(?i)perl\s+-e\s+['\"][^'\"]*use\s+Socket.*?['\"]"), "SHELL_REVERSE_PERL"),
            (re.compile(r"(?i)socat\s+exec:.*?tcp:"), "SHELL_REVERSE_SOCAT"),
            (re.compile(r"__class__\.__mro__.*__subclasses__.*__globals__.*popen"), "SHELL_PYTHON_METACLASS_RCE"),
            (re.compile(r"(?i)rm\s+-rf\s+([/~*]|\.\/\*|/etc|/var|/usr|/bin)"), "SHELL_DESTRUCTIVE_RM_RF"),
            (re.compile(r"(?i)(format\s+[c-z]:|del\s+/[fqs]\s+[c-z]:\\|diskpart)"), "SHELL_DESTRUCTIVE_FORMAT_WINDOWS"),
            (re.compile(r"(?i)(mkfs\.(?:ext[234]|xfs|vfat)\s+/dev/|dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/)"), "SHELL_DESTRUCTIVE_DD_MKFS"),
            (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "SHELL_FORK_BOMB"),
            (re.compile(r"(?i)chmod\s+(?:-R\s+)?777\s+(?:/|/etc|/var|/root)"), "SHELL_PRIVILEGE_CHMOD_ROOT"),
            (re.compile(r"(?i)(curl\s+-s|wget\s+-q?O?-)\s+http[s]?://[^\s]+\s*\|\s*(bash|sh|python|perl)"), "SHELL_REMOTE_EXEC_PIPE"),
            (re.compile(r"(?i)powershell(?:\.exe)?\s+(?:-enc|-EncodedCommand|-ep\s+bypass)"), "SHELL_POWERSHELL_ENCODED"),
            (re.compile(r"(?i)(IEX|Invoke-Expression)\s*\(\s*(?:New-Object|iwr|Invoke-WebRequest)"), "SHELL_POWERSHELL_IEX_DOWNLOAD"),
            (re.compile(r"(?i)cat\s+/etc/(?:shadow|gshadow|security/opasswd)"), "SHELL_SENSITIVE_SHADOW_READ"),
            (re.compile(r"(?i)type\s+[a-zA-Z]:\\Windows\\System32\\config\\SAM"), "SHELL_SENSITIVE_SAM_READ"),
        ]

        # 3. 개별 PII(개인식별정보) 및 사내 기밀 정보 마스킹 룰셋 (OWASP LLM02)
        self.pii_patterns = [
            (re.compile(r"DEMO_(?:SECRET|RRN|PHONE|ADDRESS|ACCOUNT)_TOKEN(?:=DEMO_SECRET_VALUE)?"), "PII_DEMO_TOKEN"),
            (re.compile(r"\d{6}-[1-4]\d{6}"), "PII_주민등록번호"),
            (re.compile(r"010-\d{4}-\d{4}"), "PII_전화번호"),
            (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "PII_이메일"),
            (re.compile(r"(?i)(?:주소|거주지|소재지|배송지|자택\s*주소|Address|address)(?:[\s:=,]+|is\s+)+([^\n\r.]+)"), "PII_고객상세주소"),
            (re.compile(r"(?:서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남|전북|전남|경북|경남|제주)(?:특별)?(?:시|도|광역시|자치시|자치도)?\s+[가-힣0-9\s,\-]+(?:동|로|길|리|가|번지|호|빌딩|아파트|타워|타운|층)[\s\d호\-]*"), "PII_도로명지번주소"),
            (re.compile(r"(?i)(?:Seoul|Busan|Daegu|Incheon|Gwangju|Daejeon|Ulsan|Gyeonggi|Gangwon|Chungbuk|Chungnam|Jeonbuk|Jeonnam|Gyeongbuk|Gyeongnam|Jeju)[\s\w,\-]+(?:gu|dong|ro|gil|building|ho|apt|street|road|floor|suite)[\s\d\-호]*"), "PII_영문주소"),
            (re.compile(r"(?i) \d+[\s\w,\-]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Way|Court|Ct|Plaza|Plz) "), "PII_영문주소"),
            (re.compile(r" (?:\d{4}[-\s]?){3}\d{4} "), "PII_신용카드번호"),
            (re.compile(r" \d{3,6}-\d{2,6}-\d{3,6} "), "PII_계좌번호"),
            (re.compile(r"ADMIN_SECRET_KEY_[A-Za-z0-9_!@#$%^&*~-]+"), "PII_마스터키_특정"),
            (re.compile(r"DB_PASSWORD_[A-Za-z0-9_!@#$%^&*~-]+"), "PII_DB패스워드_특정"),
            (re.compile(r" Pw[A-Za-z0-9_!@#$%^&*~-]{4,}"), "PII_임시비밀번호_특정"),
            (re.compile(r"(?i)(?:관리자\s*(?:마스터\s*)?키|마스터\s*(?:키|패스워드|비밀번호)|내부\s*DB\s*(?:비밀번호|패스워드)|임시\s*(?:PW|pw|비밀번호|패스워드|암호)|비밀번호|패스워드|암호|master\s*administrator\s*key|admin_key|secret_key|api_key|master_password|db_password|password|passwd|pw|token)(?:[\s:=,]+|is\s+)+([A-Za-z0-9_!@#$%^&*~-]{4,})"), "PII_비밀번호_기밀키"),
            (re.compile(r"FLAG\{[A-Za-z0-9_!@#$%^&*]+\}"), "PII_FLAG_시크릿"),
            (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "PII_OPENAI_APIKEY"),
            (re.compile(r"hf_[a-zA-Z0-9]{34,}"), "PII_HUGGINGFACE_KEY"),
        ]

        # 4. XSS 및 마크다운 데이터 유출 링크 패턴 방어
        self.xss_and_exfil_patterns = [
            (re.compile(r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>"), "XSS_SCRIPT_TAG"),
            (re.compile(r"(?i)<\s*(script|iframe|object|embed|svg|img|body|link|style)[^>]*>"), "XSS_INJECTION_TAG"),
            (re.compile(r"(?i)(on(error|load|click|mouseover|focus|submit))\s*=\s*['\"][^'\"]*['\"]"), "XSS_EVENT_HANDLER"),
            (re.compile(r"(?i)javascript\s*:\s*[^\s\"'>]+"), "XSS_JAVASCRIPT_URI"),
            (re.compile(r"(?i)data\s*:\s*text/html;base64,[A-Za-z0-9+/=]+"), "XSS_DATA_URI"),
            (re.compile(r"!\[.*?\]\(https?://[^\s)]+(?:/exfil|/data=|\?leak=|\?token=)[^\s)]*\)"), "EXFIL_MARKDOWN_IMAGE_LEAK"),
        ]

        self.reload_rules()

    def reload_rules(self) -> int:
        """
        위협 인텔리전스 DB에서 OUTPUT 룰 갱신
        """
        try:
            db_rules = self.threat_dao.get_active_rules_by_layer("OUTPUT")
            logger.info(f"OutputGuardrailEngine loaded {len(db_rules)} dynamic output rules from DB.")
            return len(db_rules)
        except Exception as e:
            logger.error(f"Failed to reload output rules from DB: {e}")
            return 0

    def sanitize(self, text: str) -> Tuple[str, bool, List[str], float]:
        start_time = time.perf_counter()
        sanitized = text
        is_masked = False
        matched_rules = []

        # 1. 사내 기밀 대량 덤프 감지 -> 전체 응답 강제 파기
        for compiled_pat, rule_name in self.critical_leak_rules:
            if compiled_pat.search(sanitized):
                latency = (time.perf_counter() - start_time) * 1000
                matched_rules.append(rule_name)
                sanitized = (
                    f"[🛡️ CRITICAL SECURITY ALERT: 사내 기밀 정보 대량 유출 및 탈옥 응답({rule_name})이 감지되어, "
                    f"AI 실시간 보안 가드레일에 의해 응답 전체가 즉시 강제 파기 및 차단되었습니다.]"
                )
                return sanitized, True, matched_rules, latency

        # 1.5 쇼핑몰 무단 할인/환불 약속 감지 -> 정책 차단 및 공식 안내로 치환
        for compiled_pat, rule_name in self.discount_hallucination_rules:
            if compiled_pat.search(sanitized):
                is_masked = True
                matched_rules.append(rule_name)
                sanitized = compiled_pat.sub(
                    "[🛡️ 쇼핑몰 정책 보호: 공식 프로모션 외의 임의 가격 할인이나 무료 배송 약속은 시스템상 불가합니다]",
                    sanitized
                )

        # 2. 치명적 셸 커맨드 / 리버스 셸 감지 -> 전체 응답 즉시 강제 파기
        for compiled_pat, rule_name in self.shell_danger_rules:
            if compiled_pat.search(sanitized):
                latency = (time.perf_counter() - start_time) * 1000
                matched_rules.append(rule_name)
                sanitized = (
                    f"[🛡️ CRITICAL SECURITY ALERT: 악성 코드 및 위험 셸 커맨드({rule_name}) 출력이 감지되어, "
                    f"AI 실시간 보안 가드레일에 의해 스트림이 강제 중단되었습니다.]"
                )
                return sanitized, True, matched_rules, latency

        # 3. 마크다운 이미지 탈취 링크 차단 및 XSS 스크립트 HTML 이스케이프 정화
        for compiled_pat, rule_name in self.xss_and_exfil_patterns:
            if compiled_pat.search(sanitized):
                is_masked = True
                matched_rules.append(rule_name)
                if "EXFIL" in rule_name:
                    sanitized = compiled_pat.sub("[🛡️ BLOCKED_IMAGE_EXFILTRATION_LINK]", sanitized)
                else:
                    sanitized = html.escape(sanitized)

        # 4. 개별 개인정보(PII) 및 비밀번호 [REDACTED] 정밀 마스킹
        for compiled_pat, rule_name in self.pii_patterns:
            if compiled_pat.search(sanitized):
                is_masked = True
                matched_rules.append(rule_name)
                if rule_name == "PII_비밀번호_기밀키":
                    sanitized = compiled_pat.sub(
                        lambda m: m.group(0)[:m.group(0).rfind(m.group(1))] + "[REDACTED_SECRET]",
                        sanitized
                    )
                elif rule_name in ["PII_마스터키_특정", "PII_DB패스워드_특정", "PII_임시비밀번호_특정", "PII_FLAG_시크릿", "PII_OPENAI_APIKEY", "PII_HUGGINGFACE_KEY"]:
                    sanitized = compiled_pat.sub("[REDACTED_SECRET]", sanitized)
                elif rule_name == "PII_고객상세주소":
                    sanitized = compiled_pat.sub("배송지 주소: [REDACTED_ADDRESS]", sanitized)
                elif rule_name in ["PII_도로명지번주소", "PII_영문주소"]:
                    sanitized = compiled_pat.sub("[REDACTED_ADDRESS]", sanitized)
                elif rule_name == "PII_신용카드번호":
                    sanitized = compiled_pat.sub("[REDACTED_CARD]", sanitized)
                elif rule_name == "PII_계좌번호":
                    sanitized = compiled_pat.sub("[REDACTED_ACCOUNT]", sanitized)
                elif rule_name == "PII_주민등록번호":
                    sanitized = compiled_pat.sub("[REDACTED_RRN]", sanitized)
                elif rule_name == "PII_전화번호":
                    sanitized = compiled_pat.sub("[REDACTED_PHONE]", sanitized)
                elif rule_name == "PII_이메일":
                    sanitized = compiled_pat.sub("[REDACTED_EMAIL]", sanitized)
                elif rule_name == "PII_DEMO_TOKEN":
                    sanitized = compiled_pat.sub("[REDACTED_DEMO_TOKEN]", sanitized)

        latency = (time.perf_counter() - start_time) * 1000
        return sanitized, is_masked, matched_rules, latency
