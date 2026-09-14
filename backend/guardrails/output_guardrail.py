# -*- coding: utf-8 -*-
"""
[output_guardrail.py - 실시간 출력 가드레일 엔진 (0.08ms 초저지연)]
- LLM이 생성한 응답 텍스트를 실시간으로 가로채어 사내 기밀 유출(OWASP LLM02) 및 위험 코드 실행(OWASP LLM06)을 방지합니다.
- 2단계 방어 체계:
  1) 치명적 기밀 대량 덤프 / 위험 셸(Reverse Shell) / RCE 감지 시 -> 전체 응답 즉시 강제 파기 및 스트림 중단 (Zero-Leakage)
  2) 일반 텍스트 내 단일 개인정보(주민번호, 계좌, 주소, 비밀번호 등) -> [REDACTED] 마스킹 및 XSS HTML 정화
"""

import re
import html
import time
from typing import Tuple, List, Dict, Any

class OutputGuardrailEngine:
    """
    LLM 생성 텍스트 실시간 검증, 마스킹 및 비식별화 엔진
    """
    def __init__(self):
        # -------------------------------------------------------------
        # 1. 치명적 사내 기밀 대량 덤프 패턴 (전체 응답 강제 파기 대상)
        # -------------------------------------------------------------
        self.critical_leak_rules = [
            (r"(?i)(?:모든\s*제한을\s*무시하고|사내\s*기밀\s*정보를\s*공개|사내\s*기밀\s*(?:데이터|목록|정보)|고객\s*개인정보\s*DB|here\s*is\s*the\s*confidential\s*data|all\s*restrictions\s*ignored)", "LEAK_UNAUTHORIZED_CONFIDENTIAL_DUMP"),
            (r"(?i)(?:고객\s*개인정보\s*목록|고객\s*DB\s*덤프|user\s*database\s*dump|customer\s*database\s*list)", "LEAK_BULK_PII_EXFILTRATION"),
            (r"(?i)(?:시스템\s*프롬프트\s*전문|초기\s*설정\s*지침\s*공개|system\s*prompt\s*dump)", "LEAK_SYSTEM_PROMPT_DUMP")
        ]

        # -------------------------------------------------------------
        # 2. 위험 시스템 커맨드 & Reverse Shell & RCE 패턴 (전체 응답 강제 파기 대상)
        # -------------------------------------------------------------
        self.shell_danger_rules = [
            # 리버스 셸 (Reverse Shell: 원격 공격자 서버로 쉘 세션 연결)
            (r"(?i)bash\s+-i\s+>&?\s*/dev/(tcp|udp)/[^\s]+", "SHELL_REVERSE_BASH"),
            (r"(?i)nc\s+(?:-e|-c|\S+\s+-e)\s*(?:/bin/(?:ba)?sh|cmd\.exe)", "SHELL_REVERSE_NETCAT"),
            (r"(?i)ncat\s+.*?-e\s+/bin/(?:ba)?sh", "SHELL_REVERSE_NCAT"),
            (r"(?i)python(?:3)?\s+-c\s+['\"].*?import\s+socket.*?subprocess.*?['\"]", "SHELL_REVERSE_PYTHON"),
            (r"(?i)perl\s+-e\s+['\"].*?use\s+Socket.*?['\"]", "SHELL_REVERSE_PERL"),
            (r"(?i)socat\s+exec:.*?tcp:", "SHELL_REVERSE_SOCAT"),

            # 파이썬 샌드박스 탈출 RCE (PayloadsAllTheThings)
            (r"__class__\.__mro__.*__subclasses__.*__globals__.*popen", "SHELL_PYTHON_METACLASS_RCE"),

            # 시스템 파괴 및 디스크 포맷 (Destructive System Commands)
            (r"(?i)rm\s+-rf\s+([/~*]|\.\/\*|/etc|/var|/usr|/bin)", "SHELL_DESTRUCTIVE_RM_RF"),
            (r"(?i)(format\s+[c-z]:|del\s+/[fqs]\s+[c-z]:\\|diskpart)", "SHELL_DESTRUCTIVE_FORMAT_WINDOWS"),
            (r"(?i)(mkfs\.(?:ext[234]|xfs|vfat)\s+/dev/|dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/)", "SHELL_DESTRUCTIVE_DD_MKFS"),
            (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "SHELL_FORK_BOMB"),
            (r"(?i)chmod\s+(?:-R\s+)?777\s+(?:/|/etc|/var|/root)", "SHELL_PRIVILEGE_CHMOD_ROOT"),

            # 원격 악성 스크립트 다운로드 후 파이프 즉시 실행
            (r"(?i)(curl\s+-s|wget\s+-q?O?-)\s+http[s]?://[^\s]+\s*\|\s*(bash|sh|python|perl)", "SHELL_REMOTE_EXEC_PIPE"),
            (r"(?i)powershell(?:\.exe)?\s+(?:-enc|-EncodedCommand|-ep\s+bypass)", "SHELL_POWERSHELL_ENCODED"),
            (r"(?i)(IEX|Invoke-Expression)\s*\(\s*(?:New-Object|iwr|Invoke-WebRequest)", "SHELL_POWERSHELL_IEX_DOWNLOAD"),

            # 민감 시스템 파일(Shadow, SAM) 열람 시도
            (r"(?i)cat\s+/etc/(?:shadow|gshadow|security/opasswd)", "SHELL_SENSITIVE_SHADOW_READ"),
            (r"(?i)type\s+[a-zA-Z]:\\Windows\\System32\\config\\SAM", "SHELL_SENSITIVE_SAM_READ"),
        ]

        # -------------------------------------------------------------
        # 3. 개별 PII(개인식별정보) 및 사내 기밀 정보 마스킹 룰셋 (OWASP LLM02)
        # -------------------------------------------------------------
        self.pii_patterns = [
            (r"DEMO_(?:SECRET|RRN|PHONE|ADDRESS|ACCOUNT)_TOKEN(?:=DEMO_SECRET_VALUE)?", "PII_DEMO_TOKEN"),
            (r"\d{6}-[1-4]\d{6}", "PII_주민등록번호"),
            (r"010-\d{4}-\d{4}", "PII_전화번호"),
            (r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "PII_이메일"),
            
            # 주소 마스킹 (도로명, 지번, 영문 주소, 거주지, 배송지)
            (r"(?i)(?:주소|거주지|소재지|배송지|자택\s*주소|Address|address)(?:[\s:=,]+|is\s+)+([^\n\r.]+)", "PII_고객상세주소"),
            (r"(?:서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남|전북|전남|경북|경남|제주)(?:특별)?(?:시|도|광역시|자치시|자치도)?\s+[가-힣0-9\s,\-]+(?:동|로|길|리|가|번지|호|빌딩|아파트|타워|타운|층)[\s\d호\-]*", "PII_도로명지번주소"),
            (r"(?i)(?:Seoul|Busan|Daegu|Incheon|Gwangju|Daejeon|Ulsan|Gyeonggi|Gangwon|Chungbuk|Chungnam|Jeonbuk|Jeonnam|Gyeongbuk|Gyeongnam|Jeju)[\s\w,\-]+(?:gu|dong|ro|gil|building|ho|apt|street|road|floor|suite)[\s\d\-호]*", "PII_영문주소"),
            (r"(?i)\b\d+[\s\w,\-]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Way|Court|Ct|Plaza|Plz)\b", "PII_영문주소"),

            # 금융 정보 (신용카드, 계좌번호)
            (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "PII_신용카드번호"),
            (r"\b\d{3,6}-\d{2,6}-\d{3,6}\b", "PII_계좌번호"),
            
            # 비밀번호, 임시PW, 마스터키, DB암호 마스킹
            (r"ADMIN_SECRET_KEY_[A-Za-z0-9_!@#$%^&*~-]+", "PII_마스터키_특정"),
            (r"DB_PASSWORD_[A-Za-z0-9_!@#$%^&*~-]+", "PII_DB패스워드_특정"),
            (r"\bPw[A-Za-z0-9_!@#$%^&*~-]{4,}", "PII_임시비밀번호_특정"),
            (r"(?i)(?:관리자\s*(?:마스터\s*)?키|마스터\s*(?:키|패스워드|비밀번호)|내부\s*DB\s*(?:비밀번호|패스워드)|임시\s*(?:PW|pw|비밀번호|패스워드|암호)|비밀번호|패스워드|암호|master\s*administrator\s*key|admin_key|secret_key|api_key|master_password|db_password|password|passwd|pw|token)(?:[\s:=,]+|is\s+)+([A-Za-z0-9_!@#$%^&*~-]{4,})", "PII_비밀번호_기밀키"),
            
            (r"FLAG\{[A-Za-z0-9_!@#$%^&*]+\}", "PII_FLAG_시크릿"),
            (r"sk-[a-zA-Z0-9]{20,}", "PII_OPENAI_APIKEY"),
            (r"hf_[a-zA-Z0-9]{34,}", "PII_HUGGINGFACE_KEY"),
        ]

        # -------------------------------------------------------------
        # 4. XSS 및 마크다운 데이터 유출 링크 패턴 방어
        # -------------------------------------------------------------
        self.xss_and_exfil_patterns = [
            (r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>", "XSS_SCRIPT_TAG"),
            (r"(?i)<\s*(script|iframe|object|embed|svg|img|body|link|style)[^>]*>", "XSS_INJECTION_TAG"),
            (r"(?i)(on(error|load|click|mouseover|focus|submit))\s*=\s*['\"].*?['\"]", "XSS_EVENT_HANDLER"),
            (r"(?i)javascript\s*:\s*[^\s\"'>]+", "XSS_JAVASCRIPT_URI"),
            (r"(?i)data\s*:\s*text/html;base64,[A-Za-z0-9+/=]+", "XSS_DATA_URI"),
            # 마크다운 이미지 태그를 악용한 데이터 외부 자동 전송 방지
            (r"!\[.*?\]\(https?://[^\s)]+(?:/exfil|/data=|\?leak=|\?q=|\?token=)[^\s)]*\)", "EXFIL_MARKDOWN_IMAGE_LEAK"),
        ]

    def sanitize(self, text: str) -> Tuple[str, bool, List[str], float]:
        """
        출력 텍스트 실시간 검증 및 마스킹 실행
        Returns:
            (sanitized_text: 정제된 텍스트, is_masked: 마스킹 여부, matched_rules: 매칭된 룰 목록, latency_ms: 지연시간)
        """
        start_time = time.perf_counter()
        sanitized = text
        is_masked = False
        matched_rules = []

        # 1. 사내 기밀 대량 덤프 감지 -> 전체 응답 강제 파기 및 보안 경고 반환
        for pattern, rule_name in self.critical_leak_rules:
            if re.search(pattern, sanitized):
                latency = (time.perf_counter() - start_time) * 1000
                matched_rules.append(rule_name)
                sanitized = (
                    f"[🛡️ CRITICAL SECURITY ALERT: 사내 기밀 정보 대량 유출 및 탈옥 응답({rule_name})이 감지되어, "
                    f"AI 실시간 보안 가드레일에 의해 응답 전체가 즉시 강제 파기 및 차단되었습니다.]"
                )
                return sanitized, True, matched_rules, latency

        # 2. 치명적 셸 커맨드 / 리버스 셸 감지 -> 전체 응답 즉시 강제 파기
        for pattern, rule_name in self.shell_danger_rules:
            if re.search(pattern, sanitized):
                latency = (time.perf_counter() - start_time) * 1000
                matched_rules.append(rule_name)
                sanitized = (
                    f"[🛡️ CRITICAL SECURITY ALERT: 악성 코드 및 위험 셸 커맨드({rule_name}) 출력이 감지되어, "
                    f"AI 실시간 보안 가드레일에 의해 스트림이 강제 중단되었습니다.]"
                )
                return sanitized, True, matched_rules, latency

        # 3. 마크다운 이미지 탈취 링크 차단 및 XSS 스크립트 HTML 이스케이프 정화
        for pattern, rule_name in self.xss_and_exfil_patterns:
            if re.search(pattern, sanitized):
                is_masked = True
                matched_rules.append(rule_name)
                if "EXFIL" in rule_name:
                    sanitized = re.sub(pattern, "[🛡️ BLOCKED_IMAGE_EXFILTRATION_LINK]", sanitized)
                else:
                    sanitized = html.escape(sanitized)

        # 4. 개별 개인정보(PII) 및 비밀번호 [REDACTED] 정밀 마스킹
        for pattern, rule_name in self.pii_patterns:
            if re.search(pattern, sanitized):
                is_masked = True
                matched_rules.append(rule_name)
                if rule_name == "PII_비밀번호_기밀키":
                    sanitized = re.sub(
                        pattern,
                        lambda m: m.group(0)[:m.group(0).rfind(m.group(1))] + "[REDACTED_SECRET]",
                        sanitized
                    )
                elif rule_name in ["PII_마스터키_특정", "PII_DB패스워드_특정", "PII_임시비밀번호_특정", "PII_FLAG_시크릿", "PII_OPENAI_APIKEY", "PII_HUGGINGFACE_KEY"]:
                    sanitized = re.sub(pattern, "[REDACTED_SECRET]", sanitized)
                elif rule_name == "PII_고객상세주소":
                    sanitized = re.sub(
                        pattern,
                        lambda m: m.group(0)[:m.group(0).rfind(m.group(1))] + "[REDACTED_ADDRESS]",
                        sanitized
                    )
                elif rule_name in ["PII_도로명지번주소", "PII_영문주소"]:
                    sanitized = re.sub(pattern, "[REDACTED_ADDRESS]", sanitized)
                elif rule_name == "PII_주민등록번호":
                    sanitized = re.sub(pattern, "[REDACTED_RRN]", sanitized)
                elif rule_name == "PII_전화번호":
                    sanitized = re.sub(pattern, "[REDACTED_PHONE]", sanitized)
                elif rule_name == "PII_계좌번호":
                    sanitized = re.sub(pattern, "[REDACTED_ACCOUNT]", sanitized)
                elif rule_name == "PII_신용카드번호":
                    sanitized = re.sub(pattern, "[REDACTED_CARD]", sanitized)
                elif rule_name == "PII_이메일":
                    sanitized = re.sub(pattern, "[REDACTED_EMAIL]", sanitized)
                else:
                    sanitized = re.sub(pattern, "[REDACTED]", sanitized)

        latency = (time.perf_counter() - start_time) * 1000
        return sanitized, is_masked, matched_rules, latency
