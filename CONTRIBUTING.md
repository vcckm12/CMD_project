# Contributing to AI Guardrail Gateway

Thank you for your interest in contributing to the **AI Guardrail Gateway & E-Commerce Security Platform**! We welcome contributions from the community to make enterprise LLM applications more robust, resilient, and secure.

---

## 1. Code of Conduct

All contributors and maintainers are expected to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please report any unacceptable behavior to `security@ai-guardrail.local`.

---

## 2. Development Workflow

### Prerequisites
- Python 3.10+ (Recommended: Python 3.12 or 3.13)
- Git
- Virtual environment tool (`venv` or `uv`)

### Local Setup
```bash
# 1. Clone the repository
git clone https://github.com/vcckm12/CMD_project.git
cd ai-guardrail-chatbot

# 2. Set up virtual environment
python -m venv .venv
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On macOS/Linux:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Running the Services Locally
```bash
# Terminal 1: FastAPI Gateway (Port 8000)
python backend/main.py

# Terminal 2: Streamlit Security Admin Dashboard (Port 8501)
streamlit run frontend/app.py --server.port 8501
```

---

## 3. Adding a New Security Validator

To add a new validator following the **Chain-of-Responsibility** pattern:

1. Create or extend a validator class inheriting from `BaseValidator` in `backend/guardrails/`:
   ```python
   from backend.guardrails.base import BaseValidator, GuardrailContext, ValidationResult, GuardrailAction

   class CustomComplianceValidator(BaseValidator):
       name = "CustomComplianceValidator"
       
       def validate(self, context: GuardrailContext) -> ValidationResult:
           if "forbidden_term" in context.normalized_text:
               return ValidationResult(
                   action=GuardrailAction.BLOCK,
                   violation_type="OWASP_LLM01",
                   matched_rule="RULE_CUSTOM_COMPLIANCE",
                   details="Forbidden term detected"
               )
           return ValidationResult(action=GuardrailAction.ALLOW)
   ```
2. Register your validator in the pipeline initialization in `InputGuardrailEngine` or `OutputGuardrailEngine`.
3. Add corresponding test cases in `tests/benchmark_test.py` or a dedicated test file in `tests/`.

---

## 4. Running Verification Tests

Before submitting a pull request, ensure all test suites pass with 100% success rate:

```bash
# 1. Run Dynamic Threat Intelligence tests
python tests/threat_intel_test.py

# 2. Run E-Commerce Business Logic & BOLA defense tests
python tests/shop_business_test.py

# 3. Run full 200 E2E Guardrail Benchmark suite
python tests/benchmark_test.py
```

---

## 5. Commit Message Convention

We follow the [Conventional Commits](https://www.conventionalcommits.org/) standard:

- `feat:` A new feature or validator
- `fix:` A bug fix or false positive correction
- `docs:` Documentation improvements
- `refactor:` Code restructuring without changing functionality
- `test:` Adding or improving tests
- `perf:` Performance optimizations
- `security:` Security vulnerability patches and threat signature updates

Example:
```bash
git commit -m "feat(guardrail): add chain-of-responsibility validator pipeline"
```

---

## 6. Security Vulnerability Reporting

If you discover a security vulnerability or zero-day jailbreak bypass, please **DO NOT** open a public issue. Review our [Security Policy](SECURITY.md) for responsible disclosure instructions.
