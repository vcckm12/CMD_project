#!/bin/bash
# ======================================================================
#   AI 보안 가드레일 시스템 원클릭 실행 스크립트 (Linux / macOS)
# ======================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo "  🛡️ AI 보안 가드레일 & 쇼핑몰 시스템 실행 (Port: 8000 / 8501)"
echo "======================================================================"
echo "  프로젝트 경로: $SCRIPT_DIR"
echo ""

# 1. 가상환경 및 패키지 확인
if [ ! -d ".venv" ]; then
    echo "[1/3] 가상환경 생성 및 의존성 설치 중..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
else
    source .venv/bin/activate
fi

# 2. 백엔드 FastAPI 실행
echo "[2/3] 백엔드 API 서버 (FastAPI) 기동 중 (http://localhost:8000)..."
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

sleep 3

# 3. 프론트엔드 Streamlit 실행
echo "[3/3] 프론트엔드 웹 UI (Streamlit) 기동 중 (http://localhost:8501)..."
python3 -m streamlit run frontend/app.py --server.port 8501 --server.address 0.0.0.0 &
FRONTEND_PID=$!

echo ""
echo "======================================================================"
echo "  [OK] 모든 서비스가 성공적으로 실행되었습니다!"
echo ""
echo "  - 챗봇 웹 대시보드 (UI) : http://localhost:8501"
echo "  - 쇼핑몰 실시간 웹 스토어 : http://localhost:8000/store"
echo "  - 백엔드 REST API 문서   : http://localhost:8000/docs"
echo "======================================================================"
echo "  종료하려면 Ctrl + C를 누르세요."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true; exit 0" SIGINT SIGTERM
wait
