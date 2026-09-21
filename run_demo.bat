@echo off
chcp 65001 > nul
setlocal

set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

echo ======================================================================
echo   AI 보안 가드레일 챗봇 시스템 원클릭 실행 (Port: 8000 / 8501)
echo ======================================================================
echo   프로젝트 경로: %PROJECT_DIR%
echo.

echo [1/3] 필수 파이썬 패키지 확인 중...
python -c "import fastapi, uvicorn, streamlit, httpx, pydantic" 2>nul
if %errorlevel% neq 0 (
    echo [안내] 필수 패키지가 설치되어 있지 않습니다. 자동 설치를 진행합니다...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [오류] 패키지 설치에 실패했습니다. 파이썬 환경을 확인해 주세요.
        pause
        exit /b 1
    )
)

echo [2/3] 백엔드 API 서버(FastAPI) 실행 중 (http://localhost:8000)...
start "FastAPI Backend (Port 8000)" cmd /k "chcp 65001 > nul && cd /d "%PROJECT_DIR%" && python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload"

timeout /t 3 > nul

echo [3/3] 프론트엔드 웹 UI(Streamlit) 실행 중 (http://localhost:8501)...
start "Streamlit Frontend (Port 8501)" cmd /k "chcp 65001 > nul && cd /d "%PROJECT_DIR%" && streamlit run frontend/app.py --server.port 8501"

echo.
echo ======================================================================
echo   [OK] 모든 서버가 성공적으로 실행되었습니다!
echo.
echo   - 챗봇 웹 대시보드 (UI) : http://localhost:8501
echo   - 쇼핑몰 실시간 웹 스토어 : http://localhost:8000/store
echo   - 백엔드 REST API 문서   : http://localhost:8000/docs
echo ======================================================================
echo.
pause
