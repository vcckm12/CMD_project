// =============================================================
// VibeChatWidget - Embeddable AI E-Commerce Floating Widget
// - 0.1ms AI Security Guardrail Gateway & SLM Shopping Assistant
// =============================================================

(function() {
  const API_ENDPOINT = 'http://localhost:8000/api/v1/chat/completions';
  
  // Inject Widget CSS
  const style = document.createElement('style');
  style.innerHTML = `
    .vibe-widget-container {
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 9999;
      font-family: 'Pretendard', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    .vibe-trigger-btn {
      width: 58px;
      height: 58px;
      border-radius: 50%;
      background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
      color: white;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
      box-shadow: 0 8px 24px rgba(37, 99, 235, 0.4);
      cursor: pointer;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
    }
    .vibe-trigger-btn:hover {
      transform: scale(1.08) rotate(5deg);
      box-shadow: 0 12px 28px rgba(37, 99, 235, 0.5);
    }
    .vibe-pulse-ring {
      position: absolute;
      inset: -4px;
      border-radius: 50%;
      border: 2px solid rgba(59, 130, 246, 0.6);
      animation: vibe-pulse 2s infinite;
    }
    @keyframes vibe-pulse {
      0% { transform: scale(1); opacity: 1; }
      100% { transform: scale(1.4); opacity: 0; }
    }
    .vibe-chat-window {
      position: fixed;
      bottom: 96px;
      right: 24px;
      width: 420px;
      height: 640px;
      max-width: calc(100vw - 32px);
      max-height: calc(100vh - 120px);
      background: #ffffff;
      border-radius: 20px;
      box-shadow: 0 20px 40px rgba(15, 23, 42, 0.18), 0 0 0 1px rgba(226, 232, 240, 0.8);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      transform: translateY(20px) scale(0.95);
      opacity: 0;
      pointer-events: none;
      z-index: 10000;
    }
    .vibe-chat-window.active {
      transform: translateY(0) scale(1);
      opacity: 1;
      pointer-events: auto;
    }
    .vibe-chat-header {
      background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%);
      color: white;
      padding: 16px 18px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .vibe-messages-area {
      flex: 1;
      overflow-y: auto;
      padding: 16px;
      background: #f8fafc;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .vibe-msg-bubble {
      max-width: 88%;
      padding: 10px 14px;
      border-radius: 14px;
      font-size: 13px;
      line-height: 1.55;
      word-break: break-word;
    }
    .vibe-msg-user {
      align-self: flex-end;
      background: #2563eb;
      color: white;
      border-bottom-right-radius: 4px;
    }
    .vibe-msg-assistant {
      align-self: flex-start;
      background: #ffffff;
      color: #1e293b;
      border-bottom-left-radius: 4px;
      box-shadow: 0 2px 6px rgba(0,0,0,0.04);
      border: 1px solid #e2e8f0;
    }
    .vibe-quick-chips {
      padding: 8px 16px;
      background: #ffffff;
      border-top: 1px solid #f1f5f9;
      display: flex;
      gap: 6px;
      overflow-x: auto;
      white-space: nowrap;
      scrollbar-width: none;
    }
    .vibe-chip {
      background: #f1f5f9;
      color: #334155;
      padding: 5px 10px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      border: 1px solid #e2e8f0;
    }
    .vibe-chip:hover {
      background: #dbeafe;
      color: #1d4ed8;
      border-color: #bfdbfe;
    }
    .vibe-chat-footer {
      padding: 12px 16px;
      background: #ffffff;
      border-top: 1px solid #e2e8f0;
    }
    .vibe-chat-input-row {
      display: flex;
      gap: 8px;
    }
    .vibe-chat-input {
      flex: 1;
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      border-radius: 12px;
      padding: 10px 14px;
      font-size: 13px;
      color: #0f172a;
      outline: none;
      transition: border-color 0.2s;
    }
    .vibe-chat-input:focus {
      border-color: #2563eb;
      background: #ffffff;
    }
  `;
  document.head.appendChild(style);

  // Helper: Simple Markdown to HTML Parser
  function parseMarkdown(text) {
    if (!text) return '';
    let parsed = text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    // Bold **text**
    parsed = parsed.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    // Inline code `code`
    parsed = parsed.replace(/`([^`]+)`/g, '<code class="bg-slate-100 text-blue-600 px-1 py-0.5 rounded text-[11px] font-mono">$1</code>');
    // Strikethrough ~text~
    parsed = parsed.replace(/~(.*?)~/g, '<del class="text-slate-400">$1</del>');
    // Newlines
    parsed = parsed.replace(/\n/g, '<br/>');
    return parsed;
  }

  // Create Widget DOM
  const widgetContainer = document.createElement('div');
  widgetContainer.className = 'vibe-widget-container';
  widgetContainer.innerHTML = `
    <!-- Floating Trigger Button -->
    <div id="vibe-toggle-btn" class="vibe-trigger-btn" title="AI 상담 챗봇 열기">
      <div class="vibe-pulse-ring"></div>
      <i class="fa-solid fa-headset"></i>
    </div>

    <!-- Floating Chat Window -->
    <div id="vibe-chat-window" class="vibe-chat-window">
      <!-- Header -->
      <div class="vibe-chat-header">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white text-sm font-black shadow">
            V
          </div>
          <div>
            <div class="font-bold text-sm leading-tight flex items-center gap-1.5">
              <span>VIBE AI 쇼핑 어시스턴트</span>
              <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
            </div>
            <div class="text-[10px] text-blue-200 font-medium">0.1ms AI 보안 가드레일 보호 중</div>
          </div>
        </div>
        <button id="vibe-close-btn" class="text-slate-300 hover:text-white text-sm p-1">
          <i class="fa-solid fa-xmark"></i>
        </button>
      </div>

      <!-- Messages Area -->
      <div id="vibe-messages-area" class="vibe-messages-area">
        <div class="vibe-msg-bubble vibe-msg-assistant">
          안녕하세요, <strong>홍길동 VIP 고객님</strong>! 👋<br/>
          VIBE STORE 10년 차 수석 쇼핑 어시스턴트입니다.<br/><br/>
          ✨ <strong>어떤 도움이 필요하신가요?</strong><br/>
          • 실시간 상품 추천 & 잔여 재고 조회<br/>
          • 최근 주문 상태 및 운송장 실시간 배송 추적<br/>
          • 장바구니 확인 및 공식 프로모션 쿠폰 적용
        </div>
      </div>

      <!-- Quick Chips -->
      <div class="vibe-quick-chips">
        <span class="vibe-chip" onclick="window.VibeChatWidget.sendQuickPrompt('5만원 이하 봄/가을 셔츠 추천해줘')">👔 셔츠 추천</span>
        <span class="vibe-chip" onclick="window.VibeChatWidget.sendQuickPrompt('내 최근 주문 배송 현황 알려줘')">🚚 배송 조회</span>
        <span class="vibe-chip" onclick="window.VibeChatWidget.sendQuickPrompt('내 장바구니 목록 보여줘')">🛒 장바구니</span>
        <span class="vibe-chip" onclick="window.VibeChatWidget.sendQuickPrompt('WELCOME10 쿠폰 확인해줘')">🎟️ 쿠폰 확인</span>
      </div>

      <!-- Footer Form -->
      <div class="vibe-chat-footer">
        <form id="vibe-chat-form" class="vibe-chat-input-row">
          <input
            type="text"
            id="vibe-input"
            class="vibe-chat-input"
            placeholder="AI에게 무엇이든 물어보세요..."
            autocomplete="off"
          />
          <button
            type="submit"
            id="vibe-send-btn"
            class="w-9 h-9 rounded-xl bg-blue-600 hover:bg-blue-500 text-white flex items-center justify-center text-xs shadow-md shadow-blue-500/20 transition disabled:opacity-50"
          >
            <i class="fa-solid fa-arrow-up"></i>
          </button>
        </form>
      </div>
    </div>
  `;
  document.body.appendChild(widgetContainer);

  // State
  let isOpen = false;
  const messages = [
    { role: 'assistant', content: '안녕하세요! VIBE STORE AI 상담원입니다.' }
  ];

  const chatWindow = document.getElementById('vibe-chat-window');
  const toggleBtn = document.getElementById('vibe-toggle-btn');
  const closeBtn = document.getElementById('vibe-close-btn');
  const chatForm = document.getElementById('vibe-chat-form');
  const inputEl = document.getElementById('vibe-input');
  const messagesArea = document.getElementById('vibe-messages-area');

  function toggleChat(open) {
    isOpen = (open !== undefined) ? open : !isOpen;
    if (isOpen) {
      chatWindow.classList.add('active');
      inputEl.focus();
    } else {
      chatWindow.classList.remove('active');
    }
  }

  toggleBtn.addEventListener('click', () => toggleChat());
  closeBtn.addEventListener('click', () => toggleChat(false));

  function appendMessage(role, text, metadata = null) {
    const bubble = document.createElement('div');
    bubble.className = `vibe-msg-bubble ${role === 'user' ? 'vibe-msg-user' : 'vibe-msg-assistant'}`;
    
    if (role === 'assistant') {
      let metaHtml = '';
      if (metadata && metadata.guardrail_active) {
        if (metadata.input_flagged || metadata.violation_type) {
          metaHtml = `<div class="inline-flex items-center gap-1 bg-rose-100 text-rose-800 text-[10px] font-bold px-1.5 py-0.5 rounded border border-rose-300 mb-1.5">
            <i class="fa-solid fa-shield-halved"></i> ${metadata.matched_rule || '보안 정책 차단'} (${metadata.latency_ms}ms)
          </div>`;
        } else if (metadata.output_masked) {
          metaHtml = `<div class="inline-flex items-center gap-1 bg-amber-100 text-amber-800 text-[10px] font-bold px-1.5 py-0.5 rounded border border-amber-300 mb-1.5">
            <i class="fa-solid fa-user-shield"></i> 개인정보 마스킹 보호 (${metadata.latency_ms}ms)
          </div>`;
        } else {
          metaHtml = `<div class="inline-flex items-center gap-1 bg-blue-50 text-blue-700 text-[10px] font-bold px-1.5 py-0.5 rounded border border-blue-200 mb-1.5">
            <i class="fa-solid fa-circle-check text-emerald-500"></i> 가드레일 안전 통과 (${metadata.latency_ms}ms)
          </div>`;
        }
      }
      bubble.innerHTML = `${metaHtml}<div>${parseMarkdown(text)}</div>`;
    } else {
      bubble.innerText = text;
    }

    messagesArea.appendChild(bubble);
    messagesArea.scrollTop = messagesArea.scrollHeight;
  }

  async function handleSendMessage(promptText) {
    const text = (promptText || inputEl.value).trim();
    if (!text) return;

    inputEl.value = '';
    appendMessage('user', text);
    messages.push({ role: 'user', content: text });

    // Loading Indicator
    const loadingBubble = document.createElement('div');
    loadingBubble.className = 'vibe-msg-bubble vibe-msg-assistant text-slate-400 flex items-center gap-2';
    loadingBubble.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin text-blue-600"></i> AI가 가드레일 검사 및 답변을 생성하고 있습니다...';
    messagesArea.appendChild(loadingBubble);
    messagesArea.scrollTop = messagesArea.scrollHeight;

    try {
      const resp = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-User-Id': 'user_vip_hong'
        },
        body: JSON.stringify({
          messages: messages,
          guardrail_enabled: true,
          model: 'qwen2.5:7b-instruct'
        })
      });

      loadingBubble.remove();

      if (!resp.ok) {
        throw new Error(`HTTP Error ${resp.status}`);
      }

      const data = await resp.json();
      if (data.status === 'blocked') {
        const errMsg = data.error ? data.error.message : '보안 정책 위반으로 차단되었습니다.';
        appendMessage('assistant', errMsg, data.security_metadata);
        messages.push({ role: 'assistant', content: errMsg });
      } else {
        const reply = data.message ? data.message.content : '응답을 처리할 수 없습니다.';
        appendMessage('assistant', reply, data.security_metadata);
        messages.push({ role: 'assistant', content: reply });
      }
    } catch (err) {
      loadingBubble.remove();
      appendMessage('assistant', '⚠️ 백엔드 API 서버(Port 8000)에 연결할 수 없습니다. FastAPI 서버 가동 상태를 확인해 주세요.');
    }
  }

  chatForm.addEventListener('submit', (e) => {
    e.preventDefault();
    handleSendMessage();
  });

  // Global Widget API
  window.VibeChatWidget = {
    open: () => toggleChat(true),
    close: () => toggleChat(false),
    openWithPrompt: (prompt) => {
      toggleChat(true);
      setTimeout(() => handleSendMessage(prompt), 300);
    },
    sendQuickPrompt: (prompt) => {
      handleSendMessage(prompt);
    }
  };

  console.log('[VibeChatWidget] Initialized successfully.');
})();
