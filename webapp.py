from __future__ import annotations

import time
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from scamshield import analyze_text

app = FastAPI(title="ScamShield Web", version="0.1.0")

# ========= basic protections =========
MAX_TEXT_CHARS = 5000
RATE_LIMIT_PER_MIN = 30

# ip -> (window_start_ts, count)
_rate: Dict[str, list] = {}


def _client_ip(req: Request) -> str:
    # Render 常見：X-Forwarded-For
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else "unknown"


def _rate_limit_ok(ip: str) -> bool:
    now = time.time()
    rec = _rate.get(ip)
    if rec is None:
        _rate[ip] = [now, 1]
        return True
    window_start, count = rec
    if now - window_start >= 60:
        _rate[ip] = [now, 1]
        return True
    if count >= RATE_LIMIT_PER_MIN:
        return False
    rec[1] = count + 1
    return True


@app.get("/health")
def health():
    return {"ok": True}


class AnalyzeRequest(BaseModel):
    text: str = Field(..., description="要分析的文字")
    context: Optional[Dict[str, Any]] = Field(default=None, description="可選：情境/來源等資訊")


@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>ScamShield 防詐分析</title>
  <style>
    body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans TC",sans-serif;background:#0b0f14;color:#e6edf3;margin:0}
    .wrap{max-width:920px;margin:0 auto;padding:24px}
    .card{background:#101826;border:1px solid #1f2a3a;border-radius:16px;padding:18px;margin-top:16px}
    textarea{width:100%;min-height:160px;border-radius:12px;border:1px solid #2a3a52;background:#0b1220;color:#e6edf3;padding:12px;font-size:16px}
    button{border:0;border-radius:12px;padding:12px 16px;background:#00ff88;color:#04210f;font-weight:800;cursor:pointer}
    button:disabled{opacity:.55;cursor:not-allowed}
    .row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
    .pill{display:inline-block;padding:6px 10px;border-radius:999px;border:1px solid #2a3a52;background:#0b1220}
    pre{white-space:pre-wrap;word-break:break-word;background:#0b1220;border:1px solid #2a3a52;border-radius:12px;padding:12px}
    .lvl{font-weight:900}
    .low{color:#2ecc71}.medium{color:#f1c40f}.high{color:#e74c3c}.critical{color:#ff3b30}
    a{color:#00ff88}
    .small{opacity:.8;font-size:13px}
    code{background:#0b1220;border:1px solid #2a3a52;border-radius:8px;padding:2px 6px}
  </style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ ScamShield 防詐文字分析</h1>
  <div class="card">
    <p>貼上你收到的訊息（簡訊/LINE/FB/Email 都可以），按下分析。<span class="small">（上線版不會幫你存內容，別緊張）</span></p>
    <textarea id="text" placeholder="例如：你的帳戶異常，請立即匯款並提供驗證碼，否則凍結..."></textarea>
    <div class="row" style="margin-top:12px">
      <button id="btn" onclick="run()">分析</button>
      <span class="pill">⚠️ 這是輔助判斷工具，請以官方管道查證</span>
      <span class="pill">Swagger：<a href="/docs">/docs</a></span>
    </div>
  </div>

  <div class="card" id="out" style="display:none">
    <h2>結果</h2>
    <div class="row">
      <div>風險分數：<span id="score" class="lvl"></span></div>
      <div>風險等級：<span id="level" class="lvl"></span></div>
    </div>

    <h3>簡短說明</h3>
    <pre id="explain"></pre>

    <h3>建議行動</h3>
    <pre id="actions"></pre>

    <h3>可直接複製回覆模板</h3>
    <pre id="templates"></pre>

    <details>
      <summary>查看命中規則與證據句（進階）</summary>
      <pre id="rules"></pre>
    </details>
  </div>

  <p class="small">API: <code>POST /analyze</code>，健康檢查：<code>/health</code></p>
</div>

<script>
async function run(){
  const btn = document.getElementById("btn");
  const text = document.getElementById("text").value.trim();
  if(!text){ alert("先貼文字啦靠杯 🤣"); return; }

  btn.disabled = true; btn.textContent="分析中…";
  try{
    const res = await fetch("/analyze", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ text })
    });
    const data = await res.json();

    if(!res.ok){
      alert(data.detail || "出事了");
      return;
    }

    document.getElementById("out").style.display = "block";
    document.getElementById("score").textContent = data.risk_score;

    const levelEl = document.getElementById("level");
    levelEl.textContent = data.risk_level;
    levelEl.className = "lvl " + data.risk_level;

    document.getElementById("explain").textContent = data.explanation;
    document.getElementById("actions").textContent = (data.recommended_actions || []).map(x=>"• "+x).join("\\n");
    document.getElementById("templates").textContent = (data.reply_templates || []).map((x,i)=>`${i+1}. ${x}`).join("\\n");
    document.getElementById("rules").textContent = JSON.stringify(data.triggered_rules, null, 2);
  }catch(e){
    alert("出事了：" + e);
  }finally{
    btn.disabled=false; btn.textContent="分析";
  }
}
</script>
</body>
</html>
"""


@app.post("/analyze")
def analyze(payload: AnalyzeRequest, request: Request):
    ip = _client_ip(request)
    if not _rate_limit_ok(ip):
        raise HTTPException(status_code=429, detail="太多次啦靠杯（rate limit）— 請稍後再試")

    text = (payload.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="text 不能是空的")
    if len(text) > MAX_TEXT_CHARS:
        raise HTTPException(status_code=400, detail=f"text 太長（最多 {MAX_TEXT_CHARS} 字）")

    return analyze_text(text, context=payload.context)

