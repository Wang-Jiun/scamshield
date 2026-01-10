from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from scamshield import analyze_text

app = FastAPI(title="ScamShield Web", version="3.0.0")

MAX_TEXT_CHARS = 5000
RATE_LIMIT_PER_MIN = 30

# ip -> [window_start_ts, count]
_rate: Dict[str, list] = {}

# very simple stats (in-memory)
_stats = {
    "started_at": time.time(),
    "total_requests": 0,
    "rate_limited": 0,
    "avg_score": 0.0,
    "levels": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    "type_counter": {},  # type -> count
}


def _client_ip(req: Request) -> str:
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
    return {"ok": True, "version": app.version}


class AnalyzeRequest(BaseModel):
    text: str = Field(..., description="要分析的文字")
    context: Optional[Dict[str, Any]] = Field(default=None)


class TriggeredRule(BaseModel):
    name: str
    score: int
    evidence_sentences: List[str]


class AnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    scam_types: List[str] = []
    current_stage: str
    suspicious_links: List[str] = []
    triggered_rules: List[TriggeredRule]
    explanation: str
    recommended_actions: List[str]
    reply_templates: List[str]
    meta: Dict[str, Any] = {}


@app.get("/stats")
def stats():
    # 不做持久化，Render 重新部署就會重置（Lv1 很夠用）
    up = int(time.time() - _stats["started_at"])
    # top 8 types
    tc = _stats["type_counter"]
    top_types = sorted(tc.items(), key=lambda x: x[1], reverse=True)[:8]
    return {
        "uptime_sec": up,
        "total_requests": _stats["total_requests"],
        "rate_limited": _stats["rate_limited"],
        "avg_score": round(_stats["avg_score"], 2),
        "levels": _stats["levels"],
        "top_scam_types": [{"type": k, "count": v} for k, v in top_types],
        "note": "此統計為記憶體暫存，服務重啟會重置。",
    }


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
    .wrap{max-width:1040px;margin:0 auto;padding:24px}
    .card{background:#101826;border:1px solid #1f2a3a;border-radius:18px;padding:18px;margin-top:16px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
    textarea{width:100%;min-height:200px;border-radius:14px;border:1px solid #2a3a52;background:#0b1220;color:#e6edf3;padding:12px;font-size:16px;resize:vertical;line-height:1.5}
    button{border:0;border-radius:12px;padding:12px 16px;background:#00ff88;color:#04210f;font-weight:900;cursor:pointer}
    button:disabled{opacity:.55;cursor:not-allowed}
    .row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
    .pill{display:inline-block;padding:7px 12px;border-radius:999px;border:1px solid #2a3a52;background:#0b1220}
    pre{white-space:pre-wrap;word-break:break-word;background:#0b1220;border:1px solid #2a3a52;border-radius:12px;padding:12px;margin:0}
    .lvl{font-weight:1000}
    .low{color:#2ecc71}.medium{color:#f1c40f}.high{color:#e74c3c}.critical{color:#ff3b30}
    a{color:#00ff88;text-decoration:none}
    a:hover{text-decoration:underline}
    .small{opacity:.82;font-size:13px}
    .tag{display:inline-block;margin:6px 8px 0 0;padding:7px 12px;border-radius:999px;background:#0b1220;border:1px solid #2a3a52}
    .copy{background:#1f2a3a;color:#e6edf3;font-weight:800}
    .grid{display:grid;grid-template-columns:1fr;gap:16px}
    @media(min-width:980px){.grid{grid-template-columns:1fr 1fr}}
    .box{border:1px solid #243149;border-radius:14px;padding:12px;background:#0b1220}
    .muted{opacity:.9}
    .warn{color:#ffd166}
    .danger{color:#ff6b6b}
    .btn2{background:#223149;color:#e6edf3}
  </style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ ScamShield 防詐文字分析</h1>

  <div class="card">
    <p>貼上你收到的訊息（簡訊/LINE/FB/Email 都可以），按下分析。<span class="small">（上線版不會幫你存內容，別緊張）</span></p>

    <div class="row" style="margin:8px 0 10px">
      <span class="pill">快速塞範例：</span>
      <button class="btn2" onclick="fillExample('account')">假客服/帳戶凍結</button>
      <button class="btn2" onclick="fillExample('invest')">投資飆股</button>
      <button class="btn2" onclick="fillExample('friend')">交友借錢</button>
      <button class="btn2" onclick="fillExample('logistics')">包裹/物流</button>
      <button class="btn2" onclick="fillExample('job')">打工刷單</button>
    </div>

    <textarea id="text" placeholder="例如：你的帳戶異常，請立即匯款並提供驗證碼，否則凍結..."></textarea>

    <div class="row" style="margin-top:12px">
      <button id="btn" onclick="run()">分析</button>
      <span class="pill">⚠️ 這是輔助判斷工具，請以官方管道查證</span>
      <span class="pill">Swagger：<a href="/docs" target="_blank" rel="noreferrer">/docs</a></span>
      <span class="pill">Stats：<a href="/stats" target="_blank" rel="noreferrer">/stats</a></span>
    </div>
  </div>

  <div class="grid" id="out" style="display:none">
    <div class="card">
      <h2>結果</h2>
      <div class="row">
        <div>風險分數：<span id="score" class="lvl"></span></div>
        <div>風險等級：<span id="level" class="lvl"></span></div>
        <div class="muted">流程階段：<span id="stage"></span></div>
      </div>

      <h3 style="margin-top:14px">詐騙類型</h3>
      <div id="types"></div>

      <h3 style="margin-top:14px">簡短說明</h3>
      <div class="box"><pre id="explain"></pre></div>

      <h3 style="margin-top:14px">建議行動</h3>
      <div class="box"><pre id="actions"></pre></div>
    </div>

    <div class="card">
      <h3>可疑網址（請先不要點）</h3>
      <div class="box"><pre id="links"></pre></div>

      <h3 style="margin-top:14px">可直接複製回覆模板</h3>
      <div class="row" style="margin:8px 0">
        <button class="copy" onclick="copyTemplates()">一鍵複製模板</button>
        <button class="copy" onclick="copyFullReport()">一鍵複製完整報告</button>
        <span class="small" id="copyhint"></span>
      </div>
      <div class="box"><pre id="templates"></pre></div>

      <details style="margin-top:14px">
        <summary>查看命中規則與證據句（進階）</summary>
        <div class="box" style="margin-top:10px"><pre id="rules"></pre></div>
      </details>
    </div>
  </div>

  <p class="small" style="margin-top:18px">API: <code>POST /analyze</code>，健康檢查：<code>/health</code></p>
</div>

<script>
let lastTemplates = "";
let lastFullReport = "";

function makeBullets(arr){
  return (arr || []).map(x=>"• "+x).join("\\n");
}
function fillExample(kind){
  const map = {
    account: "【安全通知】你的帳戶異常，請立即點擊連結登入驗證：https://reurl.cc/xxxxx 否則將凍結。",
    invest: "老師帶你穩賺飆股！今天最後名額，加入群組領內線：t.me/xxxxxx 保證獲利。",
    friend: "我這邊臨時周轉一下，可以先借我 8000 嗎？我晚點就還你，拜託很急。",
    logistics: "【物流通知】你的包裹地址不完整，請24小時內補填資料：https://tinyurl.com/xxxxx 否則退回。",
    job: "誠徵在家兼職！日領3000起，先幫忙刷單提高評價，完成後返款+佣金，加入群組：t.me/xxxxxx"
  };
  document.getElementById("text").value = map[kind] || "";
}

async function run(){
  const btn = document.getElementById("btn");
  const text = document.getElementById("text").value.trim();
  if(!text){ alert("先貼文字啦靠杯 🤣"); return; }

  btn.disabled = true; btn.textContent="分析中…";
  document.getElementById("copyhint").textContent = "";
  try{
    const res = await fetch("/analyze", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ text })
    });

    const data = await res.json().catch(()=> ({}));
    if(!res.ok){
      alert(data.detail || ("出事了，HTTP " + res.status));
      return;
    }

    document.getElementById("out").style.display = "grid";
    document.getElementById("score").textContent = data.risk_score;

    const levelEl = document.getElementById("level");
    levelEl.textContent = data.risk_level;
    levelEl.className = "lvl " + data.risk_level;

    document.getElementById("stage").textContent = data.current_stage || "-";

    // types
    const typesEl = document.getElementById("types");
    typesEl.innerHTML = "";
    (data.scam_types || []).forEach(t=>{
      const span = document.createElement("span");
      span.className = "tag";
      span.textContent = t;
      typesEl.appendChild(span);
    });
    if((data.scam_types || []).length === 0){
      typesEl.innerHTML = "<span class='small'>（目前沒有明顯類型，但仍建議你用官方管道確認）</span>";
    }

    document.getElementById("explain").textContent = data.explanation || "";
    document.getElementById("actions").textContent = makeBullets(data.recommended_actions);

    // suspicious links
    const links = (data.suspicious_links || []);
    document.getElementById("links").textContent = links.length ? makeBullets(links.map(u=>u + "（短網址⚠️）")) : "（未偵測到明顯短網址，但仍建議不要亂點）";

    const tpl = (data.reply_templates || []).map((x,i)=>`${i+1}. ${x}`).join("\\n");
    document.getElementById("templates").textContent = tpl;
    lastTemplates = tpl;

    document.getElementById("rules").textContent = JSON.stringify(data.triggered_rules || [], null, 2);

    // full report for copy
    lastFullReport =
`【ScamShield 分析報告】
風險分數：${data.risk_score}
風險等級：${data.risk_level}
流程階段：${data.current_stage || "-"}

詐騙類型：
${(data.scam_types||[]).map(x=>"• "+x).join("\\n") || "•（未明顯分類）"}

簡短說明：
${data.explanation || ""}

建議行動：
${makeBullets(data.recommended_actions)}

可疑網址：
${(data.suspicious_links||[]).map(x=>"• "+x).join("\\n") || "•（無）"}

回覆模板：
${tpl}
`;

    document.getElementById("out").scrollIntoView({behavior:"smooth", block:"start"});
  }catch(e){
    alert("出事了：" + e);
  }finally{
    btn.disabled=false; btn.textContent="分析";
  }
}

async function copyTemplates(){
  if(!lastTemplates){ return; }
  try{
    await navigator.clipboard.writeText(lastTemplates);
    document.getElementById("copyhint").textContent = "✅ 已複製模板，貼去回對方就好（別被騙啦）";
  }catch(e){
    document.getElementById("copyhint").textContent = "⚠️ 無法自動複製，你手動選取也行";
  }
}

async function copyFullReport(){
  if(!lastFullReport){ return; }
  try{
    await navigator.clipboard.writeText(lastFullReport);
    document.getElementById("copyhint").textContent = "✅ 已複製完整報告（拿去貼群組炫耀也可以）";
  }catch(e){
    document.getElementById("copyhint").textContent = "⚠️ 無法自動複製，你手動選取也行";
  }
}
</script>
</body>
</html>
"""


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(body: AnalyzeRequest, req: Request):
    ip = _client_ip(req)
    if not _rate_limit_ok(ip):
        _stats["rate_limited"] += 1
        return JSONResponse(status_code=429, content={"detail": "太多次啦靠杯（rate limit）— 請稍後再試"})

    text = (body.text or "").strip()
    if not text:
        return JSONResponse(status_code=400, content={"detail": "text 不能是空的"})
    if len(text) > MAX_TEXT_CHARS:
        return JSONResponse(status_code=400, content={"detail": f"text 太長（最多 {MAX_TEXT_CHARS} 字）"})

    try:
        result = analyze_text(text, context=body.context)

        # update stats
        _stats["total_requests"] += 1
        n = _stats["total_requests"]
        score = int(result.get("risk_score", 0))
        _stats["avg_score"] = ((_stats["avg_score"] * (n - 1)) + score) / n

        lvl = result.get("risk_level", "low")
        if lvl in _stats["levels"]:
            _stats["levels"][lvl] += 1

        for t in result.get("scam_types", []) or []:
            _stats["type_counter"][t] = _stats["type_counter"].get(t, 0) + 1

        return result
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": f"Internal error: {type(e).__name__}"})
