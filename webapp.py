from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from scamshield import analyze_text

app = FastAPI(title="ScamShield Web", version="3.0.0")

MAX_TEXT_CHARS = 5000
RATE_LIMIT_PER_MIN = 30

# rate limit: key -> [window_start_ts, count]
_rate: Dict[str, list] = {}

# stats (不存原文)：day_key -> aggregates
_stats: Dict[str, Dict[str, Any]] = {}


def _day_key() -> str:
    # localtime day bucket
    return time.strftime("%Y-%m-%d", time.localtime())


def _fingerprint(req: Request) -> str:
    ip = _client_ip(req)
    ua = (req.headers.get("user-agent") or "").strip()
    raw = f"{ip}|{ua}".encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()[:16]


def _client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else "unknown"


def _rate_limit_ok(key: str) -> bool:
    now = time.time()
    rec = _rate.get(key)
    if rec is None:
        _rate[key] = [now, 1]
        return True
    window_start, count = rec
    if now - window_start >= 60:
        _rate[key] = [now, 1]
        return True
    if count >= RATE_LIMIT_PER_MIN:
        return False
    rec[1] = count + 1
    return True


def _stats_add(result: Dict[str, Any]) -> None:
    dk = _day_key()
    st = _stats.setdefault(dk, {
        "total": 0,
        "levels": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        "types": {},      # type -> count
        "domains": {},    # domain -> count
    })
    st["total"] += 1
    lvl = result.get("risk_level", "low")
    if lvl in st["levels"]:
        st["levels"][lvl] += 1
    for t in (result.get("scam_types") or []):
        st["types"][t] = st["types"].get(t, 0) + 1

    for u in (result.get("suspicious_urls") or []):
        url = u.get("url", "")
        dom = ""
        try:
            from scamshield import domain_of
            dom = domain_of(url)
        except Exception:
            dom = ""
        if dom:
            st["domains"][dom] = st["domains"].get(dom, 0) + 1


@app.get("/health")
def health():
    return {"ok": True, "version": app.version}


@app.get("/stats")
def stats():
    # 不要做成超機密後台，就做 demo：看今天
    dk = _day_key()
    return {"day": dk, "data": _stats.get(dk, {"total": 0, "levels": {}, "types": {}, "domains": {}})}


class AnalyzeRequest(BaseModel):
    text: str = Field(..., description="要分析的文字")
    context: Optional[Dict[str, Any]] = Field(default=None)


class TriggeredRule(BaseModel):
    name: str
    score: int
    evidence_sentences: List[str]


class SuspiciousUrl(BaseModel):
    url: str
    score: int
    reason: str


class Entities(BaseModel):
    phones: List[str] = []
    emails: List[str] = []
    long_numbers: List[str] = []
    urls: List[str] = []


class AnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    stage: str
    scam_types: List[str] = []
    triggered_rules: List[TriggeredRule]
    explanation: str
    recommended_actions: List[str]
    reply_templates: List[str]
    suspicious_urls: List[SuspiciousUrl] = []
    entities: Entities


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
    .wrap{max-width:1100px;margin:0 auto;padding:24px}
    .card{background:#101826;border:1px solid #1f2a3a;border-radius:16px;padding:18px;margin-top:16px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
    textarea{width:100%;min-height:180px;border-radius:12px;border:1px solid #2a3a52;background:#0b1220;color:#e6edf3;padding:12px;font-size:16px;resize:vertical}
    button{border:0;border-radius:12px;padding:12px 16px;background:#00ff88;color:#04210f;font-weight:900;cursor:pointer}
    button:disabled{opacity:.55;cursor:not-allowed}
    .row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
    .pill{display:inline-block;padding:6px 10px;border-radius:999px;border:1px solid #2a3a52;background:#0b1220}
    pre{white-space:pre-wrap;word-break:break-word;background:#0b1220;border:1px solid #2a3a52;border-radius:12px;padding:12px}
    .lvl{font-weight:1000}
    .low{color:#2ecc71}.medium{color:#f1c40f}.high{color:#e74c3c}.critical{color:#ff3b30}
    a{color:#00ff88}
    .small{opacity:.8;font-size:13px}
    .tag{display:inline-block;margin:4px 6px 0 0;padding:6px 10px;border-radius:999px;background:#0b1220;border:1px solid #2a3a52}
    .copy{background:#1f2a3a;color:#e6edf3;font-weight:800}
    .grid{display:grid;grid-template-columns:1fr;gap:16px}
    @media (min-width: 900px){
      .grid{grid-template-columns:1fr 1fr}
    }
    .danger{border-color:#3b1f22}
  </style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ ScamShield 防詐文字分析</h1>

  <div class="card">
    <p>貼上你收到的訊息（簡訊/LINE/FB/Email 都可以），按下分析。<span class="small">（上線版不會幫你存內容，別緊張）</span></p>

    <div class="row" style="margin:10px 0 8px">
      <span class="pill">快速塞範例：</span>
      <button class="copy" onclick="fillEx('account')">假客服/帳戶凍結</button>
      <button class="copy" onclick="fillEx('invest')">投資飆股</button>
      <button class="copy" onclick="fillEx('loan')">交友借錢</button>
      <button class="copy" onclick="fillEx('ship')">包裹/物流</button>
      <button class="copy" onclick="fillEx('task')">打工刷單</button>
    </div>

    <textarea id="text" placeholder="例如：你的帳戶異常，請立即匯款並提供驗證碼，否則凍結..."></textarea>

    <div class="row" style="margin-top:12px">
      <button id="btn" onclick="run()">分析</button>
      <span class="pill">⚠️ 這是輔助判斷工具，請以官方管道查證</span>
      <span class="pill">Swagger：<a href="/docs" target="_blank" rel="noreferrer">/docs</a></span>
      <span class="pill">Stats：<a href="/stats" target="_blank" rel="noreferrer">/stats</a></span>
    </div>
  </div>

  <div class="grid" id="grid" style="display:none">
    <div class="card" id="out">
      <h2>結果</h2>
      <div class="row">
        <div>風險分數：<span id="score" class="lvl"></span></div>
        <div>風險等級：<span id="level" class="lvl"></span></div>
        <div>流程階段：<span id="stage" class="lvl"></span></div>
      </div>

      <h3>詐騙類型</h3>
      <div id="types"></div>

      <h3>簡短說明</h3>
      <pre id="explain"></pre>

      <h3>建議行動</h3>
      <pre id="actions"></pre>
    </div>

    <div class="card" id="right">
      <h3>可疑網址（請先不要點）</h3>
      <pre id="urls" class="danger"></pre>

      <h3>可直接複製回覆模板</h3>
      <div class="row" style="margin:8px 0">
        <button class="copy" onclick="copyTemplates()">一鍵複製模板</button>
        <button class="copy" onclick="copyReport()">一鍵複製完整報告</button>
        <span class="small" id="copyhint"></span>
      </div>
      <pre id="templates"></pre>

      <details style="margin-top:10px">
        <summary>查看命中規則與證據句（進階）</summary>
        <pre id="rules"></pre>
      </details>
    </div>
  </div>

  <p class="small">API: <code>POST /analyze</code>，健康檢查：<code>/health</code></p>
</div>

<script>
let lastTemplates = "";
let lastReport = "";

function fillEx(kind){
  const ex = {
    account: "你的帳戶異常，請立即匯款並提供驗證碼，否則凍結。",
    invest: "誠徵在家兼職！日領3000起，加入群組跟著老師帶單，高報酬穩賺不賠。",
    loan: "我這邊臨時周轉一下，可以先借我 8000 嗎？我晚點就還你，拜託很急。",
    ship: "【物流通知】你的包裹地址不完整，請24小時內補填資料：https://tinyurl.com/xxxxx 否則退回。",
    task: "先幫忙刷單提高評價，完成後立刻返款+佣金，先墊付更快升級哦！"
  };
  document.getElementById("text").value = ex[kind] || "";
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

    document.getElementById("grid").style.display = "grid";

    document.getElementById("score").textContent = data.risk_score;

    const levelEl = document.getElementById("level");
    levelEl.textContent = data.risk_level;
    levelEl.className = "lvl " + data.risk_level;

    document.getElementById("stage").textContent = data.stage;

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

    document.getElementById("explain").textContent = data.explanation;
    document.getElementById("actions").textContent = (data.recommended_actions || []).map(x=>"• "+x).join("\\n");

    // suspicious urls
    const urlsText = (data.suspicious_urls || []).length
      ? (data.suspicious_urls || []).map(u=>`• ${u.url}（+${u.score}）\\n  - ${u.reason}`).join("\\n")
      : "（未偵測到明顯短網址/可疑網址，但也不要亂點連結啦）";
    document.getElementById("urls").textContent = urlsText;

    const tpl = (data.reply_templates || []).map((x,i)=>`${i+1}. ${x}`).join("\\n");
    document.getElementById("templates").textContent = tpl;
    lastTemplates = tpl;

    document.getElementById("rules").textContent = JSON.stringify(data.triggered_rules, null, 2);

    // full report (plain text)
    lastReport =
`【ScamShield 分析報告】
風險分數：${data.risk_score}
風險等級：${data.risk_level}
流程階段：${data.stage}
詐騙類型：${(data.scam_types||[]).join("、") || "（未明確）"}

簡短說明：
${data.explanation}

建議行動：
${(data.recommended_actions||[]).map(x=>"• "+x).join("\\n")}

可疑網址：
${(data.suspicious_urls||[]).map(u=>`• ${u.url}（${u.reason}）`).join("\\n") || "（未偵測到）"}

回覆模板：
${tpl}
`;

    // scroll
    document.getElementById("grid").scrollIntoView({behavior:"smooth", block:"start"});
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

async function copyReport(){
  if(!lastReport){ return; }
  try{
    await navigator.clipboard.writeText(lastReport);
    document.getElementById("copyhint").textContent = "✅ 已複製完整報告（貼給長輩/客服/警察都能用）";
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
    key = _fingerprint(req)
    if not _rate_limit_ok(key):
        return JSONResponse(status_code=429, content={"detail": "太多次啦靠杯（rate limit）— 請稍後再試"})

    text = (body.text or "").strip()
    if not text:
        return JSONResponse(status_code=400, content={"detail": "text 不能是空的"})
    if len(text) > MAX_TEXT_CHARS:
        return JSONResponse(status_code=400, content={"detail": f"text 太長（最多 {MAX_TEXT_CHARS} 字）"})

    try:
        result = analyze_text(text, context=body.context)
        _stats_add(result)
        return result
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": f"Internal error: {type(e).__name__}"})
