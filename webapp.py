from __future__ import annotations

import json
import os
import time
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request, Header, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from scamshield import analyze_text

app = FastAPI(title="ScamShield Web", version="1.4.1")

MAX_TEXT_CHARS = 5000
RATE_LIMIT_PER_MIN = 30

# 網站用 IP rate limit（只給 /analyze）
_rate_ip: Dict[str, list] = {}

# 付費 API 用量（記憶體版：單 instance OK，多 instance 之後再升級 DB/Redis）
_usage_by_key: Dict[str, Dict[str, int]] = {}  # api_key -> {"YYYY-MM-DD": count}

POLICY_VERSION = "2026.01"
MODEL_VERSION = "rules-v1"


# -------------------------
# Helpers
# -------------------------
def _utc_day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else "unknown"


def _rate_limit_ok_ip(ip: str) -> bool:
    now = time.time()
    rec = _rate_ip.get(ip)
    if rec is None:
        _rate_ip[ip] = [now, 1]
        return True
    window_start, count = rec
    if now - window_start >= 60:
        _rate_ip[ip] = [now, 1]
        return True
    if count >= RATE_LIMIT_PER_MIN:
        return False
    rec[1] = count + 1
    return True


def _parse_plan_quotas() -> Dict[str, int]:
    raw = os.getenv("PLAN_DAILY_QUOTAS", '{"free":50,"pro":500,"enterprise":999999}')
    try:
        data = json.loads(raw)
        out: Dict[str, int] = {}
        for k, v in data.items():
            out[str(k).lower()] = int(v)
        return out
    except Exception:
        return {"free": 50, "pro": 500, "enterprise": 999999}


def _parse_api_keys() -> Dict[str, str]:
    """
    Render env: SCAMSHIELD_API_KEYS="sk_free_xxx:free,sk_pro_yyy:pro"
    回傳 dict: api_key -> plan
    """
    raw = os.getenv("SCAMSHIELD_API_KEYS", "").strip()
    out: Dict[str, str] = {}
    if not raw:
        return out

    parts = [p.strip() for p in raw.split(",") if p.strip()]
    for p in parts:
        if ":" not in p:
            continue
        key, plan = p.split(":", 1)
        key = key.strip()
        plan = plan.strip().lower()
        if key:
            out[key] = plan
    return out


def _mask_key(k: str) -> str:
    if len(k) <= 8:
        return "***"
    return k[:4] + "..." + k[-4:]


def _quota_for(plan: str, quotas: Dict[str, int]) -> int:
    return int(quotas.get(plan, 0))


def _get_used_today(api_key: str) -> int:
    day = _utc_day()
    return int(_usage_by_key.get(api_key, {}).get(day, 0))


def _inc_and_get_usage(api_key: str, quota: int) -> Tuple[int, int]:
    """
    先檢查、允許才 +1
    回傳 (used_after_inc, remaining_after_inc)
    若已滿額，丟 HTTPException 429
    """
    day = _utc_day()
    per_key = _usage_by_key.setdefault(api_key, {})
    used = int(per_key.get(day, 0))

    if quota <= 0:
        raise HTTPException(status_code=403, detail="Plan quota is not configured")

    if used >= quota:
        raise HTTPException(
            status_code=429,
            detail="API quota exceeded",
        )

    used += 1
    per_key[day] = used
    remaining = max(quota - used, 0)
    return used, remaining


async def require_api_key(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """
    支援：
    - Authorization: Bearer <key>
    - X-API-Key: <key>
    """
    admin_key = os.getenv("ADMIN_KEY", "").strip()
    keys = _parse_api_keys()
    quotas = _parse_plan_quotas()

    key = None
    if authorization and authorization.lower().startswith("bearer "):
        key = authorization.split(" ", 1)[1].strip()
    elif x_api_key:
        key = x_api_key.strip()

    if not key:
        raise HTTPException(status_code=401, detail="Missing API key")

    # 管理者 key：全通（視同 enterprise）
    if admin_key and secrets.compare_digest(key, admin_key):
        return {
            "api_key": key,
            "plan": "enterprise",
            "is_admin": True,
            "quota": _quota_for("enterprise", quotas),
        }

    plan = keys.get(key)
    if not plan:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return {
        "api_key": key,
        "plan": plan,
        "is_admin": False,
        "quota": _quota_for(plan, quotas),
    }


def _with_rate_headers(resp: JSONResponse, plan: str, quota: int, used: int) -> JSONResponse:
    # 更像商業產品：X-RateLimit headers
    remaining = max(quota - used, 0)
    resp.headers["X-RateLimit-Plan"] = plan
    resp.headers["X-RateLimit-Limit"] = str(quota)
    resp.headers["X-RateLimit-Remaining"] = str(remaining)
    resp.headers["X-RateLimit-Reset-UTC"] = _utc_day()
    return resp


# -------------------------
# API / Models
# -------------------------
@app.get("/health")
def health():
    return {"ok": True}


class AnalyzeRequest(BaseModel):
    text: str = Field(..., description="要分析的文字")
    context: Optional[Dict[str, Any]] = Field(default=None)


class TriggeredRule(BaseModel):
    name: str
    score: int
    evidence_sentences: List[str]


class AnalyzeResponse(BaseModel):
    request_id: str
    risk_score: int
    risk_level: str
    scam_types: List[str] = []
    triggered_rules: List[TriggeredRule]
    explanation: str
    recommended_actions: List[str]
    reply_templates: List[str]
    policy_version: str
    model_version: str


# -------------------------
# Web UI
# -------------------------
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
    .wrap{max-width:960px;margin:0 auto;padding:24px}
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
      <span class="pill">Swagger：<a href="/docs" target="_blank" rel="noreferrer">/docs</a></span>
    </div>
  </div>

  <div class="card" id="out" style="display:none">
    <h2>結果</h2>
    <div class="row">
      <div>風險分數：<span id="score" class="lvl"></span></div>
      <div>風險等級：<span id="level" class="lvl"></span></div>
    </div>

    <h3>詐騙類型</h3>
    <div id="types"></div>

    <h3>簡短說明</h3>
    <pre id="explain"></pre>

    <h3>建議行動</h3>
    <pre id="actions"></pre>

    <h3>可直接複製回覆模板</h3>
    <div class="row" style="margin:8px 0">
      <button class="copy" onclick="copyTemplates()">一鍵複製模板</button>
      <span class="small" id="copyhint"></span>
    </div>
    <pre id="templates"></pre>

    <details style="margin-top:10px">
      <summary>查看命中規則與證據句（進階）</summary>
      <pre id="rules"></pre>
    </details>
  </div>

  <p class="small">Web API: <code>POST /analyze</code>，健康檢查：<code>/health</code></p>
  <p class="small">Paid API: <code>POST /api/v1/analyze</code>（需要 API Key），用量：<code>/api/v1/usage</code></p>
</div>

<script>
let lastTemplates = "";

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

    document.getElementById("out").style.display = "block";
    document.getElementById("score").textContent = data.risk_score;

    const levelEl = document.getElementById("level");
    levelEl.textContent = data.risk_level;
    levelEl.className = "lvl " + data.risk_level;

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

    const tpl = (data.reply_templates || []).map((x,i)=>`${i+1}. ${x}`).join("\\n");
    document.getElementById("templates").textContent = tpl;
    lastTemplates = tpl;

    document.getElementById("rules").textContent = JSON.stringify(data.triggered_rules, null, 2);
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
    document.getElementById("copyhint").textContent = "✅ 已複製，貼去回對方就好（別被騙啦）";
  }catch(e){
    document.getElementById("copyhint").textContent = "⚠️ 無法自動複製，你手動選取也行";
  }
}
</script>
</body>
</html>
"""


# -------------------------
# Web Analyze (no API key)
# -------------------------
@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_web(body: AnalyzeRequest, req: Request):
    ip = _client_ip(req)
    if not _rate_limit_ok_ip(ip):
        return JSONResponse(status_code=429, content={"detail": "太多次啦靠杯（rate limit）— 請稍後再試"})

    text = (body.text or "").strip()
    if not text:
        return JSONResponse(status_code=400, content={"detail": "text 不能是空的"})
    if len(text) > MAX_TEXT_CHARS:
        return JSONResponse(status_code=400, content={"detail": f"text 太長（最多 {MAX_TEXT_CHARS} 字）"})

    try:
        result = analyze_text(text, context=body.context)
        return {
            "request_id": secrets.token_hex(8),
            **result,
            "policy_version": POLICY_VERSION,
            "model_version": MODEL_VERSION,
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": f"Internal error: {type(e).__name__}"})


# -------------------------
# Paid API (requires API key)
# -------------------------
@app.get("/api/v1/usage")
async def api_usage(auth=Depends(require_api_key)):
    quotas = _parse_plan_quotas()
    quota = _quota_for(auth["plan"], quotas)
    used = _get_used_today(auth["api_key"])
    remaining = max(quota - used, 0)
    return {
        "day_utc": _utc_day(),
        "plan": auth["plan"],
        "quota": quota,
        "used": used,
        "remaining": remaining,
        "key": _mask_key(auth["api_key"]),
        "policy_version": POLICY_VERSION,
        "model_version": MODEL_VERSION,
    }


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def api_analyze(body: AnalyzeRequest, auth=Depends(require_api_key)):
    text = (body.text or "").strip()
    if not text:
        return JSONResponse(status_code=400, content={"detail": "text 不能是空的"})
    if len(text) > MAX_TEXT_CHARS:
        return JSONResponse(status_code=400, content={"detail": f"text 太長（最多 {MAX_TEXT_CHARS} 字）"})

    quotas = _parse_plan_quotas()
    quota = _quota_for(auth["plan"], quotas)

    # 先扣額度（滿額直接 429）
    try:
        used_after, remaining_after = _inc_and_get_usage(auth["api_key"], quota)
    except HTTPException as he:
        # 429 / 403 等直接回
        return JSONResponse(
            status_code=he.status_code,
            content={
                "detail": he.detail,
                "plan": auth["plan"],
                "day_utc": _utc_day(),
            },
        )

    try:
        result = analyze_text(text, context=body.context)
        resp = JSONResponse(
            status_code=200,
            content={
                "request_id": secrets.token_hex(8),
                **result,
                "policy_version": POLICY_VERSION,
                "model_version": MODEL_VERSION,
            },
        )
        return _with_rate_headers(resp, auth["plan"], quota, used_after)
    except Exception as e:
        # 如果分析失敗，理論上要把扣掉的額度補回去（這裡簡化：不補回，避免被濫用）
        return JSONResponse(status_code=500, content={"detail": f"Internal error: {type(e).__name__}"})
