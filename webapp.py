from __future__ import annotations

import json
import os
import time
import secrets
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request, Header, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from scamshield import analyze_text

app = FastAPI(title="ScamShield Web", version="1.6.0")

# ======================
# LINE Bot 設定（全域）
# ======================
import requests

LINE_CHANNEL_SECRET = os.getenv("LINE_CHANNEL_SECRET", "")
LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "")

def _line_reply(reply_token: str, text: str) -> None:
    """
    用 LINE Messaging API 回覆文字訊息
    """
    if not LINE_CHANNEL_ACCESS_TOKEN:
        print("LINE_CHANNEL_ACCESS_TOKEN missing")
        return

    url = "https://api.line.me/v2/bot/message/reply"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}",
    }
    payload = {
        "replyToken": reply_token,
        "messages": [{"type": "text", "text": text[:5000]}],
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=10)
        if r.status_code >= 400:
            print("LINE reply failed:", r.status_code, r.text)
    except Exception as e:
        print("LINE reply exception:", e)
def _lvl_badge(level: str) -> str:
    lv = (level or "").lower()
    if lv == "critical":
        return "🔴 高度可疑"
    if lv == "high":
        return "🟠 高風險"
    if lv == "medium":
        return "🟡 中風險"
    if lv == "low":
        return "🟢 低風險"
    return "⚪ 未知"


def _shorten(s: str, n: int = 180) -> str:
    s = (s or "").strip()
    if len(s) <= n:
        return s
    return s[:n].rstrip() + "…"


def format_line_reply(result: dict) -> str:
    level = result.get("risk_level", "unknown")
    score = int(result.get("risk_score", 0) or 0)
    types = result.get("scam_types", []) or []
    explain = (result.get("explanation", "") or "").strip()
    actions = result.get("recommended_actions", []) or []
    templates = result.get("reply_templates", []) or []
    urls = result.get("suspicious_urls", []) or []

    types_str = "、".join(types) if types else "（未明確歸類）"

    url_lines = []
    for u in urls[:3]:
        if isinstance(u, dict):
            url_lines.append(f"• {u.get('url','')}（+{u.get('score',0)}）")
        else:
            url_lines.append(f"• {str(u)}")

    badge = _lvl_badge(level)

    blocks = []
    blocks.append("🛡️ ScamShield 防詐快篩")
    blocks.append(f"{badge}｜分數：{score}/100")
    blocks.append(f"類型：{types_str}")

    if explain:
        blocks.append("\n📌 我看到的可疑點")
        blocks.append(_shorten(explain, 220))

    if url_lines:
        blocks.append("\n🔗 可疑連結")
        blocks.append("\n".join(url_lines))

    if actions:
        blocks.append("\n✅ 建議作法")
        blocks.append("\n".join([f"{i+1}. {a}" for i, a in enumerate(actions[:4])]))

    if templates:
        blocks.append("\n✍️ 可以直接回覆")
        for i, t in enumerate(templates[:3], start=1):
            blocks.append(f"{i}) {t}")

    blocks.append("\n—\n⚠️ 提醒：這是輔助判斷，重大金流/個資請用官方管道再確認。")

    return "\n".join(blocks)[:4800]


MAX_TEXT_CHARS = 5000
RATE_LIMIT_PER_MIN = 30

# ===== Web IP rate limit（給 /analyze 用）=====
_rate_ip: Dict[str, list] = {}  # ip -> [window_start, count]

# ===== API 授權用量（記憶體版：單機準、多 instance 會不準；之後可升級 Redis/DB）=====
_usage_by_key: Dict[str, Dict[str, int]] = {}  # api_key -> {"YYYY-MM-DD": count}

POLICY_VERSION = "2026.01"
MODEL_VERSION = "rules-v1"

# =========================
# 匿名統計（不存原文）
# =========================
_STATS: Dict[str, Any] = {
    "since_epoch": int(time.time()),
    "total": 0,
    "by_level": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    "by_type": {},  # scam_type -> count
    "last_50": [],  # 最近 50 次（只記匿名摘要）

    # ✅ 趨勢：日/小時聚合（UTC）
    "daily": {},   # day -> {total, score_sum, by_level, by_type}
    "hourly": {},  # hour -> {total, score_sum, by_level}
}

def _utc_day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _utc_hour() -> str:
    # e.g. "2026-01-11 05"
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H")


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _prune_hourly(max_hours: int = 48) -> None:
    keys = sorted(_STATS["hourly"].keys())
    if len(keys) <= max_hours:
        return
    for k in keys[:-max_hours]:
        _STATS["hourly"].pop(k, None)


def _prune_daily(max_days: int = 90) -> None:
    keys = sorted(_STATS["daily"].keys())
    if len(keys) <= max_days:
        return
    for k in keys[:-max_days]:
        _STATS["daily"].pop(k, None)


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


def _check_and_inc_usage(api_key: str, plan: str, quotas: Dict[str, int]) -> Tuple[int, int, int]:
    """
    回傳 (used_today, remaining_today, quota)
    """
    day = _utc_day()
    quota = int(quotas.get(plan, 0))

    per_key = _usage_by_key.setdefault(api_key, {})
    used = int(per_key.get(day, 0))

    if used >= quota:
        return used, 0, quota

    used += 1
    per_key[day] = used
    remaining = max(quota - used, 0)
    return used, remaining, quota


def _mask_key(k: str) -> str:
    if len(k) <= 8:
        return "***"
    return k[:4] + "..." + k[-4:]


def _stable_anon_id(text: str) -> str:
    """
    不可逆的摘要 id（只用於辨識重複事件，不可回推出原文）
    - 加 SALT：避免有人拿字典撞 hash
    """
    salt = os.getenv("STATS_SALT", "scamshield-default-salt")
    h = hashlib.sha256((salt + "\n" + text).encode("utf-8")).hexdigest()
    return h[:12]


def _stats_add(summary: Dict[str, Any]) -> None:
    _STATS["total"] += 1

    lvl = str(summary.get("risk_level", "")).lower()
    score = int(summary.get("risk_score", 0) or 0)
    types = summary.get("scam_types", []) or []

    # overall by_level
    if lvl in _STATS["by_level"]:
        _STATS["by_level"][lvl] += 1

    # overall by_type
    for t in types:
        t = str(t)
        _STATS["by_type"][t] = int(_STATS["by_type"].get(t, 0)) + 1

    # last_50
    _STATS["last_50"].insert(0, summary)
    _STATS["last_50"] = _STATS["last_50"][:50]

    # daily
    day = _utc_day()
    d = _STATS["daily"].setdefault(day, {
        "total": 0,
        "score_sum": 0,
        "by_level": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        "by_type": {},
    })
    d["total"] += 1
    d["score_sum"] += score
    if lvl in d["by_level"]:
        d["by_level"][lvl] += 1
    for t in types:
        t = str(t)
        d["by_type"][t] = int(d["by_type"].get(t, 0)) + 1

    # hourly
    hour = _utc_hour()
    h = _STATS["hourly"].setdefault(hour, {
        "total": 0,
        "score_sum": 0,
        "by_level": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    })
    h["total"] += 1
    h["score_sum"] += score
    if lvl in h["by_level"]:
        h["by_level"][lvl] += 1

    _prune_hourly(48)
    _prune_daily(90)


def _extract_suspicious_urls_from_result(result: Dict[str, Any]) -> List[str]:
    """
    盡量從 analyze_text 的輸出裡找出可疑網址（你不一定有這個欄位，所以做保底）
    """
    urls: List[str] = []
    for key in ("suspicious_urls", "urls", "found_urls"):
        val = result.get(key)
        if isinstance(val, list):
            for u in val:
                if isinstance(u, str) and u.strip():
                    urls.append(u.strip())
    # 去重但保序
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


# =========================
# Auth dependencies
# =========================

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

    if admin_key and secrets.compare_digest(key, admin_key):
        return {"api_key": key, "plan": "enterprise", "is_admin": True, "quota": quotas.get("enterprise", 999999)}

    plan = keys.get(key)
    if not plan:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return {"api_key": key, "plan": plan, "is_admin": False, "quota": quotas.get(plan, 0)}


async def require_admin(
    authorization: Optional[str] = Header(default=None),
    x_admin_key: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """
    管理者用（給 stats / reset）
    支援：
    - Authorization: Bearer <ADMIN_KEY>
    - X-Admin-Key: <ADMIN_KEY>
    """
    admin_key = os.getenv("ADMIN_KEY", "").strip()

    key = None
    if authorization and authorization.lower().startswith("bearer "):
        key = authorization.split(" ", 1)[1].strip()
    elif x_admin_key:
        key = x_admin_key.strip()

    if not admin_key:
        raise HTTPException(status_code=500, detail="ADMIN_KEY not configured")

    if not key or not secrets.compare_digest(key, admin_key):
        raise HTTPException(status_code=401, detail="Unauthorized")

    return {"is_admin": True}


# =========================
# Models
# =========================

class AnalyzeRequest(BaseModel):
    text: str = Field(..., description="要分析的文字")
    context: Optional[Dict[str, Any]] = Field(default=None)
    allow_anon_stats: Optional[bool] = Field(default=True, description="是否允許匿名統計（不存原文）")


class TriggeredRule(BaseModel):
    name: str
    score: int
    evidence_sentences: List[str]


class SuspiciousUrl(BaseModel):
    url: str
    score: int = 0
    reason: str = ""


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
    suspicious_urls: Optional[List[SuspiciousUrl]] = None
    entities: Optional[Dict[str, Any]] = None



# =========================
# Basic routes
# =========================

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/line/webhook")
async def line_webhook(req: Request, x_line_signature: str = Header(None)):
    body = await req.json()
    events = body.get("events", [])

    for ev in events:
        if ev.get("type") != "message":
            continue

        msg = ev.get("message", {})
        if msg.get("type") != "text":
            continue

        user_text = (msg.get("text") or "").strip()
        reply_token = ev.get("replyToken")
        if not reply_token:
            continue

        try:
            result = analyze_text(user_text, context=None)
            reply = format_line_reply(result)  
        except Exception as e:
            reply = f"剛剛分析失常：{e}"

        _line_reply(reply_token, reply)

    return {"ok": True}





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
    :root{
      --bg:#0b0f14;
      --card:#101826;
      --card2:#0b1220;
      --border:#1f2a3a;
      --border2:#2a3a52;
      --txt:#e6edf3;
      --muted:rgba(230,237,243,.75);
      --green:#2ecc71;
      --yellow:#f1c40f;
      --orange:#ff8a3d;
      --red:#ff3b30;
      --accent:#00ff88;
    }
    body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans TC",sans-serif;background:var(--bg);color:var(--txt);margin:0}
    .wrap{max-width:1080px;margin:0 auto;padding:24px}
    .grid{display:grid;grid-template-columns:1.2fr .8fr;gap:16px}
    @media (max-width: 980px){ .grid{grid-template-columns:1fr} }

    .card{background:var(--card);border:1px solid var(--border);border-radius:18px;padding:18px;margin-top:16px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
    .card.soft{background:linear-gradient(180deg, rgba(16,24,38,1), rgba(11,18,32,1))}
    textarea{width:100%;min-height:180px;border-radius:14px;border:1px solid var(--border2);background:var(--card2);color:var(--txt);padding:12px;font-size:16px;resize:vertical;outline:none}
    button{border:0;border-radius:12px;padding:12px 16px;background:var(--accent);color:#04210f;font-weight:900;cursor:pointer}
    button:disabled{opacity:.55;cursor:not-allowed}
    .row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
    .pill{display:inline-flex;gap:8px;align-items:center;padding:8px 12px;border-radius:999px;border:1px solid var(--border2);background:var(--card2)}
    a{color:var(--accent);text-decoration:none}
    a:hover{text-decoration:underline}
    .small{opacity:.88;font-size:13px}
    .muted{opacity:.75}
    .hr{height:1px;background:var(--border);margin:14px 0}

    .checkbox{display:flex;gap:10px;align-items:center;user-select:none}
    .checkbox input{width:18px;height:18px}

    /* Result header */
    .resultHead{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
    .badge{
      display:inline-flex;align-items:center;gap:10px;
      padding:10px 14px;border-radius:999px;
      border:1px solid var(--border2);background:var(--card2);
      font-weight:1000
    }
    .badgeDot{width:10px;height:10px;border-radius:999px;background:#999}
    .b-low .badgeDot{background:var(--green)}
    .b-medium .badgeDot{background:var(--yellow)}
    .b-high .badgeDot{background:var(--orange)}
    .b-critical .badgeDot{background:var(--red)}

    .scoreBox{flex:1;min-width:260px}
    .scoreTop{display:flex;justify-content:space-between;align-items:baseline}
    .scoreNum{font-size:28px;font-weight:1000}
    .scoreMax{opacity:.7}
    .bar{height:12px;border-radius:999px;background:#0a0f18;border:1px solid var(--border2);overflow:hidden}
    .bar > div{height:100%;width:0%}
    .bar.low > div{background:var(--green)}
    .bar.medium > div{background:var(--yellow)}
    .bar.high > div{background:var(--orange)}
    .bar.critical > div{background:var(--red)}

    /* Tags */
    .tags{display:flex;flex-wrap:wrap;gap:8px}
    .tag{display:inline-flex;gap:6px;align-items:center;padding:7px 10px;border-radius:999px;background:var(--card2);border:1px solid var(--border2)}
    .tagIcon{opacity:.8}

    /* Sections */
    .sectionTitle{margin:0 0 8px 0;font-size:15px;opacity:.95}
    .box{background:var(--card2);border:1px solid var(--border2);border-radius:14px;padding:12px}
    pre{white-space:pre-wrap;word-break:break-word;margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}

    .twoCol{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    @media (max-width: 980px){ .twoCol{grid-template-columns:1fr} }

    .ghostBtn{background:#1f2a3a;color:var(--txt);font-weight:900}
    .copyhint{min-height:18px}

    /* Sample buttons */
    .samples{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px}
    .sampleBtn{
      border:1px solid var(--border2);background:var(--card2);color:var(--txt);
      padding:10px 12px;border-radius:12px;cursor:pointer;font-weight:900
    }
    .sampleBtn:hover{border-color:rgba(0,255,136,.45)}
  </style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ ScamShield 防詐文字分析</h1>

  <div class="card soft">
    <p>貼上你收到的訊息，按下分析。<span class="small">（上線版不會存取內容）</span></p>

    <textarea id="text" placeholder="例如：你的帳戶異常，請立即匯款並提供驗證碼，否則凍結..."></textarea>

    <div class="samples">
      <button class="sampleBtn" onclick="fillSample('kfreeze')">📵 假客服凍結帳戶</button>
      <button class="sampleBtn" onclick="fillSample('invest')">📈 投資老師帶單</button>
      <button class="sampleBtn" onclick="fillSample('ship')">📦 物流補繳關稅</button>
      <button class="sampleBtn" onclick="fillSample('borrow')">💸 熟人借錢急用</button>
    </div>

    <div class="row" style="margin-top:12px">
      <button id="btn" onclick="run()">分析</button>
      <span class="pill">⚠️ 這是輔助判斷工具，請以官方管道查證</span>
      <span class="pill">Swagger：<a href="/docs" target="_blank" rel="noreferrer">/docs</a></span>
      <span class="pill">API 文件：<a href="/api-docs" target="_blank" rel="noreferrer">/api-docs</a></span>
      <span class="pill">Stats：<a href="#" onclick="openStats();return false;">/stats-ui</a></span>
    </div>

    <div class="row" style="margin-top:10px">
      <label class="checkbox small">
        <input id="allowStats" type="checkbox" checked />
        允許匿名統計（不存原文，只記次數/等級/類型）
      </label>
      <span class="small muted">* 你不勾我就當沒看到，統計直接放生。</span>
    </div>
  </div>

  <div class="grid">
    <div class="card" id="out" style="display:none">
      <h2 style="margin:0 0 10px 0">結果</h2>

      <div class="resultHead">
        <div id="badge" class="badge b-low">
          <span class="badgeDot"></span>
          <span id="badgeText">🟢 低風險</span>
        </div>

        <div class="scoreBox">
          <div class="scoreTop">
            <div>風險分數</div>
            <div><span id="score" class="scoreNum">0</span><span class="scoreMax">/100</span></div>
          </div>
          <div id="bar" class="bar low" aria-label="score bar"><div></div></div>
          <div class="small muted" style="margin-top:6px">風險等級：<span id="level" style="font-weight:1000"></span></div>
        </div>
      </div>

      <div class="hr"></div>

      <div class="sectionTitle">詐騙類型</div>
      <div id="types" class="tags"></div>

      <div class="hr"></div>

      <div class="twoCol">
        <div>
          <div class="sectionTitle">📌 我看到的可疑點</div>
          <div class="box"><pre id="explain"></pre></div>
        </div>
        <div>
          <div class="sectionTitle">✅ 建議你現在做</div>
          <div class="box"><pre id="actions"></pre></div>
        </div>
      </div>

      <div class="hr"></div>

      <div class="sectionTitle">✍️ 可以回覆對方</div>
      <div class="row" style="margin:8px 0">
        <button class="ghostBtn" onclick="copyTemplates()">一鍵複製模板</button>
        <span class="small copyhint" id="copyhint"></span>
      </div>
      <div class="box"><pre id="templates"></pre></div>

      <details style="margin-top:12px">
        <summary class="small">查看命中規則與證據句（進階）</summary>
        <div class="hr"></div>
        <div class="box"><pre id="rules"></pre></div>
      </details>
    </div>

    <div class="card" id="urlsCard" style="display:none">
      <h2 style="margin:0 0 8px 0">🔗 可疑網址</h2>
      <div class="small muted">看到 tinyurl/bit.ly 這種短網址，先當它是詐騙，靠杯真的。</div>
      <div class="hr"></div>
      <div class="box"><pre id="urls"></pre></div>
    </div>
  </div>

  <p class="small muted" style="margin-top:14px">
    Web API: <code>POST /analyze</code>，健康檢查：<code>/health</code> ｜ Paid API: <code>POST /api/v1/analyze</code>（需要 API Key）
  </p>
</div>

<script>
let lastTemplates = "";

function openStats(){
  const key = prompt("輸入 ADMIN_KEY 才能看後台");
  if(!key) return;
  window.open("/stats-ui?k=" + encodeURIComponent(key), "_blank");
}

function fillSample(kind){
  const samples = {
    kfreeze: "【通知】你的帳戶異常，請於24小時內完成身份驗證，否則將凍結。點擊連結更新資料：https://bit.ly/xxx 並提供簡訊驗證碼。",
    invest: "老師帶單保證獲利，今天最後名額！加入群組跟單，穩賺不賠，現在入金就翻倍。",
    ship: "你有一筆包裹派送失敗/清關異常，請點擊連結補填地址並繳交關稅/運費，否則退回。",
    borrow: "我現在真的很急，可以先借我一點周轉嗎？我今天就還你，拜託了。"
  };
  document.getElementById("text").value = samples[kind] || "";
}

function levelMeta(level){
  const lv = (level || "").toLowerCase();
  if(lv === "critical") return {txt:"🔴 高度可疑", cls:"critical"};
  if(lv === "high")     return {txt:"🟠 高風險",   cls:"high"};
  if(lv === "medium")   return {txt:"🟡 中風險",   cls:"medium"};
  if(lv === "low")      return {txt:"🟢 低風險",   cls:"low"};
  return {txt:"⚪ 未知", cls:"low"};
}

function renderUrls(urls){
  // 支援 list[str] 或 list[dict{url,score,reason}]
  if(!urls || !urls.length) return "";
  return urls.map(u=>{
    if(typeof u === "string") return "• " + u;
    if(u && typeof u === "object"){
      const url = u.url || "";
      const sc  = (u.score ?? 0);
      const rs  = u.reason ? ("｜" + u.reason) : "";
      return `• ${url}（+${sc}）${rs}`;
    }
    return "• " + String(u);
  }).join("\\n");
}

async function run(){
  const btn = document.getElementById("btn");
  const text = document.getElementById("text").value.trim();
  const allow_anon_stats = document.getElementById("allowStats").checked;

  if(!text){ alert("請貼文字"); return; }

  btn.disabled = true; btn.textContent="分析中…";
  document.getElementById("copyhint").textContent = "";
  document.getElementById("urlsCard").style.display = "none";

  try{
    const res = await fetch("/analyze", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ text, allow_anon_stats })
    });

    const data = await res.json().catch(()=> ({}));
    if(!res.ok){
      alert(data.detail || ("出事，HTTP " + res.status));
      return;
    }

    // show out
    document.getElementById("out").style.display = "block";

    const score = Number(data.risk_score || 0);
    const level = (data.risk_level || "unknown").toLowerCase();

    // badge + bar
    const meta = levelMeta(level);
    document.getElementById("badgeText").textContent = meta.txt;
    const badge = document.getElementById("badge");
    badge.className = "badge b-" + meta.cls;

    document.getElementById("score").textContent = score;
    document.getElementById("level").textContent = level;

    const bar = document.getElementById("bar");
    bar.className = "bar " + meta.cls;
    bar.firstElementChild.style.width = Math.max(0, Math.min(score, 100)) + "%";

    // types
    const typesEl = document.getElementById("types");
    typesEl.innerHTML = "";
    const types = (data.scam_types || []);
    if(types.length){
      types.forEach(t=>{
        const span = document.createElement("span");
        span.className = "tag";
        span.innerHTML = `<span class="tagIcon">🏷️</span><span>${t}</span>`;
        typesEl.appendChild(span);
      });
    }else{
      const span = document.createElement("span");
      span.className = "tag";
      span.innerHTML = `<span class="tagIcon">🫥</span><span>未明確歸類（先用官方管道確認）</span>`;
      typesEl.appendChild(span);
    }

    // explain/actions/templates
    document.getElementById("explain").textContent = (data.explanation || "（沒有額外說明）");
    document.getElementById("actions").textContent =
      (data.recommended_actions || []).slice(0,6).map((x,i)=>`${i+1}. ${x}`).join("\\n") || "（暫無）";

    const tpl = (data.reply_templates || []).slice(0,6).map((x,i)=>`${i+1}. ${x}`).join("\\n");
    document.getElementById("templates").textContent = tpl || "（暫無）";
    lastTemplates = tpl;

    // rules
    document.getElementById("rules").textContent = JSON.stringify(data.triggered_rules || [], null, 2);

    // urls
    const urls = (data.suspicious_urls || []);
    if(urls.length){
      document.getElementById("urlsCard").style.display = "block";
      document.getElementById("urls").textContent = renderUrls(urls);
    }

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
    document.getElementById("copyhint").textContent = "✅ 已複製，貼去回對方就好";
  }catch(e){
    document.getElementById("copyhint").textContent = "⚠️ 無法自動複製";
  }
}
</script>
</body>
</html>
"""


# =========================
# Web analyze (IP rate limit + optional anon stats)
# =========================

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_web(body: AnalyzeRequest, req: Request):
    ip = _client_ip(req)
    if not _rate_limit_ok_ip(ip):
        return JSONResponse(status_code=429, content={"detail": "太多次（rate limit）— 請稍後再試"})

    text = (body.text or "").strip()
    if not text:
        return JSONResponse(status_code=400, content={"detail": "text 不能是空的"})
    if len(text) > MAX_TEXT_CHARS:
        return JSONResponse(status_code=400, content={"detail": f"text 太長（最多 {MAX_TEXT_CHARS} 字）"})

    try:
        result = analyze_text(text, context=body.context)

        suspicious_urls = _extract_suspicious_urls_from_result(result)
        if suspicious_urls:
            result["suspicious_urls"] = suspicious_urls

        response = {
            "request_id": secrets.token_hex(8),
            **result,
            "policy_version": POLICY_VERSION,
            "model_version": MODEL_VERSION,
        }

        if bool(body.allow_anon_stats):
            anon_id = _stable_anon_id(text)
            summary = {
                "ts_utc": _now_iso_utc(),
                "risk_level": str(response.get("risk_level", "")).lower(),
                "risk_score": int(response.get("risk_score", 0) or 0),
                "scam_types": response.get("scam_types", []) or [],
                "anon_id": anon_id,
            }
            _stats_add(summary)

        return response

    except Exception:
        return JSONResponse(status_code=500, content={"detail": "Internal error"})


# =========================
# Paid API (API key + daily quota)
# =========================

@app.get("/api/v1/usage")
async def api_usage(auth=Depends(require_api_key)):
    day = _utc_day()
    api_key = auth["api_key"]
    plan = auth["plan"]
    quotas = _parse_plan_quotas()
    quota = int(quotas.get(plan, 0))
    used = int(_usage_by_key.get(api_key, {}).get(day, 0))
    remaining = max(quota - used, 0)

    return {
        "day_utc": day,
        "plan": plan,
        "quota": quota,
        "used": used,
        "remaining": remaining,
        "key": _mask_key(api_key),
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
    used, remaining, quota = _check_and_inc_usage(auth["api_key"], auth["plan"], quotas)
    if used > quota:
        return JSONResponse(status_code=429, content={"detail": "API quota exceeded", "plan": auth["plan"], "day_utc": _utc_day()})

    try:
        result = analyze_text(text, context=body.context)
        suspicious_urls = _extract_suspicious_urls_from_result(result)
        if suspicious_urls:
            result["suspicious_urls"] = suspicious_urls

        return {
            "request_id": secrets.token_hex(8),
            **result,
            "policy_version": POLICY_VERSION,
            "model_version": MODEL_VERSION,
        }
    except Exception:
        return JSONResponse(status_code=500, content={"detail": "Internal error"})


# =========================
# Stats (admin only)
# =========================

@app.get("/stats")
async def stats_json(_=Depends(require_admin)):
    total = int(_STATS["total"])

    score_sum_all = 0
    for _, d in (_STATS.get("daily") or {}).items():
        score_sum_all += int(d.get("score_sum", 0) or 0)
    avg_score = (score_sum_all / total) if total > 0 else 0.0

    bt = _STATS.get("by_type") or {}
    top_types = sorted(bt.items(), key=lambda x: x[1], reverse=True)[:10]

    hourly_keys = sorted((_STATS.get("hourly") or {}).keys())[-24:]
    hourly_24h = [{"hour": k, **_STATS["hourly"][k]} for k in hourly_keys]

    daily_keys = sorted((_STATS.get("daily") or {}).keys())[-7:]
    daily_7d = [{"day": k, **_STATS["daily"][k]} for k in daily_keys]

    return {
        "since_epoch": _STATS["since_epoch"],
        "total": total,
        "avg_score": avg_score,
        "by_level": _STATS["by_level"],
        "by_type": _STATS["by_type"],
        "top_types": top_types,
        "last_50": _STATS["last_50"],
        "hourly_24h": hourly_24h,
        "daily_7d": daily_7d,
    }


@app.post("/admin/reset-stats")
async def reset_stats(_=Depends(require_admin)):
    _STATS["since_epoch"] = int(time.time())
    _STATS["total"] = 0
    _STATS["by_level"] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    _STATS["by_type"] = {}
    _STATS["last_50"] = []
    _STATS["daily"] = {}
    _STATS["hourly"] = {}
    return {"ok": True}


@app.get("/stats-ui", response_class=HTMLResponse)
async def stats_ui(req: Request):
    admin_key = os.getenv("ADMIN_KEY", "").strip()
    k = (req.query_params.get("k") or "").strip()
    if not admin_key or not k or not secrets.compare_digest(k, admin_key):
        return HTMLResponse(status_code=401, content="<pre>Unauthorized. 你沒帶 ADMIN_KEY </pre>")



    # ✅ 不用 f-string，避免 JS template literal 的 ${...} 讓 Python 爆炸
    return """
<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>ScamShield 匿名統計</title>
  <style>
    :root{
      --bg:#0b0f14; --card:#101826; --line:#1f2a3a; --soft:#0b1220;
      --txt:#e6edf3; --muted:rgba(230,237,243,.75); --acc:#00ff88;
      --danger:#ff3b30; --r:16px;
    }
    body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans TC",sans-serif;background:var(--bg);color:var(--txt);margin:0}
    .wrap{max-width:1180px;margin:0 auto;padding:24px}
    .topbar{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;flex-wrap:wrap}
    h1{margin:0}
    .muted{color:var(--muted);font-size:13px}
    .grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-top:16px}
    @media (max-width: 980px){ .grid{grid-template-columns:1fr} }
    .card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:16px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
    .big{font-size:44px;font-weight:1000;line-height:1}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .pill{display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border-radius:999px;border:1px solid #2a3a52;background:var(--soft);font-size:13px}
    .btn{border:0;border-radius:12px;padding:10px 14px;background:#1f2a3a;color:var(--txt);font-weight:900;cursor:pointer}
    .btn:hover{filter:brightness(1.1)}
    .danger{background:var(--danger);color:#fff}
    .hr{height:1px;background:var(--line);margin:12px 0}
    table{width:100%;border-collapse:collapse;margin-top:10px}
    th,td{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:top}
    th{color:var(--muted);font-weight:700}
    .bar{height:10px;border-radius:999px;background:#0f1726;border:1px solid #20304a;overflow:hidden}
    .bar > i{display:block;height:100%;background:var(--acc)}
    .tiny{font-size:12px;color:var(--muted)}
    .kpi{display:flex;justify-content:space-between;align-items:flex-end;gap:10px}
    .kpi .label{color:var(--muted);font-size:13px}
    .two{display:grid;grid-template-columns:1.2fr .8fr;gap:14px;margin-top:14px}
    @media (max-width: 980px){ .two{grid-template-columns:1fr} }
    input,select{background:var(--soft);border:1px solid #2a3a52;border-radius:12px;color:var(--txt);padding:10px 12px;outline:none}
  </style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div>
      <h1>📊 ScamShield 匿名統計</h1>
      <div class="muted">不包含任何原文內容（只記次數、等級、類型、匿名指紋）。</div>
    </div>
    <div class="row">
      <button class="btn" onclick="reload()">刷新</button>
      <button class="btn danger" onclick="resetStats()">重置統計</button>
      <button class="btn" onclick="window.location='/docs'">Swagger /docs</button>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="kpi">
        <div>
          <div class="label">總分析次數</div>
          <div class="big" id="total">-</div>
        </div>
        <div class="tiny" id="since">-</div>
      </div>
      <div class="hr"></div>
      <div class="row">
        <span class="pill">平均風險分數：<b id="avg">-</b></span>
      </div>
    </div>

    <div class="card">
      <div class="label muted">等級分佈（占比）</div>
      <div style="margin-top:10px" id="levels"></div>
    </div>

    <div class="card">
      <div class="label muted">Top 詐騙類型</div>
      <div style="margin-top:10px" id="types"></div>
    </div>
  </div>

  <div class="two">
    <div class="card">
      <div class="label muted">近 24 小時趨勢（UTC 每小時）</div>
      <div style="margin-top:10px" id="h24"></div>
      <div class="tiny">* 這是每小時分析次數</div>
    </div>

    <div class="card">
      <div class="label muted">近 7 天趨勢（UTC 每日）</div>
      <div style="margin-top:10px" id="d7"></div>
      <div class="tiny">* UTC 正常反應</div>
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
      <h2 style="margin:0">最近 50 次（匿名摘要）</h2>
      <div class="row">
        <select id="filterLevel" onchange="renderRows()">
          <option value="">全部等級</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
        </select>
        <input id="filterText" placeholder="搜尋類型 / 指紋" oninput="renderRows()" />
      </div>
    </div>

    <table>
      <thead>
        <tr>
          <th style="width:220px">時間(UTC)</th>
          <th style="width:110px">等級</th>
          <th style="width:90px">分數</th>
          <th>類型</th>
          <th style="width:170px">匿名指紋</th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</div>

<script>
const adminKey = new URLSearchParams(location.search).get("k");
sessionStorage.setItem("scamshield_admin_key", adminKey);

let last50 = [];

function pill(s){ return `<span class="pill">${s}</span>`; }
function fmtEpoch(e){
  const d = new Date(e * 1000);
  return d.toISOString().replace(".000Z","Z");
}

async function fetchStats(){
  const k = sessionStorage.getItem("scamshield_admin_key");
  const res = await fetch("/stats", { headers: { "X-Admin-Key": k } });
  const data = await res.json().catch(()=>({}));
  if(!res.ok) throw new Error(data.detail || ("HTTP " + res.status));
  return data;
}

function barLine(label, value, max){
  const pct = max ? Math.round((value/max)*100) : 0;
  return `
    <div style="display:grid;grid-template-columns:120px 1fr 70px;gap:10px;align-items:center;margin:8px 0">
      <div class="tiny">${label}</div>
      <div class="bar"><i style="width:${pct}%;"></i></div>
      <div class="tiny" style="text-align:right">${value}</div>
    </div>
  `;
}

function levelRow(name, count, total){
  const pct = total ? Math.round((count/total)*100) : 0;
  return `
    <div style="display:grid;grid-template-columns:100px 1fr 90px;gap:10px;align-items:center;margin:8px 0">
      <div>${pill(name)}</div>
      <div class="bar"><i style="width:${pct}%;"></i></div>
      <div class="tiny" style="text-align:right">${count} (${pct}%)</div>
    </div>
  `;
}

function renderRows(){
  const lv = document.getElementById("filterLevel").value.trim().toLowerCase();
  const q = document.getElementById("filterText").value.trim().toLowerCase();

  const rows = (last50 || []).filter(r => {
    if(lv && (String(r.risk_level||"").toLowerCase() !== lv)) return false;
    if(!q) return true;
    const types = (r.scam_types||[]).join(" ").toLowerCase();
    const id = String(r.anon_id||"").toLowerCase();
    return types.includes(q) || id.includes(q);
  });

  const tbody = document.getElementById("rows");
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td>${r.ts_utc || "-"}</td>
      <td>${pill(r.risk_level || "-")}</td>
      <td>${r.risk_score ?? "-"}</td>
      <td>${(r.scam_types || []).map(pill).join(" ") || "<span class='muted'>-</span>"}</td>
      <td><span class="pill">${r.anon_id || "-"}</span></td>
    </tr>
  `).join("") || `<tr><td colspan="5" class="muted">（沒有符合條件的紀錄）</td></tr>`;
}

async function reload(){
  try{
    const data = await fetchStats();
    const total = Number(data.total || 0);

    document.getElementById("total").textContent = total;
    document.getElementById("since").textContent = "統計起算：" + fmtEpoch(data.since_epoch || 0);
    document.getElementById("avg").textContent = (Number(data.avg_score || 0)).toFixed(2);

    const by = data.by_level || {};
    const order = ["critical","high","medium","low"];
    document.getElementById("levels").innerHTML = order
      .map(k => levelRow(k, Number(by[k]||0), total))
      .join("") || "<span class='muted'>（還沒有資料）</span>";

    const top = data.top_types || [];
    document.getElementById("types").innerHTML = top.length
      ? top.map(([k,v]) => `${pill(k)} <span class="tiny">${v}</span>`).join("<br/>")
      : "<span class='muted'>（還沒有資料）</span>";

    const h24 = data.hourly_24h || [];
    const maxH = Math.max(1, ...h24.map(x => Number(x.total||0)));
    document.getElementById("h24").innerHTML = h24.length
      ? h24.map(x => barLine(x.hour, Number(x.total||0), maxH)).join("")
      : "<span class='muted'>（還沒有資料）</span>";

    const d7 = data.daily_7d || [];
    const maxD = Math.max(1, ...d7.map(x => Number(x.total||0)));
    document.getElementById("d7").innerHTML = d7.length
      ? d7.map(x => barLine(x.day, Number(x.total||0), maxD)).join("")
      : "<span class='muted'>（還沒有資料）</span>";

    last50 = data.last_50 || [];
    renderRows();
  }catch(e){
    document.body.innerHTML = `<pre>Stats UI 出事了：${e}\n（你是不是 ADMIN_KEY 打錯了，或 /stats 掛了）</pre>`;
  }
}

async function resetStats(){
  if(!confirm("確定要清空統計？")) return;
  const k = sessionStorage.getItem("scamshield_admin_key");
  const res = await fetch("/admin/reset-stats", { method: "POST", headers: { "X-Admin-Key": k } });
  const data = await res.json().catch(()=>({}));
  if(!res.ok){ alert(data.detail || ("HTTP " + res.status)); return; }
  await reload();
}

reload();
</script>
</body>
</html>
"""

@app.get("/api-docs", response_class=HTMLResponse)
async def api_docs():
    return """
<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>ScamShield 外部 API 文件</title>
  <style>
    :root{
      --bg:#0b0f14; --card:#101826; --line:#1f2a3a; --soft:#0b1220;
      --txt:#e6edf3; --muted:rgba(230,237,243,.75); --acc:#00ff88;
      --danger:#ff3b30; --r:16px;
    }
    body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans TC",sans-serif;background:var(--bg);color:var(--txt);margin:0}
    .wrap{max-width:980px;margin:0 auto;padding:24px}
    .card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:16px;margin-top:14px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
    h1{margin:0 0 8px 0}
    h2{margin:0 0 10px 0}
    p{color:var(--muted);line-height:1.6;margin:8px 0}
    a{color:var(--acc)}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .pill{display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border-radius:999px;border:1px solid #2a3a52;background:var(--soft);font-size:13px}
    .hr{height:1px;background:var(--line);margin:12px 0}
    code, pre{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
    pre{white-space:pre;overflow:auto;background:var(--soft);border:1px solid #2a3a52;border-radius:12px;padding:12px;margin:0}
    table{width:100%;border-collapse:collapse;margin-top:10px}
    th,td{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:top}
    th{color:var(--muted);font-weight:700}
    .muted{color:var(--muted)}
    .warn{color:#ffd166}
  </style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ ScamShield 外部 API 文件</h1>
  <p>給外部系統串接用的防詐文字分析 API。<span class="muted">（不儲存原文，放心啦）</span></p>

  <div class="row">
    <span class="pill">Base URL：<code id="base">-</code></span>
    <a class="pill" href="/docs" target="_blank" rel="noreferrer">Swagger：/docs</a>
    <a class="pill" href="/openapi.json" target="_blank" rel="noreferrer">OpenAPI：/openapi.json</a>
    <a class="pill" href="/" target="_blank" rel="noreferrer">回首頁</a>
  </div>

  <div class="card">
    <h2>1) 驗證方式（API Key）</h2>
    <p>支援兩種帶法（擇一即可）：</p>
    <p class="muted">A. <code>X-API-Key: &lt;key&gt;</code></p>
    <p class="muted">B. <code>Authorization: Bearer &lt;key&gt;</code></p>
    <div class="hr"></div>
    <p class="warn">⚠️ 不要把 Key 寫死在前端。</p>
  </div>

  <div class="card">
    <h2>2) 端點一覽</h2>
    <table>
      <thead>
        <tr><th>方法</th><th>路徑</th><th>說明</th></tr>
      </thead>
      <tbody>
        <tr><td>POST</td><td><code>/api/v1/analyze</code></td><td>分析文字內容（需要 API Key）</td></tr>
        <tr><td>GET</td><td><code>/api/v1/usage</code></td><td>查詢今日用量 / 剩餘額度（需要 API Key）</td></tr>
        <tr><td>POST</td><td><code>/analyze</code></td><td>Web UI 使用（依 IP rate limit）</td></tr>
        <tr><td>GET</td><td><code>/health</code></td><td>健康檢查</td></tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>3) POST /api/v1/analyze</h2>
    <p class="muted">Request JSON：</p>
<pre><code>{
  "text": "要分析的文字（必填）",
  "context": { "可選：額外上下文" },
  "allow_anon_stats": true
}</code></pre>
    <div class="hr"></div>
    <p class="muted">curl 範例（X-API-Key）：</p>
<pre><code>curl -X POST "{BASE}/api/v1/analyze" \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"text":"你的帳戶異常，請立即匯款並提供驗證碼..."}'</code></pre>
    <div class="hr"></div>
    <p class="muted">curl 範例（Bearer）：</p>
<pre><code>curl -X POST "{BASE}/api/v1/analyze" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"text":"你已中獎，請點此連結領取..."}'</code></pre>
  </div>

  <div class="card">
    <h2>4) Response 欄位（重要）</h2>
    <table>
      <thead>
        <tr><th>欄位</th><th>型別</th><th>說明</th></tr>
      </thead>
      <tbody>
        <tr><td><code>risk_score</code></td><td>int</td><td>0~100，越高越危險</td></tr>
        <tr><td><code>risk_level</code></td><td>string</td><td><code>low / medium / high / critical</code></td></tr>
        <tr><td><code>scam_types</code></td><td>string[]</td><td>詐騙類型（可能為空）</td></tr>
        <tr><td><code>triggered_rules</code></td><td>object[]</td><td>命中規則與證據句（進階）</td></tr>
        <tr><td><code>explanation</code></td><td>string</td><td>簡短原因說明（給人看）</td></tr>
        <tr><td><code>recommended_actions</code></td><td>string[]</td><td>建議下一步怎麼做</td></tr>
        <tr><td><code>reply_templates</code></td><td>string[]</td><td>可複製回覆模板</td></tr>
        <tr><td><code>suspicious_urls</code></td><td>string[]?</td><td>可疑網址（如果有抓到）</td></tr>
        <tr><td><code>policy_version</code></td><td>string</td><td>規則版本</td></tr>
        <tr><td><code>model_version</code></td><td>string</td><td>引擎版本</td></tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>5) 常見錯誤（HTTP）</h2>
    <table>
      <thead>
        <tr><th>HTTP</th><th>原因</th><th>怎麼辦</th></tr>
      </thead>
      <tbody>
        <tr><td>400</td><td>text 空或超長</td><td>檢查輸入文字</td></tr>
        <tr><td>401</td><td>Missing/Invalid API key</td><td>確認 header 帶對</td></tr>
        <tr><td>429</td><td>Quota exceeded / rate limit</td><td>等待或升級配額</td></tr>
        <tr><td>500</td><td>Internal error</td><td>稍後重試；必要時回報</td></tr>
      </tbody>
    </table>
    <p class="muted">備註：你也可以導到 <code>/api/v1/usage</code> 讓客戶自己看剩多少。</p>
  </div>

  <div class="card">
    <h2>6) 限制與隱私</h2>
    <p class="muted">
      • 最大文字長度：依伺服器設定（你目前 <code>MAX_TEXT_CHARS</code>）。<br/>
      • 不儲存原文：匿名統計（若啟用）也只有「不可逆指紋 + 類型統計」。<br/>
      • 這是輔助判斷工具：最終仍建議用官方管道查證。
    </p>
  </div>

  <p class="muted" style="margin-top:14px">© ScamShield — 別被詐騙搞到血壓上來，靠杯。</p>
</div>

<script>
const base = location.origin;
document.getElementById("base").textContent = base;
document.body.innerHTML = document.body.innerHTML.replaceAll("{BASE}", base);
</script>
</body>
</html>
"""