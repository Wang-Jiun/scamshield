from __future__ import annotations

import json
import os
import time
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request, Header, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from scamshield import analyze_text

app = FastAPI(title="ScamShield Web", version="1.6.0")

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
    # e.g. "2026-01-11 05:00"
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:00")


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _prune_hourly(max_hours: int = 48) -> None:
    hourly = _STATS.get("hourly") or {}
    keys = sorted(hourly.keys())
    if len(keys) <= max_hours:
        return
    for k in keys[:-max_hours]:
        hourly.pop(k, None)


def _prune_daily(max_days: int = 90) -> None:
    daily = _STATS.get("daily") or {}
    keys = sorted(daily.keys())
    if len(keys) <= max_days:
        return
    for k in keys[:-max_days]:
        daily.pop(k, None)


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
    suspicious_urls: Optional[List[str]] = None
    entities: Optional[Dict[str, Any]] = None


# =========================
# Basic routes
# =========================

@app.get("/health")
def health():
    return {"ok": True}


# 你的 home() / analyze_web() / paid API 都照你原本的放著（略）
# （你已經寫好了，我這裡不重複貼，避免你複製到手軟）


# =========================
# Stats (admin only)
# =========================

@app.get("/stats")
async def stats_json(_=Depends(require_admin)):
    total = int(_STATS.get("total", 0) or 0)

    # avg_score：用 daily 的 total+score_sum 算「整體平均」（穩）
    daily = _STATS.get("daily") or {}
    total2 = 0
    score_sum2 = 0
    for _, d in daily.items():
        total2 += int(d.get("total", 0) or 0)
        score_sum2 += int(d.get("score_sum", 0) or 0)

    if total2 > 0:
        avg_score = score_sum2 / total2
    else:
        # fallback：沒 daily 的時候用 last_50 算
        last_50 = _STATS.get("last_50") or []
        scores = [int(x.get("risk_score", 0) or 0) for x in last_50 if isinstance(x, dict)]
        avg_score = (sum(scores) / len(scores)) if scores else 0.0

    bt = _STATS.get("by_type") or {}
    top_types = sorted(bt.items(), key=lambda x: int(x[1]), reverse=True)[:10]

    # 近 24 小時：固定回傳 24 個 hour（補 0）
    hourly = _STATS.get("hourly") or {}
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    hourly_24h = []
    for i in range(24):
        dt = now - timedelta(hours=23 - i)
        k = dt.strftime("%Y-%m-%d %H:00")
        rec = hourly.get(k) or {"total": 0, "score_sum": 0, "by_level": {"low": 0, "medium": 0, "high": 0, "critical": 0}}
        hourly_24h.append({
            "hour": k,
            "total": int(rec.get("total", 0) or 0),
        })

    # 近 7 天：固定回傳 7 個 day（補 0）
    daily_7d = []
    for i in range(7):
        dt = now.date() - timedelta(days=6 - i)
        k = dt.strftime("%Y-%m-%d")
        rec = daily.get(k) or {"total": 0, "score_sum": 0, "by_level": {"low": 0, "medium": 0, "high": 0, "critical": 0}, "by_type": {}}
        daily_7d.append({
            "day": k,
            "total": int(rec.get("total", 0) or 0),
        })

    return {
        "since_epoch": int(_STATS.get("since_epoch", int(time.time()))),
        "total": total,
        "avg_score": float(avg_score),
        "by_level": _STATS.get("by_level") or {"low": 0, "medium": 0, "high": 0, "critical": 0},
        "by_type": _STATS.get("by_type") or {},
        "top_types": top_types,
        "last_50": _STATS.get("last_50") or [],
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


# =========================
# Stats UI（你貼的那份 그대로，OK）
# =========================

@app.get("/stats-ui", response_class=HTMLResponse)
async def stats_ui(req: Request):
    admin_key = os.getenv("ADMIN_KEY", "").strip()
    k = (req.query_params.get("k") or "").strip()
    if not admin_key or not k or not secrets.compare_digest(k, admin_key):
        return HTMLResponse(status_code=401, content="<pre>Unauthorized. 你沒帶 ADMIN_KEY </pre>")

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
      <div class="tiny">* 這是每小時分析次數，不是股價圖，靠杯別緊張 😆</div>
    </div>

    <div class="card">
      <div class="label muted">近 7 天趨勢（UTC 每日）</div>
      <div style="margin-top:10px" id="d7"></div>
      <div class="tiny">* UTC 會讓你覺得時間怪怪的，正常啦。</div>
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
  if(!confirm("確定要清空統計？你按下去就真的歸零，別等下又靠杯我沒提醒你 🤣")) return;
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
