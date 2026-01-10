from __future__ import annotations

import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from scamshield import analyze_text

app = FastAPI(title="ScamShield Web", version="1.3.0")

MAX_TEXT_CHARS = 5000
RATE_LIMIT_PER_MIN = 30

_rate: Dict[str, list] = {}

# =========================
# 匿名統計（不存原文）
# =========================
_STATS: Dict[str, Any] = {
    "since_epoch": int(time.time()),
    "total": 0,
    "by_level": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    "by_type": {},  # scam_type -> count
    "last_50": [],  # 最近 50 次（只記匿名摘要）
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


def _anon_fingerprint(text: str) -> str:
    """
    只用來做匿名去重/辨識，不可逆（不回推出原文）。
    """
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return h[:12]


def _stats_add(result: Dict[str, Any], text: str) -> None:
    """
    寫入匿名統計：只存風險等級、類型、時間、匿名指紋，不存原文。
    """
    level = (result.get("risk_level") or "low").lower()
    if level not in _STATS["by_level"]:
        _STATS["by_level"][level] = 0

    _STATS["total"] += 1
    _STATS["by_level"][level] += 1

    for t in (result.get("scam_types") or []):
        _STATS["by_type"][t] = _STATS["by_type"].get(t, 0) + 1

    item = {
        "ts": int(time.time()),
        "level": level,
        "score": int(result.get("risk_score") or 0),
        "types": list(result.get("scam_types") or []),
        "fp": _anon_fingerprint(text),
    }
    _STATS["last_50"].append(item)
    if len(_STATS["last_50"]) > 50:
        _STATS["last_50"] = _STATS["last_50"][-50:]


@app.get("/health")
def health():
    return {"ok": True}


class AnalyzeRequest(BaseModel):
    text: str = Field(..., description="要分析的文字")
    context: Optional[Dict[str, Any]] = Field(default=None)
    # 是否允許匿名統計（預設 True：你也可以改成 False）
    allow_anon_stats: bool = Field(default=True, description="允許匿名統計（不存原文）")


class TriggeredRule(BaseModel):
    name: str
    score: int
    evidence_sentences: List[str]


class AnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    scam_types: List[str] = []
    triggered_rules: List[TriggeredRule]
    explanation: str
    recommended_actions: List[str]
    reply_templates: List[str]

    # Lv3+ 可選欄位（你現在若沒有也沒關係）
    stage: Optional[str] = None
    suspicious_urls: Optional[List[str]] = None


class ReportRequest(BaseModel):
    """
    報告生成：只送分析結果（不送原文）
    """
    analyzed: AnalyzeResponse
    # 可選：使用者自己要不要放「原文摘要」(預設不放，避免敏感)
    include_preview: bool = False
    preview_text: Optional[str] = None  # 若 include_preview=True 才會用（前端自己決定要不要帶）


def _lvl_class(level: str) -> str:
    lv = (level or "").lower()
    if lv in ("low", "medium", "high", "critical"):
        return lv
    return "low"


def _render_report_html(a: AnalyzeResponse, include_preview: bool, preview_text: Optional[str]) -> str:
    now = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S (GMT+8)")
    lvl = _lvl_class(a.risk_level)
    types = a.scam_types or []
    urls = a.suspicious_urls or []

    def esc(s: str) -> str:
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    types_html = "".join([f"<span class='tag'>{esc(t)}</span>" for t in types]) or "<span class='muted'>（未判定明顯類型）</span>"
    urls_html = "".join([f"<li><code>{esc(u)}</code></li>" for u in urls]) or "<li class='muted'>（未偵測到明顯可疑網址）</li>"

    actions = "\n".join([f"• {x}" for x in (a.recommended_actions or [])])
    templates = "\n".join([f"{i+1}. {x}" for i, x in enumerate(a.reply_templates or [])])

    rules_json = esc(str([r.dict() for r in (a.triggered_rules or [])]))

    preview_block = ""
    if include_preview and preview_text:
        preview_block = f"""
        <div class="card">
          <h2>原文預覽（可選）</h2>
          <pre>{esc(preview_text)}</pre>
          <p class="muted">⚠️ 這段是你自己選擇加入的預覽，若要分享給別人，記得先遮掉個資。</p>
        </div>
        """

    stage_html = ""
    if a.stage:
        stage_html = f"<div class='row'><div>流程階段：<span class='tag'>{esc(a.stage)}</span></div></div>"

    return f"""<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>ScamShield 完整報告</title>
  <style>
    body{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans TC",sans-serif;background:#0b0f14;color:#e6edf3;margin:0}}
    .wrap{{max-width:980px;margin:0 auto;padding:28px}}
    .top{{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-end}}
    h1{{margin:0}}
    .muted{{opacity:.75}}
    .card{{background:#101826;border:1px solid #1f2a3a;border-radius:16px;padding:18px;margin-top:16px;box-shadow:0 10px 30px rgba(0,0,0,.25)}}
    .row{{display:flex;gap:14px;flex-wrap:wrap;align-items:center}}
    .tag{{display:inline-block;margin:4px 6px 0 0;padding:6px 10px;border-radius:999px;background:#0b1220;border:1px solid #2a3a52}}
    pre{{white-space:pre-wrap;word-break:break-word;background:#0b1220;border:1px solid #2a3a52;border-radius:12px;padding:12px}}
    .lvl{{font-weight:1000}}
    .low{{color:#2ecc71}} .medium{{color:#f1c40f}} .high{{color:#e74c3c}} .critical{{color:#ff3b30}}
    ul{{margin:8px 0 0 18px}}
    code{{background:#0b1220;border:1px solid #2a3a52;border-radius:8px;padding:2px 6px}}
    @media print {{
      .no-print{{display:none !important}}
      body{{background:white;color:black}}
      .card{{box-shadow:none}}
      pre, code{{border:1px solid #ddd}}
    }}
  </style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div>
      <h1>🛡️ ScamShield 防詐分析－完整報告</h1>
      <div class="muted">生成時間：{esc(now)}</div>
    </div>
    <div class="no-print">
      <button onclick="window.print()" style="border:0;border-radius:12px;padding:10px 14px;background:#00ff88;color:#04210f;font-weight:900;cursor:pointer">列印 / 存成 PDF</button>
    </div>
  </div>

  <div class="card">
    <h2>判定摘要</h2>
    <div class="row">
      <div>風險分數：<span class="lvl">{int(a.risk_score or 0)}</span></div>
      <div>風險等級：<span class="lvl {lvl}">{esc(a.risk_level)}</span></div>
    </div>
    {stage_html}

    <h3 style="margin-top:12px">詐騙類型</h3>
    <div>{types_html}</div>

    <h3 style="margin-top:12px">簡短說明</h3>
    <pre>{esc(a.explanation or "")}</pre>
  </div>

  <div class="card">
    <h2>建議行動</h2>
    <pre>{esc(actions)}</pre>
  </div>

  <div class="card">
    <h2>可疑網址（請先不要點）</h2>
    <ul>{urls_html}</ul>
    <p class="muted">小提醒：短網址（tinyurl/bit.ly 等）很常被拿來釣魚，別手癢去點，靠杯。</p>
  </div>

  <div class="card">
    <h2>可直接複製回覆模板</h2>
    <pre>{esc(templates)}</pre>
  </div>

  {preview_block}

  <div class="card">
    <h2>命中規則與證據（進階）</h2>
    <pre>{rules_json}</pre>
  </div>

  <p class="muted">本報告為輔助判斷，請以官方管道查證；若涉及金流或個資，建議聯繫 165 或相關平台客服。</p>
</div>
</body>
</html>
"""


@app.get("/stats")
def stats():
    """
    匿名統計（不含任何原文內容）
    """
    return {
        "since_epoch": _STATS["since_epoch"],
        "total": _STATS["total"],
        "by_level": _STATS["by_level"],
        "by_type": _STATS["by_type"],
        "last_50": _STATS["last_50"],
    }


@app.get("/stats-ui", response_class=HTMLResponse)
def stats_ui():
    """
    儀表板（純前端用 /stats 取資料）
    """
    return """<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>ScamShield Stats</title>
  <style>
    body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans TC",sans-serif;background:#0b0f14;color:#e6edf3;margin:0}
    .wrap{max-width:1100px;margin:0 auto;padding:24px}
    .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}
    .card{grid-column:span 12;background:#101826;border:1px solid #1f2a3a;border-radius:16px;padding:16px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
    @media (min-width:900px){ .c4{grid-column:span 4} .c6{grid-column:span 6} .c12{grid-column:span 12} }
    h1{margin:0 0 6px 0}
    .muted{opacity:.75}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .pill{display:inline-block;padding:6px 10px;border-radius:999px;border:1px solid #2a3a52;background:#0b1220}
    .bar{height:12px;border-radius:999px;background:#0b1220;border:1px solid #2a3a52;overflow:hidden}
    .fill{height:100%;background:#00ff88}
    table{width:100%;border-collapse:collapse}
    th,td{border-bottom:1px solid #1f2a3a;padding:10px;text-align:left;font-size:14px}
    code{background:#0b1220;border:1px solid #2a3a52;border-radius:8px;padding:2px 6px}
    a{color:#00ff88}
  </style>
</head>
<body>
<div class="wrap">
  <div class="row" style="justify-content:space-between">
    <div>
      <h1>📊 ScamShield 匿名統計</h1>
      <div class="muted">不包含任何原文內容（只記次數、等級、類型）</div>
    </div>
    <div class="row">
      <a class="pill" href="/" target="_blank" rel="noreferrer">回首頁</a>
      <a class="pill" href="/docs" target="_blank" rel="noreferrer">Swagger /docs</a>
      <button class="pill" onclick="load()" style="cursor:pointer;border:1px solid #2a3a52">重新整理</button>
    </div>
  </div>

  <div class="grid" style="margin-top:14px">
    <div class="card c4">
      <h3 style="margin:0 0 10px 0">總分析次數</h3>
      <div style="font-size:34px;font-weight:900" id="total">-</div>
      <div class="muted" id="since">-</div>
    </div>

    <div class="card c4">
      <h3 style="margin:0 0 10px 0">等級分佈</h3>
      <div id="levels"></div>
    </div>

    <div class="card c4">
      <h3 style="margin:0 0 10px 0">Top 詐騙類型</h3>
      <div id="types"></div>
    </div>

    <div class="card c12">
      <h3 style="margin:0 0 10px 0">最近 50 次（匿名摘要）</h3>
      <table>
        <thead>
          <tr><th>時間</th><th>等級</th><th>分數</th><th>類型</th><th>匿名指紋</th></tr>
        </thead>
        <tbody id="last"></tbody>
      </table>
      <div class="muted" style="margin-top:8px">匿名指紋是不可逆 hash 的前 12 碼，用來辨識重複事件，不會回推出原文。</div>
    </div>
  </div>
</div>

<script>
function fmtTs(ts){
  const d = new Date(ts*1000);
  return d.toLocaleString("zh-TW", { hour12:false });
}

function pct(n, total){
  if(!total) return 0;
  return Math.round((n/total)*100);
}

async function load(){
  const res = await fetch("/stats");
  const s = await res.json();

  document.getElementById("total").textContent = s.total ?? 0;

  const since = new Date((s.since_epoch||0)*1000).toLocaleString("zh-TW", {hour12:false});
  document.getElementById("since").textContent = "統計起算：" + since;

  // levels
  const lv = s.by_level || {};
  const total = s.total || 0;
  const order = ["critical","high","medium","low"];
  const wrap = document.getElementById("levels");
  wrap.innerHTML = "";
  order.forEach(k=>{
    const n = lv[k] || 0;
    const p = pct(n,total);
    const div = document.createElement("div");
    div.style.marginBottom="10px";
    div.innerHTML = `
      <div class="row" style="justify-content:space-between">
        <span class="pill">${k}</span>
        <span class="muted">${n}（${p}%）</span>
      </div>
      <div class="bar"><div class="fill" style="width:${p}%;"></div></div>
    `;
    wrap.appendChild(div);
  });

  // types top 8
  const bt = s.by_type || {};
  const items = Object.entries(bt).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const typesEl = document.getElementById("types");
  typesEl.innerHTML = items.length ? "" : "<span class='muted'>（目前還沒有足夠資料）</span>";
  items.forEach(([name,n])=>{
    const div = document.createElement("div");
    div.className = "row";
    div.style.justifyContent="space-between";
    div.innerHTML = `<span class="pill">${name}</span><span class="muted">${n}</span>`;
    typesEl.appendChild(div);
  });

  // last 50
  const last = (s.last_50 || []).slice().reverse();
  const tbody = document.getElementById("last");
  tbody.innerHTML = "";
  last.forEach(x=>{
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${fmtTs(x.ts)}</td>
      <td><code>${x.level}</code></td>
      <td>${x.score}</td>
      <td>${(x.types||[]).join(" / ") || "-"}</td>
      <td><code>${x.fp}</code></td>
    `;
    tbody.appendChild(tr);
  });
}

load();
</script>
</body>
</html>
"""


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
    .toggle{display:flex;gap:8px;align-items:center}
    input[type="checkbox"]{width:18px;height:18px}
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
      <span class="pill">Stats：<a href="/stats-ui" target="_blank" rel="noreferrer">/stats-ui</a></span>
    </div>

    <div class="row" style="margin-top:10px">
      <div class="toggle">
        <input id="anon" type="checkbox" checked />
        <label for="anon" class="small">允許匿名統計（不存原文，只記次數/等級/類型）</label>
      </div>
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

    <h3>可疑網址（請先不要點）</h3>
    <pre id="urls"></pre>

    <h3>可直接複製回覆模板</h3>
    <div class="row" style="margin:8px 0">
      <button class="copy" onclick="copyTemplates()">一鍵複製模板</button>
      <button class="copy" onclick="downloadReport()">一鍵下載完整報告</button>
      <span class="small" id="copyhint"></span>
    </div>
    <pre id="templates"></pre>

    <details style="margin-top:10px">
      <summary>查看命中規則與證據句（進階）</summary>
      <pre id="rules"></pre>
    </details>
  </div>

  <p class="small">API: <code>POST /analyze</code>，健康檢查：<code>/health</code></p>
</div>

<script>
let lastTemplates = "";
let lastAnalyzed = null;

async function run(){
  const btn = document.getElementById("btn");
  const text = document.getElementById("text").value.trim();
  if(!text){ alert("先貼文字"); return; }

  btn.disabled = true; btn.textContent="分析中…";
  document.getElementById("copyhint").textContent = "";
  try{
    const allowAnon = document.getElementById("anon").checked;

    const res = await fetch("/analyze", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ text, allow_anon_stats: allowAnon })
    });

    const data = await res.json().catch(()=> ({}));
    if(!res.ok){
      alert(data.detail || ("出事了，HTTP " + res.status));
      return;
    }

    lastAnalyzed = data;

    document.getElementById("out").style.display = "block";
    document.getElementById("score").textContent = data.risk_score;

    const levelEl = document.getElementById("level");
    levelEl.textContent = data.risk_level;
    levelEl.className = "lvl " + (data.risk_level || "low");

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
    document.getElementById("actions").textContent = (data.recommended_actions || []).map(x=>"• "+x).join("\\n");

    const sus = (data.suspicious_urls || []);
    document.getElementById("urls").textContent = sus.length ? sus.map(x=>"• "+x).join("\\n") : "（未偵測到明顯可疑網址）";

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
    document.getElementById("copyhint").textContent = "✅ 已複製";
  }catch(e){
    document.getElementById("copyhint").textContent = "⚠️ 無法自動複製";
  }
}

async function downloadReport(){
  if(!lastAnalyzed){
    alert("你還沒分析就想要報告？先按分析");
    return;
  }
  try{
    const body = {
      analyzed: lastAnalyzed,
      include_preview: false,
      preview_text: null
    };

    const res = await fetch("/report", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify(body)
    });

    if(!res.ok){
      const data = await res.json().catch(()=> ({}));
      alert(data.detail || ("報告生成失敗，HTTP " + res.status));
      return;
    }

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "ScamShield_Report.html";
    document.body.appendChild(a);
    a.click();
    a.remove();

    URL.revokeObjectURL(url);

    document.getElementById("copyhint").textContent = "✅ 報告已下載（打開後可列印/存成 PDF）";
  }catch(e){
    alert("報告生成出事了：" + e);
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
        return JSONResponse(status_code=429, content={"detail": "太多次啦靠杯（rate limit）— 請稍後再試"})

    text = (body.text or "").strip()
    if not text:
        return JSONResponse(status_code=400, content={"detail": "text 不能是空的"})
    if len(text) > MAX_TEXT_CHARS:
        return JSONResponse(status_code=400, content={"detail": f"text 太長（最多 {MAX_TEXT_CHARS} 字）"})

    try:
        result = analyze_text(text, context=body.context)

        # 匿名統計：只有使用者勾選才記
        if body.allow_anon_stats:
            _stats_add(result, text)

        return result
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": f"Internal error: {type(e).__name__}"})


@app.post("/report", response_class=HTMLResponse)
async def report(req: ReportRequest):
    """
    生成完整報告（HTML），不存任何資料。
    下載後可用瀏覽器列印 / 存成 PDF（最方便也最像產品流程）。
    """
    html = _render_report_html(req.analyzed, req.include_preview, req.preview_text)
    headers = {
        "Content-Disposition": 'attachment; filename="ScamShield_Report.html"'
    }
    return HTMLResponse(content=html, headers=headers)
