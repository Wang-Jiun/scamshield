from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from scamshield import analyze_text

app = FastAPI(title="ScamShield Web", version="1.2.0")

# ========= basic protections =========
MAX_TEXT_CHARS = 5000
RATE_LIMIT_PER_MIN = 30

# ip -> [window_start_ts, count]
_rate: Dict[str, list] = {}

# anonymous stats (NO message content stored)
_stats = {
    "start_ts": time.time(),
    "total_requests": 0,
    "analyze_ok": 0,
    "analyze_4xx": 0,
    "analyze_5xx": 0,
    "rate_limited": 0,
    "avg_text_len_sum": 0,
    "avg_text_len_n": 0,
    "risk_level_count": {"low": 0, "medium": 0, "high": 0, "critical": 0, "unknown": 0},
}


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


def _security_headers(resp: JSONResponse | HTMLResponse) -> JSONResponse | HTMLResponse:
    # 低成本安全小補強（不擋 Swagger /docs）
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # CSP 放寬一點（因為我們 inline script/style）
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return resp


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/stats")
def stats():
    # 匿名統計（不存訊息內容）
    uptime = int(time.time() - _stats["start_ts"])
    avg_len = 0
    if _stats["avg_text_len_n"] > 0:
        avg_len = int(_stats["avg_text_len_sum"] / _stats["avg_text_len_n"])
    return {
        "uptime_sec": uptime,
        "total_requests": _stats["total_requests"],
        "analyze_ok": _stats["analyze_ok"],
        "analyze_4xx": _stats["analyze_4xx"],
        "analyze_5xx": _stats["analyze_5xx"],
        "rate_limited": _stats["rate_limited"],
        "avg_text_len": avg_len,
        "risk_level_count": _stats["risk_level_count"],
        "note": "匿名統計：不會儲存你貼的文字內容",
    }


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
    triggered_rules: List[TriggeredRule]
    explanation: str
    recommended_actions: List[str]
    reply_templates: List[str]


@app.get("/", response_class=HTMLResponse)
def home():
    html = r"""
<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>ScamShield 防詐分析</title>
  <style>
    body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans TC",sans-serif;background:#0b0f14;color:#e6edf3;margin:0}
    .wrap{max-width:980px;margin:0 auto;padding:24px}
    .card{background:#101826;border:1px solid #1f2a3a;border-radius:18px;padding:18px;margin-top:16px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
    textarea{width:100%;min-height:190px;border-radius:12px;border:1px solid #2a3a52;background:#0b1220;color:#e6edf3;padding:12px;font-size:16px;resize:vertical}
    button{border:0;border-radius:12px;padding:12px 16px;background:#00ff88;color:#04210f;font-weight:900;cursor:pointer}
    button:disabled{opacity:.55;cursor:not-allowed}
    .row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
    .pill{display:inline-block;padding:6px 10px;border-radius:999px;border:1px solid #2a3a52;background:#0b1220}
    pre{white-space:pre-wrap;word-break:break-word;background:#0b1220;border:1px solid #2a3a52;border-radius:12px;padding:12px}
    .lvl{font-weight:1000}
    .low{color:#2ecc71}.medium{color:#f1c40f}.high{color:#e74c3c}.critical{color:#ff3b30}
    a{color:#00ff88}
    .small{opacity:.82;font-size:13px}
    .tag{display:inline-block;margin:4px 6px 0 0;padding:6px 10px;border-radius:999px;background:#0b1220;border:1px solid #2a3a52}
    .copy{background:#1f2a3a;color:#e6edf3;font-weight:900}
    .danger{border-color:#6b2b2b}
    .grid{display:grid;grid-template-columns:1fr;gap:12px}
    @media (min-width: 860px){
      .grid{grid-template-columns:1fr 1fr}
    }
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
    .hint{opacity:.9}
  </style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ ScamShield 防詐文字分析</h1>

  <div class="card">
    <p class="hint">貼上你收到的訊息（簡訊/LINE/FB/Email 都可以），按下分析。<span class="small">（上線版不會幫你存內容，別緊張）</span></p>

    <div class="row" style="margin:10px 0 12px">
      <span class="pill">快速塞範例：</span>
      <button class="copy" onclick="fillExample('bank')">假客服/帳戶凍結</button>
      <button class="copy" onclick="fillExample('invest')">投資飆股</button>
      <button class="copy" onclick="fillExample('love')">交友借錢</button>
      <button class="copy" onclick="fillExample('parcel')">包裹/物流</button>
      <button class="copy" onclick="fillExample('job')">打工刷單</button>
    </div>

    <textarea id="text" placeholder="例如：你的帳戶異常，請立即匯款並提供驗證碼，否則凍結..."></textarea>

    <div class="row" style="margin-top:12px">
      <button id="btn" onclick="run()">分析</button>
      <span class="pill">⚠️ 這是輔助判斷工具，請以官方管道查證</span>
      <span class="pill">Swagger：<a href="/docs" target="_blank" rel="noreferrer">/docs</a></span>
      <span class="pill">Stats：<a href="/stats" target="_blank" rel="noreferrer">/stats</a></span>
    </div>
  </div>

  <div class="grid">
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
      <pre id="urls" class="mono"></pre>

      <h3>可直接複製回覆模板</h3>
      <div class="row" style="margin:8px 0">
        <button class="copy" onclick="copyTemplates()">一鍵複製模板</button>
        <button class="copy" onclick="copyFullReport()">一鍵複製完整報告</button>
        <span class="small" id="copyhint"></span>
      </div>
      <pre id="templates"></pre>

      <details style="margin-top:10px">
        <summary>查看命中規則與證據句（進階）</summary>
        <pre id="rules"></pre>
      </details>
    </div>

    <div class="card" id="multi" style="display:none">
      <h2>整串對話模式（自動切段）</h2>
      <p class="small">如果你貼的是一整串對話，我會切成多段各自分析，並挑出最危險 Top 3。靠杯好用吧。</p>

      <h3>最危險 Top 3</h3>
      <pre id="top3"></pre>

      <details style="margin-top:10px">
        <summary>查看每段分析（進階）</summary>
        <pre id="segments"></pre>
      </details>
    </div>
  </div>

  <p class="small">API: <code>POST /analyze</code>，健康檢查：<code>/health</code></p>
</div>

<script>
let lastTemplates = "";
let lastFullReport = "";

function fillExample(kind){
  const t = document.getElementById("text");
  const samples = {
    bank: "【銀行客服】你的帳戶異常，請立刻匯款並提供驗證碼，否則將凍結處理。可點此連結完成認證：https://bit.ly/xxxxx",
    invest: "恭喜你獲得內線飆股名單！加入LINE群立即領取：line.me/ti/g2/xxxxx  保證獲利、限時名額，現在入金最划算。",
    love: "我現在人在外地出事了，手機沒電，只能先借你一點錢救急…拜託你先匯到這個帳號，我等下就還你。",
    parcel: "【物流通知】你的包裹因地址不完整，請24小時內補填資料：https://tinyurl.com/xxxxx 否則退回。",
    job: "誠徵在家兼職！日領3000起，先幫忙刷單提高評價，完成後立刻返款+佣金，加入群組：t.me/xxxxx"
  };
  t.value = samples[kind] || "";
}

function extractUrls(text){
  // 抓 http(s) / 常見短網址 / line.me / t.me
  const re = /(https?:\/\/[^\s"')]+)|\b(bit\.ly\/[^\s]+|tinyurl\.com\/[^\s]+|t\.me\/[^\s]+|line\.me\/[^\s]+)\b/ig;
  const out = [];
  let m;
  while((m = re.exec(text)) !== null){
    out.push(m[0]);
  }
  // 去重
  return [...new Set(out)];
}

function isShortUrl(u){
  return /bit\.ly|tinyurl\.com/i.test(u);
}

function splitIntoSegments(text){
  // 目標：對話貼一整串時，自動切段
  // 規則：用換行切，然後把「空行」當段落分隔；再把過短段落合併
  const lines = text.split(/\r?\n/);
  const segs = [];
  let buf = [];
  for(const line of lines){
    if(line.trim() === ""){
      if(buf.length){
        segs.push(buf.join("\n").trim());
        buf = [];
      }
    }else{
      buf.push(line);
    }
  }
  if(buf.length) segs.push(buf.join("\n").trim());

  // 如果沒有空行分段，就用句號/驚嘆/問號/頓號之類粗切（保底）
  if(segs.length <= 1){
    const rough = text.split(/(?<=[。！？!?\n])\s*/).map(s=>s.trim()).filter(Boolean);
    // 合併成每段最多 3 句，避免太碎
    const merged = [];
    let tmp = [];
    for(const s of rough){
      tmp.push(s);
      if(tmp.length >= 3){
        merged.push(tmp.join(" "));
        tmp = [];
      }
    }
    if(tmp.length) merged.push(tmp.join(" "));
    return merged.filter(s=>s.length >= 8);
  }

  // 合併太短的段落
  const merged = [];
  for(const s of segs){
    if(merged.length === 0){
      merged.push(s);
    }else{
      if(s.length < 20){
        merged[merged.length-1] += "\n" + s;
      }else{
        merged.push(s);
      }
    }
  }
  return merged;
}

async function analyzeOne(text){
  const res = await fetch("/analyze", {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ text })
  });
  const data = await res.json().catch(()=> ({}));
  return { ok: res.ok, status: res.status, data };
}

function buildReport(originalText, result, urls){
  const lines = [];
  lines.push("【ScamShield 完整報告】");
  lines.push("時間：" + new Date().toLocaleString());
  lines.push("");
  lines.push("【原始訊息】");
  lines.push(originalText);
  lines.push("");
  lines.push("【分析結果】");
  lines.push("風險分數：" + result.risk_score);
  lines.push("風險等級：" + result.risk_level);
  if((result.scam_types || []).length){
    lines.push("詐騙類型：" + result.scam_types.join("、"));
  }else{
    lines.push("詐騙類型：未明確分類（仍建議用官方管道確認）");
  }
  lines.push("");
  lines.push("【簡短說明】");
  lines.push(result.explanation || "");
  lines.push("");
  lines.push("【建議行動】");
  (result.recommended_actions || []).forEach(x=> lines.push("• " + x));
  lines.push("");
  lines.push("【回覆模板】");
  (result.reply_templates || []).forEach((x,i)=> lines.push((i+1) + ". " + x));
  lines.push("");
  lines.push("【可疑網址】");
  if(urls.length){
    urls.forEach(u=>{
      lines.push("- " + u + (isShortUrl(u) ? "  （短網址⚠️）" : ""));
    });
  }else{
    lines.push("（未偵測到明顯網址）");
  }
  lines.push("");
  lines.push("【命中規則/證據】");
  lines.push(JSON.stringify(result.triggered_rules || [], null, 2));
  lines.push("");
  lines.push("※ 這是輔助判斷工具，請以官方管道查證。");
  return lines.join("\n");
}

async function run(){
  const btn = document.getElementById("btn");
  const text = document.getElementById("text").value.trim();
  if(!text){ alert("先貼文字啦靠杯 🤣"); return; }

  btn.disabled = true; btn.textContent="分析中…";
  document.getElementById("copyhint").textContent = "";
  document.getElementById("out").style.display = "none";
  document.getElementById("multi").style.display = "none";

  try{
    // 單次分析
    const single = await analyzeOne(text);
    if(!single.ok){
      alert((single.data && single.data.detail) ? single.data.detail : ("出事了，HTTP " + single.status));
      return;
    }

    const data = single.data || {};
    const urls = extractUrls(text);

    // 顯示單次結果
    document.getElementById("out").style.display = "block";
    document.getElementById("score").textContent = data.risk_score;

    const levelEl = document.getElementById("level");
    levelEl.textContent = data.risk_level;
    levelEl.className = "lvl " + data.risk_level;

    // types tags
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

    const tpl = (data.reply_templates || []).map((x,i)=>`${i+1}. ${x}`).join("\\n");
    document.getElementById("templates").textContent = tpl;
    lastTemplates = tpl;

    document.getElementById("rules").textContent = JSON.stringify(data.triggered_rules || [], null, 2);

    // urls
    if(urls.length){
      document.getElementById("urls").textContent = urls.map(u => "- " + u + (isShortUrl(u) ? "  （短網址⚠️）" : "")).join("\\n");
    }else{
      document.getElementById("urls").textContent = "（未偵測到明顯網址）";
    }

    // full report
    lastFullReport = buildReport(text, data, urls);

    // 多段分析（如果看起來像一整串）
    const segs = splitIntoSegments(text);
    if(segs.length >= 2){
      document.getElementById("multi").style.display = "block";

      // 限制段落數，避免一直打爆 API（你有 rate limit）
      const maxSeg = 12;
      const picked = segs.slice(0, maxSeg);

      const results = [];
      for(const s of picked){
        const r = await analyzeOne(s);
        if(r.ok){
          results.push({ seg: s, risk: r.data.risk_score ?? -1, level: r.data.risk_level ?? "unknown", data: r.data });
        }else{
          results.push({ seg: s, risk: -1, level: "error", data: { detail: r.data?.detail || ("HTTP " + r.status) } });
        }
      }

      // Top3 by risk
      const okOnes = results.filter(x=> typeof x.risk === "number" && x.risk >= 0);
      okOnes.sort((a,b)=> b.risk - a.risk);
      const top3 = okOnes.slice(0,3);

      document.getElementById("top3").textContent =
        top3.length
          ? top3.map((x,i)=>`#${i+1} 風險 ${x.risk} / ${x.level}\n${x.seg}\n`).join("\n")
          : "（段落分析失敗或沒有足夠段落）";

      // segments details
      const detail = results.map((x,idx)=>{
        if(x.level === "error"){
          return `--- 段落 ${idx+1}（分析失敗） ---\n${x.seg}\n\n錯誤：${JSON.stringify(x.data)}\n`;
        }
        return `--- 段落 ${idx+1}（風險 ${x.risk} / ${x.level}） ---\n${x.seg}\n\n說明：${x.data.explanation || ""}\n\n`;
      }).join("\n");
      document.getElementById("segments").textContent = detail;
    }

    // scroll
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
    document.getElementById("copyhint").textContent = "✅ 已複製模板，直接貼回去就好（別被騙啦）";
  }catch(e){
    document.getElementById("copyhint").textContent = "⚠️ 不能自動複製，你手動選取也行";
  }
}

async function copyFullReport(){
  if(!lastFullReport){ return; }
  try{
    await navigator.clipboard.writeText(lastFullReport);
    document.getElementById("copyhint").textContent = "✅ 已複製完整報告（家人/老師/警察都看得懂那種）";
  }catch(e){
    document.getElementById("copyhint").textContent = "⚠️ 不能自動複製，你手動選取也行";
  }
}
</script>
</body>
</html>
"""
    resp = HTMLResponse(html)
    return _security_headers(resp)


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(body: AnalyzeRequest, req: Request):
    _stats["total_requests"] += 1

    ip = _client_ip(req)
    if not _rate_limit_ok(ip):
        _stats["rate_limited"] += 1
        return JSONResponse(status_code=429, content={"detail": "太多次啦靠杯（rate limit）— 請稍後再試"})

    text = (body.text or "").strip()

    if not text:
        _stats["analyze_4xx"] += 1
        return JSONResponse(status_code=400, content={"detail": "text 不能是空的"})

    if len(text) > MAX_TEXT_CHARS:
        _stats["analyze_4xx"] += 1
        return JSONResponse(status_code=400, content={"detail": f"text 太長（最多 {MAX_TEXT_CHARS} 字）"})

    # anonymous length stats
    _stats["avg_text_len_sum"] += len(text)
    _stats["avg_text_len_n"] += 1

    try:
        result = analyze_text(text, context=body.context)

        # update risk count (best-effort)
        lvl = (result.get("risk_level") if isinstance(result, dict) else None) or "unknown"
        if lvl not in _stats["risk_level_count"]:
            lvl = "unknown"
        _stats["risk_level_count"][lvl] += 1

        _stats["analyze_ok"] += 1

        resp = JSONResponse(status_code=200, content=result)
        return _security_headers(resp)
    except Exception as e:
        _stats["analyze_5xx"] += 1
        # 保底：不要把 traceback 直接噴給使用者
        resp = JSONResponse(status_code=500, content={"detail": f"Internal error: {type(e).__name__}"})
        return _security_headers(resp)
