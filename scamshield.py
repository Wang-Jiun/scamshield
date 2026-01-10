from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import urlparse

# =========================
# Utilities
# =========================

URL_RE = re.compile(
    r"""(?xi)
    \b(
      https?://[^\s<>"'()]+
      |
      www\.[^\s<>"'()]+
    )"""
)

PHONE_RE = re.compile(r"""(?x)
    (?:
      (?:\+?886[-\s]?)?0?9\d{2}[-\s]?\d{3}[-\s]?\d{3}   # 台灣手機
      |
      0\d{1,2}[-\s]?\d{6,8}                              # 市話
    )
""")

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")

# 很粗略：銀行帳號/卡號通常是長數字，避免誤抓一般數字
LONG_NUMBER_RE = re.compile(r"\b\d{10,19}\b")

SHORTENER_DOMAINS = {
    "tinyurl.com", "bit.ly", "reurl.cc", "t.co", "is.gd", "cutt.ly", "goo.gl", "rb.gy"
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "site", "click", "live", "icu", "cfd", "shop", "work", "info"
}

PUNYCODE_PREFIX = "xn--"


def _norm_url(u: str) -> str:
    u = u.strip()
    if u.startswith("www."):
        u = "http://" + u
    return u


def extract_urls(text: str) -> List[str]:
    urls = []
    for m in URL_RE.finditer(text or ""):
        urls.append(m.group(1).rstrip(".,;:!?)]}"))
    # 去重保序
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def extract_entities(text: str) -> Dict[str, List[str]]:
    phones = list(dict.fromkeys(PHONE_RE.findall(text or "")))
    emails = list(dict.fromkeys(EMAIL_RE.findall(text or "")))
    long_nums = list(dict.fromkeys(LONG_NUMBER_RE.findall(text or "")))
    urls = extract_urls(text or "")
    return {
        "phones": phones,
        "emails": emails,
        "long_numbers": long_nums,
        "urls": urls,
    }


def domain_of(url: str) -> str:
    try:
        pu = urlparse(_norm_url(url))
        host = (pu.hostname or "").lower()
        return host
    except Exception:
        return ""


def is_ip_host(host: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host or ""))


def analyze_url_risk(url: str) -> Tuple[int, str]:
    """
    return (score, reason)
    """
    host = domain_of(url)
    if not host:
        return (0, "無法解析網域")

    score = 0
    reasons = []

    if host in SHORTENER_DOMAINS:
        score += 25
        reasons.append("短網址（常用於釣魚跳轉）")

    if host.startswith(PUNYCODE_PREFIX) or PUNYCODE_PREFIX in host:
        score += 20
        reasons.append("疑似混淆網域（punycode）")

    if is_ip_host(host):
        score += 30
        reasons.append("IP 直連網址（很可疑）")

    # tld
    parts = host.split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        if tld in SUSPICIOUS_TLDS:
            score += 12
            reasons.append(f"可疑網域尾綴 .{tld}")

    # 超多子網域
    if len(parts) >= 4:
        score += 8
        reasons.append("子網域過多（常見於偽裝）")

    # URL 太長
    if len(url) >= 80:
        score += 6
        reasons.append("網址過長（常藏參數/跳轉）")

    # @ 符號常用來混淆
    if "@" in url:
        score += 10
        reasons.append("網址含 @（常用混淆導向）")

    reason = "、".join(reasons) if reasons else "目前未見明顯網址風險特徵"
    return (min(score, 50), reason)


# =========================
# Rule engine
# =========================

@dataclass
class Rule:
    name: str
    score: int
    patterns: List[re.Pattern]
    scam_types: List[str]
    stage_hint: str  # pipeline stage hint
    note: str = ""


def _p(s: str) -> re.Pattern:
    return re.compile(s, re.IGNORECASE)


RULES: List[Rule] = [
    # 威脅/緊迫
    Rule(
        name="急迫/恐嚇",
        score=18,
        patterns=[_p(r"立即|馬上|立刻|限時|24小時|今天內|最後通牒|緊急|再不.*就|否則")],
        scam_types=["急迫恐嚇"],
        stage_hint="威脅施壓",
    ),
    Rule(
        name="凍結/停權/法律威脅",
        score=28,
        patterns=[_p(r"凍結|停權|封鎖|帳戶異常|司法|法院|傳票|刑事|報警|違規|罰款")],
        scam_types=["假客服/帳戶凍結"],
        stage_hint="威脅施壓",
    ),

    # 要求資料/驗證
    Rule(
        name="索取個資/驗證碼/OTP",
        score=30,
        patterns=[_p(r"驗證碼|OTP|一次性密碼|簡訊碼|提供.*密碼|提供.*驗證|登入驗證|二步驗證")],
        scam_types=["索取個資/驗證碼"],
        stage_hint="要求資料/驗證",
    ),
    Rule(
        name="要求點擊連結/填資料",
        score=22,
        patterns=[_p(r"點擊連結|點此|填寫|補填|更新資料|確認資料|網址|連結")],
        scam_types=["釣魚連結"],
        stage_hint="要求資料/驗證",
    ),

    # 金流/匯款
    Rule(
        name="匯款/轉帳/購買點數",
        score=35,
        patterns=[_p(r"匯款|轉帳|ATM|點數|代購|超商代碼|充值|儲值|買遊戲點|購買禮物卡")],
        scam_types=["要求匯款/點數"],
        stage_hint="要求匯款",
    ),

    # 投資
    Rule(
        name="投資高報酬/帶單/內線",
        score=26,
        patterns=[_p(r"高報酬|保證獲利|帶單|老師|群組|飆股|內線|翻倍|穩賺|不賠")],
        scam_types=["投資詐騙"],
        stage_hint="資訊投放",
    ),

    # 打工/刷單
    Rule(
        name="打工刷單/日領",
        score=28,
        patterns=[_p(r"刷單|日領|免經驗|在家兼職|先垫付|先墊付|返款|佣金|傭金|提高評價")],
        scam_types=["打工刷單"],
        stage_hint="資訊投放",
    ),

    # 物流/包裹
    Rule(
        name="偽物流通知/包裹異常",
        score=22,
        patterns=[_p(r"包裹|物流|地址不完整|派送失敗|清關|補繳|關稅|運費|退回")],
        scam_types=["偽物流通知"],
        stage_hint="要求資料/驗證",
    ),

    # 轉移平台
    Rule(
        name="引導轉移平台",
        score=18,
        patterns=[_p(r"加LINE|加好友|私訊|移到|telegram|tg|whatsapp|WeChat|微信|t\.me/")],
        scam_types=["轉移平台"],
        stage_hint="轉移平台",
    ),

    # 借錢社工（修你那張 0 分）
    Rule(
        name="借錢/急用/情緒勒索",
        score=22,
        patterns=[_p(r"先借我|借我|急用|周轉|拜託|很急|我現在.*需要|今天就還|馬上還|轉我.*(元|塊)?")],
        scam_types=["冒名熟人/借錢"],
        stage_hint="要求匯款",
        note="常見冒名熟人或社工借錢話術",
    ),
]


def _split_sentences(text: str) -> List[str]:
    # 粗切：中英標點
    parts = re.split(r"[。！？!?;\n\r]+", text or "")
    parts = [p.strip() for p in parts if p.strip()]
    return parts


def _find_evidence(sentences: List[str], rule: Rule) -> List[str]:
    ev = []
    for s in sentences:
        for pat in rule.patterns:
            if pat.search(s):
                ev.append(s)
                break
    # 限制證據句數量
    return ev[:4]


STAGE_ORDER = [
    "資訊投放",
    "建立信任",
    "轉移平台",
    "要求資料/驗證",
    "要求匯款",
    "威脅施壓",
]


def _pick_stage(stage_scores: Dict[str, int]) -> str:
    if not stage_scores:
        return "資訊投放"
    # 分數最高者；同分就取更後面（越後面通常越危險）
    best = max(stage_scores.items(), key=lambda kv: (kv[1], STAGE_ORDER.index(kv[0]) if kv[0] in STAGE_ORDER else 0))
    return best[0]


def _risk_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _merge_unique(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def analyze_text(text: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    text = (text or "").strip()
    sentences = _split_sentences(text)
    entities = extract_entities(text)
    urls = entities.get("urls", [])

    triggered_rules = []
    scam_types: List[str] = []
    stage_scores: Dict[str, int] = {}

    base_score = 0

    for rule in RULES:
        hit = False
        for pat in rule.patterns:
            if pat.search(text):
                hit = True
                break
        if not hit:
            continue

        ev = _find_evidence(sentences, rule)
        triggered_rules.append({
            "name": rule.name,
            "score": rule.score,
            "evidence_sentences": ev or sentences[:1]  # 沒抓到就至少丟一段
        })
        base_score += rule.score
        scam_types.extend(rule.scam_types)
        stage_scores[rule.stage_hint] = stage_scores.get(rule.stage_hint, 0) + rule.score

    scam_types = _merge_unique(scam_types)

    # URL risk
    suspicious_urls: List[Dict[str, Any]] = []
    url_score_total = 0
    for u in urls:
        s, reason = analyze_url_risk(u)
        if s > 0:
            suspicious_urls.append({"url": u, "score": s, "reason": reason})
        url_score_total += s

    # 資料/驗證碼特別加權（避免被低估）
    extra = 0
    if entities.get("long_numbers"):
        # 長數字可能是帳號/卡號，視為風險訊號，但別太重
        extra += 6

    # 最終分數
    score = base_score + min(url_score_total, 40) + extra

    # 沒命中規則但有短網址/可疑網址，也要給基本提醒
    if score == 0 and urls:
        score = min(25, max(url_score_total, 15))
        stage_scores["要求資料/驗證"] = stage_scores.get("要求資料/驗證", 0) + 10
        if "釣魚連結" not in scam_types:
            scam_types.append("釣魚連結")

    score = max(0, min(score, 100))
    level = _risk_level(score)
    stage = _pick_stage(stage_scores)

    # Explanation
    highlights = []
    if triggered_rules:
        highlights.append(f"判斷流程階段：{stage}")
        highlights.append("我看到的重點：")
        for r in triggered_rules[:5]:
            highlights.append(f"• 命中：{r['name']}（+{r['score']}）")
    else:
        highlights.append(f"判斷流程階段：{stage}")
        highlights.append("• 目前沒有明顯高風險特徵，但仍建議用官方管道確認。")

    if suspicious_urls:
        highlights.append("• 文字內含可疑網址/短網址（很常是釣魚入口）")

    explanation = "\n".join(highlights)

    # Recommended actions
    actions = [
        "先冷靜：不要急著回覆，不要照做對方指示。",
        "用官方管道自查：自己打開官方 App/官網，不要用對方給的連結。",
        "保留證據：截圖、保存聊天紀錄、帳號、連結、轉帳資訊。",
    ]
    if level in ("high", "critical"):
        actions.extend([
            "不要提供：驗證碼/密碼/卡號/身分證等任何敏感資訊。",
            "若已匯款或提供資料：立刻改密碼、開啟兩步驗證，並通知銀行/平台。",
            "可撥 165 反詐騙諮詢（台灣）或向警方報案。",
        ])

    # Reply templates (可直接貼回對方)
    templates = [
        "我會到官方管道自行查證，不會點不明連結或在這裡提供任何資料。",
        "我不會提供驗證碼/密碼/卡號，也不會依照指示轉帳或購買點數。",
        "若你是官方單位，請提供正式公文/案件編號與可回撥的官方電話，我會自行致電確認。",
    ]
    if "冒名熟人/借錢" in scam_types:
        templates.insert(0, "你先用電話/視訊跟我確認身分，我確認是本人再說。現在我不會轉帳。")

    return {
        "risk_score": score,
        "risk_level": level,
        "scam_types": scam_types,
        "stage": stage,
        "triggered_rules": triggered_rules,
        "explanation": explanation,
        "recommended_actions": actions,
        "reply_templates": templates,
        "suspicious_urls": suspicious_urls,
        "entities": entities,
    }
