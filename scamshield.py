from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple


# =========================
# Utilities
# =========================

URL_RE = re.compile(
    r"(https?://[^\s<>\]]+|www\.[^\s<>\]]+|(?:t\.me|bit\.ly|tinyurl\.com|reurl\.cc|pse\.is|lihi\.cc|"
    r"cutt\.ly|rebrand\.ly|t\.co|s\.id|is\.gd|soo\.gd|tiny\.cc|shorturl\.at)/[^\s<>\]]+)",
    re.IGNORECASE,
)

SENT_SPLIT_RE = re.compile(r"[。\.\!\?！？\n\r]+")

SHORTENER_DOMAINS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "reurl.cc",
    "pse.is",
    "lihi.cc",
    "cutt.ly",
    "rebrand.ly",
    "s.id",
    "is.gd",
    "soo.gd",
    "tiny.cc",
    "shorturl.at",
    "t.me",
}

# 常見關鍵字
KW_URGENCY = [
    "立即", "馬上", "立刻", "限時", "最後", "倒數", "今日內", "今天內", "24小時", "12小時",
    "逾期", "過期", "否則", "不然", "將", "將會", "否則凍結", "否則停用", "否則退回",
]
KW_ACCOUNT = ["帳戶異常", "帳戶", "帳號", "登入", "驗證", "安全性", "凍結", "停用", "解鎖", "風險"]
KW_OTP = ["驗證碼", "OTP", "一次性密碼", "短信碼", "簡訊碼", "動態密碼", "認證碼", "安全碼"]
KW_MONEY = ["匯款", "轉帳", "入金", "付款", "繳費", "金額", "保證金", "手續費", "解凍金", "充值", "儲值", "點數"]
KW_LOGISTICS = ["物流", "包裹", "宅配", "快遞", "投遞", "配送", "地址", "收件", "取件", "運費", "退回", "未送達", "派送"]
KW_GOV_BANK = ["銀行", "金管會", "法院", "檢察官", "警察", "165", "戶政", "電信", "中華電信", "健保", "稅務", "國稅局"]
KW_JOB = ["在家兼職", "打工", "高薪", "日領", "刷單", "代刷", "任務", "佣金", "抽成", "入群", "群組", "帶單", "導師"]
KW_INVEST = ["投資", "飆股", "當沖", "老師", "助理", "帶你賺", "保證獲利", "穩賺", "內線", "入會", "VIP", "群", "群組"]
KW_ROMANCE = ["交友", "交往", "戀愛", "暈船", "寶貝", "親愛的", "網戀", "視訊", "裸聊", "包養"]
KW_THREAT = ["提告", "法辦", "通緝", "拘提", "逮捕", "法院傳票", "不配合", "涉嫌", "洗錢", "刑責"]


def _now_ts() -> float:
    return time.time()


def _clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def _normalize_text(s: str) -> str:
    s = (s or "").strip()
    # 連續空白壓縮
    s = re.sub(r"[ \t]+", " ", s)
    return s


def _split_sentences(text: str) -> List[str]:
    parts = [p.strip() for p in SENT_SPLIT_RE.split(text) if p.strip()]
    # 避免太碎：把很短的句子跟前一句合併
    merged: List[str] = []
    for p in parts:
        if merged and len(p) <= 4:
            merged[-1] = merged[-1] + " " + p
        else:
            merged.append(p)
    return merged if merged else [text.strip()] if text.strip() else []


def _extract_urls(text: str) -> List[str]:
    urls = []
    for m in URL_RE.finditer(text or ""):
        u = m.group(0).strip().rstrip(").,，。；;")
        # 補 www.
        if u.lower().startswith("www."):
            u = "http://" + u
        urls.append(u)
    # 去重但保留順序
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _domain_of(url: str) -> str:
    # 超輕量解析（夠用就好）
    u = url.strip()
    u = re.sub(r"^https?://", "", u, flags=re.IGNORECASE)
    u = u.split("/")[0]
    u = u.split(":")[0]
    return u.lower()


def _contains_any(text: str, kws: List[str]) -> bool:
    t = text or ""
    return any(k in t for k in kws)


def _find_hits_in_sentences(sentences: List[str], patterns: List[re.Pattern]) -> List[str]:
    hits: List[str] = []
    for s in sentences:
        if any(p.search(s) for p in patterns):
            hits.append(s)
    return hits


# =========================
# Rule Engine (Lv3)
# =========================

@dataclass(frozen=True)
class Rule:
    name: str
    score: int
    patterns: List[re.Pattern]
    scam_types: List[str]


def _compile_kw_patterns(kws: List[str]) -> List[re.Pattern]:
    # kw 直接做 OR，避免寫一堆 regex
    esc = [re.escape(k) for k in kws]
    if not esc:
        return []
    return [re.compile("|".join(esc), re.IGNORECASE)]


RULES: List[Rule] = [
    Rule(
        name="急迫/恐嚇（限時、否則、凍結/退回）",
        score=18,
        patterns=_compile_kw_patterns(KW_URGENCY + KW_THREAT),
        scam_types=["急迫恐嚇"],
    ),
    Rule(
        name="帳戶/身份驗證壓力（帳戶異常、登入、凍結、解鎖）",
        score=18,
        patterns=_compile_kw_patterns(KW_ACCOUNT),
        scam_types=["冒充客服/帳戶凍結"],
    ),
    Rule(
        name="索取驗證碼/OTP（高風險）",
        score=45,
        patterns=_compile_kw_patterns(KW_OTP),
        scam_types=["冒充客服/帳戶凍結"],
    ),
    Rule(
        name="涉及金錢（匯款/轉帳/保證金/手續費/點數）",
        score=30,
        patterns=_compile_kw_patterns(KW_MONEY),
        scam_types=["金錢要求"],
    ),
    Rule(
        name="物流/包裹通知（常見釣魚入口）",
        score=20,
        patterns=_compile_kw_patterns(KW_LOGISTICS),
        scam_types=["偽物流通知"],
    ),
    Rule(
        name="短網址/可疑連結（bit.ly/tinyurl/reurl...）",
        score=25,
        patterns=[re.compile(r"(bit\.ly|tinyurl\.com|reurl\.cc|pse\.is|lihi\.cc|cutt\.ly|rebrand\.ly|t\.co|s\.id|is\.gd|soo\.gd|tiny\.cc|shorturl\.at)", re.I)],
        scam_types=["釣魚連結"],
    ),
    Rule(
        name="要求填寫資料/點擊連結/輸入密碼",
        score=28,
        patterns=[re.compile(r"(點擊|點開|連結|網址|填寫|輸入|登入|認證|驗證|更新資料|補填|補齊|重新驗證)", re.I)],
        scam_types=["釣魚連結"],
    ),
    Rule(
        name="假冒政府/銀行/公權力（165、法院、警察、銀行等）",
        score=30,
        patterns=_compile_kw_patterns(KW_GOV_BANK),
        scam_types=["假冒機關/銀行"],
    ),
    Rule(
        name="投資飆股/老師帶單/保證獲利",
        score=30,
        patterns=_compile_kw_patterns(KW_INVEST),
        scam_types=["投資詐騙"],
    ),
    Rule(
        name="打工/刷單/日領/佣金/入群",
        score=35,
        patterns=_compile_kw_patterns(KW_JOB),
        scam_types=["打工刷單"],
    ),
    Rule(
        name="交友/網戀/裸聊/包養（常見勒索前置）",
        score=25,
        patterns=_compile_kw_patterns(KW_ROMANCE),
        scam_types=["交友誘騙"],
    ),
]


def _detect_stage(text: str, urls: List[str]) -> str:
    t = text or ""

    # stage 0：純通知/閒聊
    stage = "資訊投放"

    # stage 1：誘導點擊
    if urls or _contains_any(t, ["點擊", "點開", "連結", "網址", "下載", "掃碼", "QR", "加入群", "入群", "t.me/"]):
        stage = "誘導點擊"

    # stage 2：要求資料/驗證/登入
    if _contains_any(t, ["填寫", "輸入", "登入", "驗證", "認證", "更新資料", "補填", "補齊", "身分證", "銀行帳號"]):
        stage = "要求資料/驗證"

    # stage 3：要求行動（金錢/轉帳/保證金/點數）
    if _contains_any(t, KW_MONEY):
        stage = "要求金錢/行動"

    # OTP 直接拉到最高階段
    if _contains_any(t, KW_OTP):
        stage = "要求金錢/行動"

    return stage


def _combo_boosts(text: str, urls: List[str]) -> List[Tuple[str, int]]:
    """Lv3-A：套路組合加權（命中就額外加分）"""
    t = text or ""
    doms = {_domain_of(u) for u in urls}
    has_short = any(d in SHORTENER_DOMAINS for d in doms) or _contains_any(t, ["tinyurl", "bit.ly", "reurl", "t.me/"])
    has_url = bool(urls)
    urgency = _contains_any(t, KW_URGENCY + KW_THREAT)
    logistics = _contains_any(t, KW_LOGISTICS)
    account = _contains_any(t, KW_ACCOUNT)
    otp = _contains_any(t, KW_OTP)
    money = _contains_any(t, KW_MONEY)
    invest = _contains_any(t, KW_INVEST)
    job = _contains_any(t, KW_JOB)
    gov = _contains_any(t, KW_GOV_BANK)
    ask_click_or_form = _contains_any(t, ["點擊", "點開", "連結", "網址", "填寫", "輸入", "登入", "認證", "驗證", "更新資料", "補填", "補齊"])

    boosts: List[Tuple[str, int]] = []

    # 物流 + 連結（尤其短網址）= 很經典
    if logistics and has_url:
        boosts.append(("組合：物流通知 + 連結", 20))
    if logistics and has_short:
        boosts.append(("組合：物流通知 + 短網址（高釣魚）", 25))
    if has_short and ask_click_or_form:
        boosts.append(("組合：短網址 + 要你點擊/填資料", 25))

    # 帳戶凍結 + 急迫 + 連結
    if account and urgency:
        boosts.append(("組合：帳戶異常/凍結 + 急迫施壓", 20))
    if account and has_url:
        boosts.append(("組合：帳戶異常/凍結 + 連結導流", 20))

    # OTP 直接爆（通常不是正常客服會要）
    if otp and (account or urgency or has_url):
        boosts.append(("組合：索取 OTP + 帳戶/急迫/連結（極高風險）", 35))

    # 公權力 + 恐嚇
    if gov and urgency:
        boosts.append(("組合：假冒機關/銀行 + 恐嚇施壓", 25))

    # 投資套路
    if invest and (_contains_any(t, ["保證", "穩賺", "內線", "帶單", "老師"]) or _contains_any(t, ["入群", "群組", "助理"])):
        boosts.append(("組合：投資話術 + 群組/老師帶單", 25))

    # 刷單套路
    if job and (_contains_any(t, ["刷單", "任務", "佣金", "日領", "群組"]) or has_url):
        boosts.append(("組合：打工刷單 + 任務/入群/導流", 30))

    # 金錢 + 急迫
    if money and urgency:
        boosts.append(("組合：金錢要求 + 急迫施壓", 25))

    return boosts


def _hard_gates(text: str, urls: List[str]) -> List[Tuple[str, str]]:
    """
    Lv3-B：硬切門檻（某些情況不能 low）
    return: list of (reason, min_level)
    """
    t = text or ""
    doms = {_domain_of(u) for u in urls}
    has_short = any(d in SHORTENER_DOMAINS for d in doms) or _contains_any(t, ["tinyurl", "bit.ly", "reurl", "t.me/"])
    has_url = bool(urls)

    urgency = _contains_any(t, KW_URGENCY + KW_THREAT)
    logistics = _contains_any(t, KW_LOGISTICS)
    account = _contains_any(t, KW_ACCOUNT)
    otp = _contains_any(t, KW_OTP)
    money = _contains_any(t, KW_MONEY)
    gov = _contains_any(t, KW_GOV_BANK)

    ask_click_or_form = _contains_any(t, ["點擊", "點開", "連結", "網址", "填寫", "輸入", "登入", "認證", "驗證", "更新資料", "補填", "補齊"])

    gates: List[Tuple[str, str]] = []

    # 短網址 + 填資料/點連結 -> 至少 medium
    if has_short and ask_click_or_form:
        gates.append(("短網址搭配點擊/填資料，常見釣魚手法", "medium"))

    # 物流 + 連結 + 急迫 -> 至少 medium
    if logistics and has_url and urgency:
        gates.append(("物流通知 + 連結 + 急迫施壓，典型偽物流詐騙", "medium"))

    # 帳戶凍結 + 連結 + 急迫 -> 至少 high
    if account and has_url and urgency:
        gates.append(("帳戶凍結話術 + 連結導流 + 急迫施壓，風險偏高", "high"))

    # OTP -> 至少 critical
    if otp:
        gates.append(("索取 OTP/驗證碼 幾乎可直接判高風險", "critical"))

    # 金錢 + 急迫 -> 至少 high
    if money and urgency:
        gates.append(("要求匯款/轉帳/費用 並施壓時間，風險偏高", "high"))

    # 假冒機關 + 恐嚇 -> 至少 high
    if gov and _contains_any(t, KW_THREAT):
        gates.append(("假冒機關/銀行搭配恐嚇刑責，風險偏高", "high"))

    return gates


def _level_from_score(score: int) -> str:
    # 你可以自己調（Lv3 最重要就是敢判）
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


_LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _apply_min_level(level: str, min_level: str) -> str:
    return level if _LEVEL_ORDER[level] >= _LEVEL_ORDER[min_level] else min_level


def _make_actions(level: str, scam_types: List[str], suspicious_links: List[str]) -> List[str]:
    actions: List[str] = []

    # 通用
    actions.append("先冷靜：不要急著回覆、不要照做對方指示。")
    if suspicious_links:
        actions.append("先不要點連結：尤其是短網址（tinyurl/bit.ly/reurl/t.me 等）。")
    actions.append("用官方管道自行查：自己打開官方 App/官網，不要用對方給的網址。")
    actions.append("保留證據：截圖、保存聊天紀錄、帳號、連結、轉帳資訊。")

    # 針對類型
    if "冒充客服/帳戶凍結" in scam_types:
        actions.append("不要提供驗證碼/密碼/卡號；客服不會要求你把 OTP 念出來。")
    if "偽物流通知" in scam_types:
        actions.append("去原本購物平台/物流官方查單號，不要在陌生連結補資料。")
    if "投資詐騙" in scam_types or "打工刷單" in scam_types:
        actions.append("不要加入群組/下載投資 App；通常都是導到詐騙池。")
    if level in ("high", "critical"):
        actions.append("若已點擊/輸入資料：立刻改密碼、開啟兩步驟驗證、通知銀行/平台。")
        actions.append("可撥 165 反詐騙諮詢（台灣）或向警方報案。")

    return actions


def _make_templates(scam_types: List[str]) -> List[str]:
    base = [
        "我會透過官方管道自行查證，不會點擊不明連結或提供任何個資。",
        "我不會提供驗證碼/密碼/卡號，也不會依照指示轉帳或購買點數。",
        "若你是官方單位，請提供正式公文/案件編號與可回撥的官方電話，我會自行致電確認。",
    ]

    if "偽物流通知" in scam_types:
        base.insert(0, "我會到購物平台/物流官方查詢，不會在不明網址補填資料。")
    if "投資詐騙" in scam_types:
        base.insert(0, "我不會加入投資群組或下載來路不明的投資 App，請勿再聯絡。")
    if "打工刷單" in scam_types:
        base.insert(0, "我不接受刷單/代操作/先墊款的工作，請不要再要求。")

    return base[:6]


def analyze_text(text: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    回傳格式（給 webapp / 前端用）：
    {
      risk_score: int (0-100),
      risk_level: "low"|"medium"|"high"|"critical",
      scam_types: [str],
      current_stage: str,
      suspicious_links: [str],
      triggered_rules: [{name, score, evidence_sentences}],
      explanation: str,
      recommended_actions: [str],
      reply_templates: [str],
      meta: {...}
    }
    """
    t0 = _now_ts()
    text = _normalize_text(text)
    sentences = _split_sentences(text)
    urls = _extract_urls(text)

    suspicious_links: List[str] = []
    for u in urls:
        dom = _domain_of(u)
        # 短網址直接列為可疑（你也可以再加黑名單/白名單）
        if dom in SHORTENER_DOMAINS:
            suspicious_links.append(u)

    triggered: List[Dict[str, Any]] = []
    scam_types: Set[str] = set()
    score = 0

    # 1) 單條規則
    for rule in RULES:
        hits = _find_hits_in_sentences(sentences, rule.patterns)
        if hits:
            triggered.append(
                {
                    "name": rule.name,
                    "score": rule.score,
                    "evidence_sentences": hits[:5],
                }
            )
            score += rule.score
            for st in rule.scam_types:
                scam_types.add(st)

    # 2) 組合加權（Lv3-A）
    boosts = _combo_boosts(text, urls)
    for name, add in boosts:
        triggered.append(
            {
                "name": name,
                "score": add,
                "evidence_sentences": sentences[:2] if sentences else [text[:120]],
            }
        )
        score += add

    # 3) stage（Lv3-C）
    stage = _detect_stage(text, urls)

    # 4) 分數壓縮到 0~100（避免爆到 200 看起來很怪）
    #    你可以改成 sigmoid，但這版先用「溫和截斷 + 小幅回彈」
    raw_score = score
    if score > 100:
        score = 100 - int((score - 100) * 0.35)  # 超過 100 的部分打折
    score = _clamp(score, 0, 100)

    level = _level_from_score(score)

    # 5) 硬切門檻（Lv3-B）
    gates = _hard_gates(text, urls)
    for reason, min_level in gates:
        triggered.append(
            {
                "name": f"門檻：{reason}",
                "score": 0,
                "evidence_sentences": sentences[:2] if sentences else [text[:120]],
            }
        )
        level = _apply_min_level(level, min_level)

    # 6) 解釋（簡短但有感）
    top = sorted(triggered, key=lambda x: x.get("score", 0), reverse=True)[:4]
    reasons = [f"• {x['name']}" for x in top if x.get("name")]
    if not reasons:
        reasons = ["• 目前沒有明顯高風險特徵，但仍建議用官方管道確認。"]

    explain = (
        f"判斷流程階段：{stage}\n"
        f"我看到的重點：\n" + "\n".join(reasons)
    )

    # 7) 行動/模板
    scam_types_list = sorted(scam_types)
    actions = _make_actions(level, scam_types_list, suspicious_links)
    templates = _make_templates(scam_types_list)

    dt_ms = int((_now_ts() - t0) * 1000)

    return {
        "risk_score": score,
        "risk_level": level,
        "scam_types": scam_types_list,
        "current_stage": stage,
        "suspicious_links": suspicious_links,
        "triggered_rules": triggered,
        "explanation": explain,
        "recommended_actions": actions,
        "reply_templates": templates,
        "meta": {
            "raw_score": raw_score,
            "latency_ms": dt_ms,
            "url_count": len(urls),
        },
    }
