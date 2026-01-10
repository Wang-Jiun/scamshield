from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# -----------------------------
# Utils
# -----------------------------
def _split_sentences(text: str) -> List[str]:
    t = (text or "").strip()
    if not t:
        return []
    # 先保留原文，但用常見標點切句
    parts = re.split(r"[。！？!\?\n\r]+", t)
    return [p.strip() for p in parts if p.strip()]


def _find_evidence_sentences(text: str, patterns: List[re.Pattern]) -> List[str]:
    sents = _split_sentences(text)
    hits: List[str] = []
    for s in sents:
        for p in patterns:
            if p.search(s):
                hits.append(s)
                break
    # 去重但保序
    seen = set()
    out = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out[:6]  # 最多給 6 句證據就好，太多很吵


def _cap(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


# -----------------------------
# Rules
# -----------------------------
@dataclass
class Rule:
    name: str
    score: int
    patterns: List[re.Pattern]
    types: List[str]  # 命中後加到 scam_types
    description: str


def _p(*keywords: str) -> List[re.Pattern]:
    # 把 keyword 變成 regex pattern（含一些空白容忍）
    ps: List[re.Pattern] = []
    for k in keywords:
        k = re.escape(k)
        ps.append(re.compile(k, re.IGNORECASE))
    return ps


# 常見詐騙特徵 pattern（簡化但實用）
RULES: List[Rule] = [
    Rule(
        name="急迫/恐嚇",
        score=18,
        patterns=[
            re.compile(r"立即|馬上|現在就|限時|最後通牒|倒數", re.IGNORECASE),
            re.compile(r"否則|不然|將.*(凍結|停用|提告|通緝|起訴)|法律責任", re.IGNORECASE),
            re.compile(r"(凍結|停用|封鎖).*(帳戶|帳號)|帳戶.*異常", re.IGNORECASE),
        ],
        types=["急迫恐嚇"],
        description="用恐嚇、凍結、起訴等字眼逼你立刻照做。",
    ),
    Rule(
        name="要求匯款/轉帳/點數",
        score=28,
        patterns=[
            re.compile(r"匯款|轉帳|匯入|入金|匯到|轉入", re.IGNORECASE),
            re.compile(r"點數|遊戲點數|序號|儲值|gift\s*card|禮物卡", re.IGNORECASE),
            re.compile(r"ATM|提款機|網銀|網路銀行", re.IGNORECASE),
        ],
        types=["匯款/點數"],
        description="要你用轉帳、點數、禮物卡等方式付款，風險超高。",
    ),
    Rule(
        name="索取驗證碼/個資",
        score=30,
        patterns=[
            re.compile(r"驗證碼|OTP|一次性密碼|簡訊碼", re.IGNORECASE),
            re.compile(r"身分證|證件|銀行卡|卡號|CVV|安全碼", re.IGNORECASE),
            re.compile(r"密碼|登入資料|帳號密碼", re.IGNORECASE),
        ],
        types=["索取個資/驗證碼"],
        description="要驗證碼、密碼、卡號這種，一律先當詐騙。",
    ),
    Rule(
        name="假冒權威（警/檢/銀行/客服）",
        score=22,
        patterns=[
            re.compile(r"警察|派出所|刑事局|檢察官|地檢署|法院", re.IGNORECASE),
            re.compile(r"銀行|金管會|客服|官方客服|專員|風控", re.IGNORECASE),
            re.compile(r"公務機關|政府|戶政|健保", re.IGNORECASE),
        ],
        types=["假冒權威"],
        description="假裝警察檢察官或銀行客服，製造權威感。",
    ),
    Rule(
        name="可疑連結/下載 App/遠端控制",
        score=20,
        patterns=[
            re.compile(r"http[s]?://|www\.", re.IGNORECASE),
            re.compile(r"下載|安裝|APP|應用程式|APK", re.IGNORECASE),
            re.compile(r"AnyDesk|TeamViewer|遠端|螢幕共享", re.IGNORECASE),
        ],
        types=["可疑連結/下載App"],
        description="要你點連結、裝 App、遠端協助，超常見套路。",
    ),
    Rule(
        name="投資/高報酬/保證獲利",
        score=26,
        patterns=[
            re.compile(r"保證獲利|穩賺|高報酬|翻倍|幾天回本|躺著賺", re.IGNORECASE),
            re.compile(r"投資|股票|期貨|虛擬貨幣|比特幣|USDT|合約", re.IGNORECASE),
            re.compile(r"老師帶單|內線|群組|VIP|拉你進群", re.IGNORECASE),
        ],
        types=["投資詐騙"],
        description="高報酬、保證獲利、帶單群組＝典型投資詐騙味。",
    ),
    Rule(
        name="感情詐騙/借錢",
        score=24,
        patterns=[
            re.compile(r"借錢|周轉|急用|醫藥費|住院|手術費", re.IGNORECASE),
            re.compile(r"我很愛你|唯一相信你|不要告訴別人|秘密", re.IGNORECASE),
            re.compile(r"見面前先|先匯|先幫我付", re.IGNORECASE),
        ],
        types=["感情借錢"],
        description="用感情綁架你掏錢或幫忙付費。",
    ),
]


# -----------------------------
# Combos (critical boosts)
# -----------------------------
def _combo_boost(text: str) -> Tuple[int, List[Dict[str, Any]]]:
    """回傳 (額外分數, 額外規則列表)"""
    t = text or ""
    has_transfer = bool(re.search(r"匯款|轉帳|點數|gift\s*card|禮物卡|ATM", t, re.IGNORECASE))
    has_otp = bool(re.search(r"驗證碼|OTP|一次性密碼|簡訊碼|密碼|卡號|CVV|安全碼", t, re.IGNORECASE))
    has_urgent = bool(re.search(r"立即|馬上|現在就|限時|否則|凍結|起訴|通緝", t, re.IGNORECASE))

    extras = []
    boost = 0

    if has_transfer and has_otp:
        boost += 25
        extras.append(
            {
                "name": "高危組合：匯款 + 驗證碼/個資",
                "score": 25,
                "evidence_sentences": _find_evidence_sentences(
                    t,
                    [re.compile(r"匯款|轉帳|點數|ATM|gift\s*card|禮物卡", re.IGNORECASE),
                     re.compile(r"驗證碼|OTP|密碼|卡號|CVV|安全碼", re.IGNORECASE)]
                ),
            }
        )

    if has_transfer and has_urgent:
        boost += 18
        extras.append(
            {
                "name": "高危組合：匯款 + 急迫恐嚇",
                "score": 18,
                "evidence_sentences": _find_evidence_sentences(
                    t,
                    [re.compile(r"匯款|轉帳|點數|ATM|gift\s*card|禮物卡", re.IGNORECASE),
                     re.compile(r"立即|馬上|限時|否則|凍結|起訴|通緝", re.IGNORECASE)]
                ),
            }
        )

    if has_otp and has_urgent:
        boost += 18
        extras.append(
            {
                "name": "高危組合：驗證碼/個資 + 急迫恐嚇",
                "score": 18,
                "evidence_sentences": _find_evidence_sentences(
                    t,
                    [re.compile(r"驗證碼|OTP|密碼|卡號|CVV|安全碼", re.IGNORECASE),
                     re.compile(r"立即|馬上|限時|否則|凍結|起訴|通緝", re.IGNORECASE)]
                ),
            }
        )

    return boost, extras


# -----------------------------
# Templates & Actions
# -----------------------------
ACTIONS = {
    "low": [
        "先冷靜，別急著回覆或點連結。",
        "用官方 App/官網自行登入查證，不要用對方給的連結。",
        "把訊息截圖留存，覺得怪就先封鎖。"
    ],
    "medium": [
        "先停止互動，不要提供任何個資/驗證碼。",
        "用官方客服電話/官網自行查證（不要用對方提供的）。",
        "必要時向 165 反詐騙諮詢或通報。"
    ],
    "high": [
        "立刻停止互動：不要匯款、不要給驗證碼、不要下載 App。",
        "如果已點連結或安裝 App，先關網路並移除可疑 App。",
        "聯絡銀行/電信官方管道確認是否有異常，並通報 165。"
    ],
    "critical": [
        "立即停止：不要再回、不要匯款、不要給任何驗證碼/個資。",
        "如果已轉帳/給碼：立刻聯絡銀行做緊急止付/凍結，並報警或通報 165。",
        "保留證據（對話、帳號、連結、收款資訊、交易明細）。"
    ],
}

TEMPLATES = {
    "假客服/銀行": [
        "我會自行透過銀行官方客服/官方 App 查證，不會在這裡提供任何資料。",
        "請提供你的分機/案件編號，我會用官方電話回撥確認。",
        "我不會提供驗證碼或密碼，請停止要求。"
    ],
    "匯款/點數": [
        "我不會匯款或購買任何點數/禮物卡，請不要再要求。",
        "如有問題我會自行向官方查證，請勿再催促。",
        "請提供正式公文/收據與公司登記資料（我會核對）。"
    ],
    "投資": [
        "我不接受任何保證獲利或帶單投資邀請，請勿再聯絡。",
        "請提供公司登記/投顧許可證號，我會自行查證。",
        "我不會加入任何投資群組或提供個資。"
    ],
    "感情借錢": [
        "我理解你很急，但我不會借錢或轉帳給網路認識的人。",
        "如果真的需要協助，請找家人朋友或正式社福管道。",
        "我不會用匯款/點數方式幫忙，請見諒。"
    ],
}


def _pick_templates(scam_types: List[str]) -> List[str]:
    # 粗略挑 3~5 句最符合的
    out: List[str] = []
    if "假冒權威" in scam_types:
        out += TEMPLATES["假客服/銀行"]
    if "匯款/點數" in scam_types or "索取個資/驗證碼" in scam_types:
        out += TEMPLATES["匯款/點數"]
    if "投資詐騙" in scam_types:
        out += TEMPLATES["投資"]
    if "感情借錢" in scam_types:
        out += TEMPLATES["感情借錢"]

    # 去重 + 取前 5
    seen = set()
    final = []
    for x in out:
        if x not in seen:
            seen.add(x)
            final.append(x)
    if not final:
        final = [
            "我會用官方管道自行查證，不會在這裡提供任何資料。",
            "我不會匯款、提供驗證碼或點連結，請不要再要求。",
            "如需聯絡，請提供正式資訊，我會自行向官方確認。"
        ]
    return final[:5]


def _level_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


# -----------------------------
# Public API: analyze_text
# -----------------------------
def analyze_text(text: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    回傳格式（穩定）：
    {
      "risk_score": int,
      "risk_level": "low|medium|high|critical",
      "scam_types": [str],
      "triggered_rules": [{"name": str, "score": int, "evidence_sentences": [str]}],
      "explanation": str,
      "recommended_actions": [str],
      "reply_templates": [str],
    }
    """
    _ = context  # 第一版先保留，未使用

    t = (text or "").strip()
    if not t:
        return {
            "risk_score": 0,
            "risk_level": "low",
            "scam_types": [],
            "triggered_rules": [],
            "explanation": "沒有提供內容，無法分析。",
            "recommended_actions": ACTIONS["low"],
            "reply_templates": _pick_templates([]),
        }

    total = 0
    triggered: List[Dict[str, Any]] = []
    scam_types: List[str] = []

    for rule in RULES:
        evid = _find_evidence_sentences(t, rule.patterns)
        if evid:
            total += rule.score
            triggered.append(
                {
                    "name": rule.name,
                    "score": rule.score,
                    "evidence_sentences": evid,
                }
            )
            for tp in rule.types:
                if tp not in scam_types:
                    scam_types.append(tp)

    boost, extra_rules = _combo_boost(t)
    if boost:
        total += boost
        triggered.extend(extra_rules)

    risk_score = _cap(total, 0, 100)
    risk_level = _level_from_score(risk_score)

    # 解釋：不要太長，讓人一眼懂
    if risk_level in ("high", "critical"):
        explain = "這段訊息同時出現多個高風險特徵（例如：急迫恐嚇、匯款/點數、索取驗證碼或假冒權威），非常像詐騙流程。"
    elif risk_level == "medium":
        explain = "訊息有一些詐騙常見語氣/要求（例如要你快點做、或提到帳戶異常/連結），建議用官方管道查證後再處理。"
    else:
        explain = "目前看起來沒有明顯高危要求，但仍建議不要點不明連結、不要提供個資，必要時用官方管道確認。"

    actions = ACTIONS[risk_level]
    templates = _pick_templates(scam_types)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "scam_types": scam_types,
        "triggered_rules": triggered,
        "explanation": explain,
        "recommended_actions": actions,
        "reply_templates": templates,
    }
