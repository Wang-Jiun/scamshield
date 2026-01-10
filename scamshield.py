from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


# =========================
# Embedded data (keywords/templates)
# =========================

SCAM_KEYWORDS: Dict[str, List[str]] = {
    "urgency_threat": [
        "立即", "馬上", "立刻", "現在就", "最後通知", "限時", "逾期", "超時",
        "不配合", "不處理", "將", "會", "凍結", "停用", "封鎖", "提告", "告發",
        "刑責", "移送", "法院", "偵辦", "拘提", "扣押", "罰款"
    ],
    "transfer_payment": [
        "匯款", "轉帳", "匯入", "匯到", "匯至", "匯給", "刷流水",
        "點數", "遊戲點數", "購買點數", "儲值", "代充", "禮物卡", "序號",
        "ATM", "無卡", "超商繳費", "超商代碼", "繳費代碼",
        "掃碼", "QR", "收款碼", "轉錢", "打錢", "匯錢",
        "保證金", "解凍金", "手續費", "驗證金", "押金", "保證費"
    ],
    "otp_personal_info": [
        "驗證碼", "簡訊驗證碼", "OTP", "動態碼", "一次性密碼",
        "身分證", "身分證字號", "帳號", "密碼", "銀行帳號", "卡號", "信用卡",
        "CVV", "背面三碼", "有效期限", "戶頭", "存摺", "金融卡",
        "姓名", "生日", "住址", "地址", "電話", "手機號碼",
        "遠端", "遠端協助", "TeamViewer", "AnyDesk"
    ],
    "impersonation_authority": [
        "警察", "檢察官", "法院", "刑警", "調查局", "地檢署", "派出所",
        "銀行", "金管會", "客服", "官方客服", "系統通知", "資安", "風控",
        "蝦皮客服", "momo客服", "PChome客服", "LINE客服"
    ],
    "suspicious_link_download": [
        "點此", "連結", "網址", "下載", "安裝", "APP", "應用程式", "apk",
        "更新", "升級", "安全性更新", "驗證連結", "登入連結",
        "加入群", "投資群", "私訊我", "加LINE", "加賴", "加Telegram", "TG"
    ],
    "investment_scam": [
        "投資", "帶單", "老師", "助理", "內幕", "明牌", "保證獲利", "穩賺不賠",
        "高報酬", "高收益", "飆股", "配息", "套利", "群組", "跟單",
        "平台", "入金", "出金", "加碼", "補倉", "爆倉", "槓桿", "期貨", "外匯",
        "虛擬貨幣", "USDT", "比特幣", "BTC", "ETH"
    ],
    "romance_money": [
        "我愛你", "想你", "寶貝", "老公", "老婆", "靈魂伴侶",
        "遇到困難", "急用錢", "借我", "借錢", "周轉", "醫藥費", "住院", "手術費",
        "機票", "海關", "保釋", "保證金", "卡住", "帳戶被凍結", "先幫我", "我會還"
    ],
}

ACTIONS_BY_LEVEL: Dict[str, List[str]] = {
    "low": [
        "先別急著回覆，確認對方身份與來意。",
        "不要點擊不明連結或下載不明 App。",
        "涉及帳務改用官網/官方客服自行查詢（不要用對方給的電話或連結）。",
    ],
    "medium": [
        "停止提供任何個資、帳號、驗證碼、卡號等資訊。",
        "改用『你自己找得到的官方管道』回撥確認（例如銀行官網客服）。",
        "把對話截圖保存，必要時找可信任的人一起判斷。",
    ],
    "high": [
        "立刻停止匯款/購買點數/任何付款動作。",
        "若已提供驗證碼或密碼，立即改密碼並聯繫銀行/平台客服凍結風險操作。",
        "保存證據（對話、帳號、連結、匯款資訊），考慮報警或打 165 查證。",
    ],
    "critical": [
        "立即停止所有交易，並立刻聯繫銀行做止付/凍結/爭議處理。",
        "若已轉帳或買點數，立刻保留憑證、截圖，打 165 並就近報案。",
        "不要再與對方糾纏，所有聯絡改由官方/警方處理。",
    ],
}

REPLY_TEMPLATES: Dict[str, List[str]] = {
    "customer_service": [
        "我會透過官方網站/APP 的客服管道自行查詢，請勿再要求我提供驗證碼或遠端操作。",
        "若真有異常，請提供案件編號與可供我『自行查證』的官方資訊。",
        "我不會點擊任何連結或下載任何 App，請用正式公告或官方客服說明。",
        "我會保留對話紀錄並向 165 查證，謝謝。",
        "請勿再以『立刻處理/否則凍結』施壓，我只接受官方流程。",
    ],
    "transfer": [
        "我不會轉帳、買點數或提供任何付款資訊；若有需要請走正式平台流程。",
        "請提供正式帳單/合約與官方聯絡方式，我會自行向官方確認。",
        "任何要求我『立刻匯款』的訊息我都會先當成高風險處理。",
        "我會保留對話與收款資訊，必要時提供給 165/警方。",
        "請停止要求我付款或提供驗證碼。",
    ],
    "investment": [
        "我不接受保證獲利或帶單投資，請勿再邀我入群或提供平台連結。",
        "我會自行評估並透過合法券商/交易所操作，不會私下入金或提供個資。",
        "請不要再推『內幕/明牌/限時機會』，我不會跟單。",
        "任何要求轉帳到私人帳戶的投資邀約我都會直接拒絕。",
        "我會向 165 查證該平台/群組資訊。",
    ],
    "romance": [
        "我理解你的狀況，但我不會以轉帳/買點數方式協助金錢需求。",
        "如果真的需要幫忙，請你找身邊家人朋友或正式機構處理。",
        "任何『急用錢、保證金、解凍金』我都不會支付，請理解。",
        "我們可以聊，但金錢往來我一律拒絕。",
        "我會保留對話紀錄，避免誤會與風險。",
    ],
    "generic": [
        "我不會提供驗證碼、帳號密碼或任何個資，也不會點擊不明連結。",
        "請提供可供我自行查證的官方資訊，否則我會停止對話。",
        "我會保留對話紀錄並向 165 查證，謝謝。",
        "請勿催促我做任何付款或驗證動作。",
        "之後我只透過官方管道處理。",
    ],
}


# =========================
# Core: patterns / rules
# =========================

def sentence_split(text: str) -> List[str]:
    text = (text or "").replace("\r\n", "\n")
    parts = re.split(r"(?<=[。！？!?])\s+|\n+", text)
    sents = [p.strip() for p in parts if p and p.strip()]
    return sents or ([text.strip()] if text.strip() else [])


def compile_any(keywords: List[str]) -> re.Pattern:
    kws = [re.escape(k) for k in keywords if k]
    if not kws:
        return re.compile(r"(?!x)x")
    return re.compile("(" + "|".join(kws) + ")", re.IGNORECASE)


@dataclass(frozen=True)
class CompiledPatterns:
    urgency: re.Pattern
    transfer: re.Pattern
    otp: re.Pattern
    impersonation: re.Pattern
    suspicious: re.Pattern
    investment: re.Pattern
    romance: re.Pattern
    url: re.Pattern
    apk: re.Pattern


def build_patterns() -> CompiledPatterns:
    return CompiledPatterns(
        urgency=compile_any(SCAM_KEYWORDS["urgency_threat"]),
        transfer=compile_any(SCAM_KEYWORDS["transfer_payment"]),
        otp=compile_any(SCAM_KEYWORDS["otp_personal_info"]),
        impersonation=compile_any(SCAM_KEYWORDS["impersonation_authority"]),
        suspicious=compile_any(SCAM_KEYWORDS["suspicious_link_download"]),
        investment=compile_any(SCAM_KEYWORDS["investment_scam"]),
        romance=compile_any(SCAM_KEYWORDS["romance_money"]),
        url=re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE),
        apk=re.compile(r"\.apk\b|安裝.*app|下載.*app|側載|未知來源", re.IGNORECASE),
    )


@dataclass
class RuleHit:
    name: str
    score: int
    evidence_sentences: List[str]


def default_rules() -> List[Tuple[str, int, Any]]:
    # (name, weight, matcher(sentence, patterns)->bool)
    return [
        ("急迫恐嚇", 22, lambda s, p: bool(p.urgency.search(s))),
        ("要求匯款/點數", 28, lambda s, p: bool(p.transfer.search(s))),
        ("索取個資/驗證碼", 30, lambda s, p: bool(p.otp.search(s))),
        ("假冒權威/客服", 24, lambda s, p: bool(p.impersonation.search(s))),
        ("可疑連結/下載App", 24, lambda s, p: bool(p.suspicious.search(s) or p.url.search(s) or p.apk.search(s))),
        ("投資詐騙", 26, lambda s, p: bool(p.investment.search(s))),
        ("感情借錢", 26, lambda s, p: bool(p.romance.search(s))),
    ]


def score_to_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def pick_scenario(rule_names: List[str], text: str) -> str:
    t = (text or "").lower()
    names = set(rule_names)

    if "投資詐騙" in names:
        return "investment"
    if "感情借錢" in names:
        return "romance"
    if "假冒權威/客服" in names:
        return "customer_service"
    if "要求匯款/點數" in names:
        return "transfer"

    if any(k in t for k in ["投資", "獲利", "帶單", "usdt", "btc", "平台"]):
        return "investment"
    if any(k in t for k in ["寶貝", "想你", "借我", "急用錢", "醫藥費"]):
        return "romance"
    if any(k in t for k in ["客服", "銀行", "警察", "檢察官", "系統通知"]):
        return "customer_service"
    return "generic"


def build_explanation(level: str, rule_hits: List[RuleHit]) -> str:
    if not rule_hits:
        return "未觀察到明顯的詐騙話術特徵，但仍建議保持警覺、避免點擊不明連結。"

    top = sorted(rule_hits, key=lambda x: x.score, reverse=True)[:3]
    tags = "、".join([h.name for h in top])

    if level == "low":
        return f"文字中出現一些可疑訊號（{tags}），但整體風險偏低；建議先查證再回覆。"
    if level == "medium":
        return f"文字中有多個常見詐騙特徵（{tags}），風險中等；建議停止提供個資並改用官方管道查證。"
    if level == "high":
        return f"文字中出現高風險特徵（{tags}），很可能是詐騙；建議立刻停止付款/提供驗證碼並保存證據。"
    return f"文字中出現多項高危組合（{tags}），極可能是詐騙；請立即止付、保存證據並聯繫 165 或警方。"


def analyze_text(text: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    context = context or {}
    sentences = sentence_split(text)
    pat = build_patterns()

    hits: List[RuleHit] = []
    score = 0

    for (name, weight, matcher) in default_rules():
        ev = [s for s in sentences if matcher(s, pat)]
        if ev:
            hits.append(RuleHit(name=name, score=weight, evidence_sentences=ev[:4]))
            score += weight

    names = {h.name for h in hits}
    combo_hits: List[RuleHit] = []

    # Combo 1: 匯款 + 驗證碼 + 急迫 => 直接 critical
    if {"要求匯款/點數", "索取個資/驗證碼", "急迫恐嚇"}.issubset(names):
        combo_hits.append(RuleHit(
            name="高危組合：匯款 + 驗證碼 + 急迫",
            score=40,
            evidence_sentences=[s for s in sentences if (pat.transfer.search(s) or pat.otp.search(s) or pat.urgency.search(s))][:5]
        ))
        score = max(score, 95)

    # Combo 2: 權威冒充 + 驗證碼
    if {"假冒權威/客服", "索取個資/驗證碼"}.issubset(names):
        combo_hits.append(RuleHit(
            name="高危組合：假冒權威/客服 + 索取驗證碼",
            score=25,
            evidence_sentences=[s for s in sentences if (pat.impersonation.search(s) or pat.otp.search(s))][:5]
        ))
        score = max(score, 85)

    # Combo 3: 連結/下載 + 驗證碼
    if {"可疑連結/下載App", "索取個資/驗證碼"}.issubset(names):
        combo_hits.append(RuleHit(
            name="高危組合：連結/下載App + 索取驗證碼",
            score=20,
            evidence_sentences=[s for s in sentences if (pat.url.search(s) or pat.apk.search(s) or pat.otp.search(s))][:5]
        ))
        score = max(score, 80)

    if combo_hits:
        hits.extend(combo_hits)

    score = max(0, min(100, score))
    level = score_to_level(score)

    explanation = build_explanation(level, hits)
    recommended_actions = ACTIONS_BY_LEVEL[level]
    scenario = pick_scenario([h.name for h in hits], text)
    templates = REPLY_TEMPLATES.get(scenario, REPLY_TEMPLATES["generic"])
    reply_templates = templates[:3] if level in ("low", "medium") else templates[:5]

    return {
        "risk_score": score,
        "risk_level": level,
        "triggered_rules": [asdict(h) for h in sorted(hits, key=lambda x: x.score, reverse=True)],
        "explanation": explanation,
        "recommended_actions": recommended_actions,
        "reply_templates": reply_templates,
    }


def cli_main():
    p = argparse.ArgumentParser(description="ScamShield - rule-based 防詐文字分析器")
    p.add_argument("--text", type=str, default="", help='分析文字，例如 --text "..."')
    p.add_argument("--format", type=str, default="json", choices=["json"], help="輸出格式（單檔版先給 json）")
    args = p.parse_args()

    result = analyze_text(args.text)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    cli_main()
