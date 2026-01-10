from __future__ import annotations

import re
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# =========================
# Lv2 Core: Rule Engine
# =========================

@dataclass
class Rule:
    name: str
    score: int
    stage: str  # 用來判斷詐騙流程階段
    scam_types: List[str]
    patterns: List[re.Pattern]


def _compile(patterns: List[str]) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


RULES: List[Rule] = [
    # --- 急迫 / 恐嚇 ---
    Rule(
        name="急迫/限時催促",
        score=18,
        stage="製造恐慌",
        scam_types=["急迫恐嚇"],
        patterns=_compile([
            r"立即|馬上|立刻|現在就|限時|倒數|最後機會|今天內|立刻處理|緊急|急件",
            r"不處理.*(凍結|停用|封鎖)|否則.*(凍結|停用|封鎖)",
        ]),
    ),
    Rule(
        name="帳戶異常/凍結威脅",
        score=22,
        stage="製造恐慌",
        scam_types=["冒充機構", "急迫恐嚇"],
        patterns=_compile([
            r"帳戶.*異常|登入.*異常|交易.*異常|安全性.*異常",
            r"(凍結|停用|封鎖|鎖定).*(帳戶|帳號|卡片)",
        ]),
    ),

    # --- 連結 / 釣魚 ---
    Rule(
        name="連結誘導/釣魚",
        score=25,
        stage="要求行動",
        scam_types=["釣魚連結"],
        patterns=_compile([
            r"https?://\S+",
            r"點擊|點開|按這裡|連結|網址|進入.*網站|驗證頁面|查詢頁面",
            r"短網址|bit\.ly|tinyurl|reurl\.cc|ppt\.cc",
        ]),
    ),

    # --- 要求敏感資訊 ---
    Rule(
        name="索取驗證碼/OTP",
        score=30,
        stage="索取敏感資訊",
        scam_types=["驗證碼詐騙", "冒充機構"],
        patterns=_compile([
            r"驗證碼|OTP|一次性密碼|動態密碼|簡訊碼|認證碼",
            r"把.*(驗證碼|OTP).*(給我|回傳|提供)|提供.*(驗證碼|OTP)",
        ]),
    ),
    Rule(
        name="索取個資/帳密",
        score=28,
        stage="索取敏感資訊",
        scam_types=["個資詐騙", "釣魚連結"],
        patterns=_compile([
            r"帳號|帳密|密碼|身分證|身份證|生日|銀行帳戶|卡號|CVV|安全碼",
            r"拍.*(身分證|身份證)|提供.*(卡號|安全碼|CVV)",
        ]),
    ),

    # --- 匯款 / 金錢 ---
    Rule(
        name="要求匯款/轉帳/充值",
        score=32,
        stage="催促付款",
        scam_types=["匯款詐騙"],
        patterns=_compile([
            r"匯款|轉帳|匯入|入金|充值|儲值|繳費|付款",
            r"提供.*帳戶|給你.*帳號|匯到.*帳號",
        ]),
    ),
    Rule(
        name="禮物卡/點數卡",
        score=26,
        stage="催促付款",
        scam_types=["點數卡詐騙"],
        patterns=_compile([
            r"點數卡|禮物卡|遊戲點數|序號|刮刮卡|GASH|MyCard|Apple\s*Gift|Google\s*Play",
        ]),
    ),

    # --- 冒充機構 ---
    Rule(
        name="冒充銀行/客服/公務機關",
        score=24,
        stage="建立信任",
        scam_types=["冒充機構"],
        patterns=_compile([
            r"銀行|客服|金管會|警察|檢察官|法院|戶政|監理站|電信|郵局",
            r"官方|專員|案件|通緝|涉案|偵查|筆錄",
        ]),
    ),

    # --- 投資 / 高報酬 ---
    Rule(
        name="投資高報酬/帶單",
        score=27,
        stage="建立信任",
        scam_types=["投資詐騙"],
        patterns=_compile([
            r"高報酬|保證獲利|穩賺不賠|內線|帶單|老師|群組|入群|名額",
            r"比特幣|BTC|USDT|虛擬幣|加密貨幣|錢包地址",
        ]),
    ),

    # --- 求職 / 兼差 ---
    Rule(
        name="求職/兼差/代收代付",
        score=22,
        stage="建立信任",
        scam_types=["求職詐騙"],
        patterns=_compile([
            r"高薪|兼職|打工|在家工作|日領|免經驗|快速上手",
            r"代收|代付|跑分|刷流水|人頭帳戶",
        ]),
    ),

    # --- 感情 / 交友 ---
    Rule(
        name="交友/感情誘導",
        score=18,
        stage="建立信任",
        scam_types=["交友詐騙"],
        patterns=_compile([
            r"交友|戀愛|寶貝|想你|信任你|私密照|裸照|視訊",
            r"投資一起|幫你賺|只有你知道",
        ]),
    ),
]


STAGE_ORDER = [
    "建立信任",
    "製造恐慌",
    "要求行動",
    "索取敏感資訊",
    "催促付款",
]

RISK_LEVELS = [
    ("low", 0),
    ("medium", 35),
    ("high", 65),
    ("critical", 85),
]


def _split_sentences(text: str) -> List[str]:
    text = (text or "").strip()
    if not text:
        return []
    # 先把換行當分隔，再用常見標點拆句
    chunks = re.split(r"[\n\r]+", text)
    out: List[str] = []
    for ch in chunks:
        ch = ch.strip()
        if not ch:
            continue
        # 句號、驚嘆、問號、分號、頓號、逗號…都拆，但保留內容
        parts = re.split(r"[。！？!?；;]+", ch)
        for p in parts:
            p = p.strip()
            if p:
                out.append(p)
    # 太長句子再保底切一下
    final: List[str] = []
    for s in out:
        if len(s) <= 120:
            final.append(s)
        else:
            # 以逗號/頓號再切
            subs = re.split(r"[，,、]+", s)
            for sub in subs:
                sub = sub.strip()
                if sub:
                    final.append(sub)
    return final


def _risk_level(score: int) -> str:
    lvl = "low"
    for name, threshold in RISK_LEVELS:
        if score >= threshold:
            lvl = name
    return lvl


def _pick_stage(stage_scores: Dict[str, int]) -> str:
    # 依照流程順序挑「最高優先 + 有分數」的 stage
    for st in reversed(STAGE_ORDER):
        if stage_scores.get(st, 0) > 0:
            return st
    return "建立信任"


def _stable_share_id(text: str) -> str:
    # 不用存資料也能產一個穩定 id（同一段文字會得到同一個 id）
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return h[:10]


def analyze_text(text: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Lv2: 回傳仍相容你目前 webapp.py 的 AnalyzeResponse
    - risk_score, risk_level, scam_types, triggered_rules, explanation, recommended_actions, reply_templates
    另外額外附上：
    - conversation, score_breakdown, current_stage, share_id
    """

    raw = (text or "").strip()
    sentences = _split_sentences(raw)

    # 若只有一句也 OK
    if not sentences and raw:
        sentences = [raw]

    total_score = 0
    scam_type_set = set()
    stage_scores: Dict[str, int] = {st: 0 for st in STAGE_ORDER}

    # rule_name -> {score, evidence_sentences(set)}
    agg: Dict[str, Dict[str, Any]] = {}
    breakdown: Dict[str, int] = {}  # rule -> score (累積)
    conversation: List[Dict[str, Any]] = []

    for s in sentences:
        s_score = 0
        s_rules: List[str] = []
        s_stage = None

        for rule in RULES:
            hit = any(p.search(s) for p in rule.patterns)
            if not hit:
                continue

            s_score += rule.score
            s_rules.append(rule.name)

            # 聚合 evidence
            if rule.name not in agg:
                agg[rule.name] = {
                    "name": rule.name,
                    "score": rule.score,
                    "evidence_sentences": set(),
                    "stage": rule.stage,
                    "scam_types": set(rule.scam_types),
                }
            agg[rule.name]["evidence_sentences"].add(s)
            agg[rule.name]["scam_types"].update(rule.scam_types)

            # breakdown（同一規則多次命中就累積）
            breakdown[rule.name] = breakdown.get(rule.name, 0) + rule.score

            # stage 統計
            stage_scores[rule.stage] = stage_scores.get(rule.stage, 0) + rule.score
            s_stage = rule.stage

            # scam types
            scam_type_set.update(rule.scam_types)

        total_score += s_score

        if s_rules:
            conversation.append({
                "text": s,
                "score": s_score,
                "stage": s_stage or "建立信任",
                "rules": s_rules,
            })

    # 分數上限保底（避免爆表到 9999）
    total_score = max(0, min(100, total_score))
    level = _risk_level(total_score)
    current_stage = _pick_stage(stage_scores)

    # triggered_rules（給你 UI 進階區用）
    triggered_rules = []
    # 按規則累積分數排序（高的先）
    for name, _ in sorted(breakdown.items(), key=lambda x: x[1], reverse=True):
        info = agg.get(name)
        if not info:
            continue
        triggered_rules.append({
            "name": info["name"],
            "score": info["score"],
            "evidence_sentences": sorted(list(info["evidence_sentences"]))[:8],  # 控制長度
        })

    scam_types = sorted(list(scam_type_set))

    # 說明與建議（依 level + stage + types）
    explanation = _make_explanation(total_score, level, current_stage, scam_types)
    recommended_actions = _make_actions(level, scam_types)
    reply_templates = _make_templates(level, scam_types)

    result: Dict[str, Any] = {
        # === 相容你現有 AnalyzeResponse ===
        "risk_score": int(total_score),
        "risk_level": level,
        "scam_types": scam_types,
        "triggered_rules": triggered_rules,
        "explanation": explanation,
        "recommended_actions": recommended_actions,
        "reply_templates": reply_templates,

        # === Lv2 額外資訊（先回傳，之後再把前端接上） ===
        "current_stage": current_stage,
        "score_breakdown": [{"rule": k, "score": v} for k, v in sorted(breakdown.items(), key=lambda x: x[1], reverse=True)],
        "conversation": sorted(conversation, key=lambda x: x["score"], reverse=True)[:12],
        "share_id": _stable_share_id(raw) if raw else "na",
    }
    return result


def _make_explanation(score: int, level: str, stage: str, types: List[str]) -> str:
    if score >= 85:
        return f"這段訊息同時命中多個高風險特徵，整體非常像詐騙流程（目前階段：{stage}）。建議你先停手，不要照對方指示做任何操作。"
    if score >= 65:
        return f"看起來有明顯的詐騙特徵（目前階段：{stage}），尤其是：{('、'.join(types[:3]) if types else '多項可疑規則')}。先不要點連結或提供任何資料。"
    if score >= 35:
        return f"有一些可疑點（目前階段：{stage}）。不一定百分百詐騙，但建議用官方管道自行查證，不要被對方牽著走。"
    return "目前看起來沒有明顯高危要求，但仍建議保持警覺：不要亂點連結、不要提供個資，有疑慮就走官方管道查證。"


def _make_actions(level: str, types: List[str]) -> List[str]:
    base = [
        "先冷靜：先不要回、不要點連結、不要照指示操作。",
        "用官方 App/官網自行登入查證（不要用對方給的連結）。",
        "把對話截圖保存；覺得怪就先封鎖。"
    ]
    if level in ("high", "critical"):
        base = [
            "立即停止：不要回、不要匯款、不要提供任何驗證碼/個資。",
            "如果涉及帳戶/金錢：立刻用官方客服或 165 反詐騙專線查證。",
            "保留證據：對話、帳號、連結、收款資訊全部截圖保存。"
        ]
    # 類型加強
    if "釣魚連結" in types:
        base.append("若你已點過連結或輸入過資料：立刻改密碼、開啟雙重驗證，並通知相關平台。")
    if "投資詐騙" in types:
        base.append("投資群組/老師/帶單：先假設是詐騙，別轉帳、別入金、別下載不明 App。")
    if "求職詐騙" in types:
        base.append("遇到代收代付/跑分/刷流水：直接拒絕，這很容易變成人頭帳戶。")
    return base


def _make_templates(level: str, types: List[str]) -> List[str]:
    tpls = [
        "我會自行透過官方管道確認，不會透過連結或在這裡提供任何資料。",
        "請提供正式公文/公司資訊與可回撥的官方電話，否則我不再回應。",
        "我不會匯款、提供驗證碼或個資，請勿再要求。"
    ]
    if level in ("high", "critical"):
        tpls = [
            "我已透過官方管道查證，請勿再聯絡；再騷擾我會直接報警/通報 165。",
            "我不會點任何連結、不會提供驗證碼或個資；請停止要求。",
            "請用正式公文與官方客服流程處理，我只接受官方管道聯繫。"
        ]
    if "投資詐騙" in types:
        tpls.append("我不加入投資群組/不跟單/不入金，請不要再推銷或拉我進群。")
    if "交友詐騙" in types:
        tpls.append("我不會轉帳、買點數卡或借錢；請不要再用情緒或理由施壓。")
    return tpls
