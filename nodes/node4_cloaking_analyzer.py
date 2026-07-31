"""
node4_cloaking_analyzer.py  分析（靜態偵測 → 動態雙瀏覽器驗證）
合併 靜態特徵偵測 與 雙重 Playwright 動態驗證
兩者共同目標皆為「確認 cloaking」，靜態結果作為動態驗證的前置依據。

靜態部分基於 "Cloak of Visibility" (Invernizzi et al., IEEE S&P 2016) 特徵庫。
動態部分使用強化版雙重 Playwright 瀏覽器模擬 (v3)：

  BOT 強化暴露（讓 cloaking JS 更容易觸發）：
  ① 主動注入 BOT 特徵 JS（webdriver=true / plugins=0 / languages=[] ...）
  ② 奇怪 Viewport (1024×768)、無 Accept-Language、無 Cookie
  ③ 保留 AutomationControlled 旗標（不隱藏）

  HUMAN 完整修補（讓 HUMAN 儘量通過 fingerprint 檢查）：
  ④ Canvas/WebGL/Audio 假指紋注入
  ⑤ 15 個 CDP / headless 洩漏點修補
     新增: Notification.permission / mediaDevices / hasFocus /
           performance.memory / CSS hover / screen.colorDepth
  ⑥ Google 預熱 Session + Referer 鏈
  ⑦ 貝茲曲線滑鼠軌跡 + 分段閱讀捲動

  網路層防識破：
  ⑧ Proxy 支援（可選）— 設定 PROXY_URL 環境變數啟用住宅代理
     格式: http://user:pass@host:port  或  socks5://host:port
  ⑨ curl_cffi TLS 指紋偽裝（可選）— 安裝後自動啟用
     pip install curl_cffi
     讓初始 HTTP 請求的 JA3/JA4 指紋與真實 Chrome 一致，
     取代 python-requests 的 Python TLS 指紋
"""
import os
import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import re
import json
import time
import math
import random
import hashlib
import difflib
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor

from state import AnalysisState
# Cloaking 判定沿用 Node 3 的釣魚判準 —— 兩處必須是同一個實作，
# 否則「BOT 沒有惡意機制、HUMAN 有」這句話在兩個節點會有不同意思。
from nodes.node3_phishing_classifier import evaluate_page
# 爬取層已抽到 dual_crawler.py —— Node 1 負責取得兩份頁面，
# 本節點只負責「比對」，不再自己爬。
from nodes.dual_crawler import MAX_CONTENT_LEN

logger = logging.getLogger(__name__)

# ── 靜態偵測 ──────────────────────────────────────────────────
# 定位：偵測「Naive Frontend Cloaking JS」——把 bot 偵測直接寫死在前端的網站。
#      不取代動態驗證；動態爬取失敗時，這是唯一還能講話的證據來源。
#
# 舊版是加權制（門檻 0.40，各類別 0.08~0.30）。改成布林的原因：
#   那些權重沒有任何資料依據，而且門檻要不斷往上調來壓誤報 ——
#   0.20 → 0.40 的調整就是在跟 navigator.userAgent / document.referrer /
#   location.href 這些「合法網站到處都是」的模式賽跑。真正的問題不是門檻高低，
#   是把統計性特徵和高特異性特徵混在同一個加總裡。
#
# ── 布林分組 ────────────────────────────────────────
#
# 前端 cloaking 的定義是「偵測環境 → 依結果改變使用者看到的東西」。
# 兩半都不能單獨成立：
#   單獨偵測不是 cloaking —— anti-bot SDK（DataDome / PerimeterX）、
#     RWD、analytics、React DevTools hook 全都在偵測環境。
#   單獨跳轉也不是 cloaking —— SPA 路由、地區導向都會跳轉。
# 所以每條規則都是連言，沒有任何門檻分數。
_CRAWLER_ARTIFACTS = {          # 爬蟲框架注入的專屬識別符（高特異性）
    "automation_detection", "headless_feature_check",
}
# 一般性環境偵測：記錄為證據，但「不參與裁決」。
# 這批是統計性特徵，跟 Node 3 的 URL 詞彙特徵同一類 —— 合法網站大量使用
#   （RWD 用 screen.width、analytics 用 document.referrer、
#     每個 React 站都有 __REACT_DEVTOOLS_GLOBAL_HOOK__、hover 效果用 mousemove），
# 布林化只會把「現代網站」判成 cloaking。單獨或組合都不足以裁決。
_GENERIC_PROBES = {
    "user_agent_check", "referrer_check", "screen_size_gate",
    "ip_geo_check", "devtools_detection", "mouse_behavior_gate",
}
_COND_FINGERPRINT = {           # pattern 內部已含 bot 條件，本身就是連言
    "fingerprint_conditional",
}
_EVASION_ACTIONS = {            # 依偵測結果改變行為
    "javascript_redirect", "time_based_evasion",
}

# (id, [(分組, 最少命中類別數), ...], 說明)
STATIC_CLOAKING_RULES = [
    ("S1", [(_CRAWLER_ARTIFACTS, 1), (_EVASION_ACTIONS, 1)],
     "爬蟲框架洩漏識別符 + 差異化跳轉"),
    ("S2", [(_COND_FINGERPRINT, 1), (_EVASION_ACTIONS, 1)],
     "指紋條件分流 + 差異化跳轉"),
    ("S3", [(_CRAWLER_ARTIFACTS, 1), (_COND_FINGERPRINT, 1)],
     "爬蟲偵測 + 指紋條件分流（偵測到就換內容，不需跳轉）"),
]

# Cloaking 技術特徵庫 (來源: Cloak of Visibility, IEEE S&P 2016)
CLOAKING_SIGNATURES = {
    "user_agent_check": {
        "patterns": [
            r"navigator\.userAgent",
            r"userAgent\.indexOf",
            r"userAgent\.match",
            r"/googlebot/i",
            r"/bingbot/i",
            r"/crawler/i",
            r"/spider/i",
            r"bot.{0,50}test\s*\("
        ]
    },
    "referrer_check": {
        "patterns": [
            r"document\.referrer",
            r"HTTP_REFERER",
            r"referer\.includes",
            r"referer\.match"
        ]
    },
    "automation_detection": {
        "patterns": [
            r"navigator\.webdriver",
            r"window\._phantom",
            r"window\.callPhantom",
            r"__selenium",
            r"__webdriver",
            r"navigator\.plugins\.length\s*===?\s*0",
            r"screen\.width\s*===?\s*0",
            r"screen\.height\s*===?\s*0",
            r"window\.outerWidth\s*===?\s*0",
            r"window\.outerHeight\s*===?\s*0",
            r"navigator\.languages\.length\s*===?\s*0",
            r"document\.__\$webdriverAsyncExecutor"
        ]
    },
    "fingerprint_conditional": {
        "patterns": [
            r"canvas.{0,50}if\s*\(",
            r"toDataURL.{0,50}===",
            r"getImageData.{0,50}compare",
            r"WebGL.{0,50}if\s*\(",
            r"knownBot.{0,50}fingerprint",
            r"fp.{0,50}===.{0,50}bot"
        ]
    },
    "javascript_redirect": {
        "patterns": [
            r"window\.location\s*=\s*['\"]http",
            r"location\.replace\s*\(\s*['\"]http",
            r"location\.href\s*=\s*['\"]http",
            r"document\.location\s*="
        ]
    },
    "time_based_evasion": {
        "patterns": [
            r"setTimeout\s*\(.{0,100}location",
            r"setInterval\s*\(.{0,100}location",
            r"setTimeout\s*\(.{0,100}inject",
            r"delay.{0,50}redirect"
        ]
    },
    "screen_size_gate": {
        "patterns": [
            r"screen\.width\s*[<>]=?\s*\d+",
            r"screen\.height\s*[<>]=?\s*\d+",
            r"window\.innerWidth\s*[<>]=?\s*\d+",
            r"window\.innerHeight\s*[<>]=?\s*\d+"
        ]
    },
    "ip_geo_check": {
        "patterns": [
            r"geoip", r"ip2location",
            r"ip_address", r"remote_addr",
            r"cloudflare.{0,50}country",
            r"CF-IPCountry"
        ]
    },
    # ── 現代 Cloaking 手法（2023-2025 新增）─────────────────
    # 來源: Breaking the Shield (WWW 2025), CrawlPhish evasion section
    "devtools_detection": {
        "patterns": [
            r"devtools",
            r"firebug",
            r"__REACT_DEVTOOLS",
            r"window\.devtools",
            r"setInterval.{0,50}debugger",        # 持續觸發 debugger 暫停 devtools
            r"toString.{0,50}length.{0,50}>.{0,50}devtools", # devtools 開啟時 toString 回傳不同長度
        ]
    },
    "headless_feature_check": {
        "patterns": [
            r"document\.documentElement\.webdriver",
            r"navigator\.brave",
            r"chrome\.app\.isInstalled",
            r"outerHeight\s*===?\s*0",        # headless 下 outerHeight 為 0
            r"outerWidth\s*===?\s*0",
            r"window\.__nightmare",           # Nightmare.js 爬蟲標記
            r"window\.domAutomation",         # Selenium 注入旗標
            r"window\.__cdc_",               # ChromeDriver 注入的全域變數 (window.__cdc_asdjflasutopfhvcZLmcfl_)
        ]
    },
    "mouse_behavior_gate": {
        "patterns": [
            r"addEventListener\s*\(\s*['\"]mousemove",   # 等待滑鼠移動才展示內容
            r"onmousemove\s*=",
            r"mousemove.{0,50}show",
            r"mouse.{0,50}interaction.{0,50}require",
            r"window\.addEventListener.{0,100}mouse.{0,100}\{[^}]*redirect", # 滑鼠互動觸發重導向
        ]
    }
}

# 預編譯所有 Cloaking regex（模組載入時只做一次）
_CLOAKING_RE: dict = {
    tech: [re.compile(p, re.IGNORECASE) for p in rule["patterns"]]
    for tech, rule in CLOAKING_SIGNATURES.items()
}


# ─────────────────────────────────────────────────────────────
# 靜態 Cloaking 偵測
# ─────────────────────────────────────────────────────────────
def _static_detect(state: AnalysisState, llm) -> tuple:
    """
    Naive Frontend Cloaking JS 偵測：前端直接寫死的 bot 偵測 → 差異化邏輯。
    純布林（STATIC_CLOAKING_RULES 連言），無門檻分數。
    動態驗證失敗時，這是唯一還能講話的證據來源。

    回傳: (cloaking_detected, techniques_found)
    """
    all_js   = "\n".join(s["deobfuscated"] for s in state["deobfuscated_js"])
    combined = all_js + "\n" + state["raw_html"]

    # ── 命中哪些技術類別 ──────────────────────────────────────
    techniques_found = {}
    for technique, compiled_patterns in _CLOAKING_RE.items():
        hits = [pat.pattern for pat in compiled_patterns if pat.search(combined)]
        if hits:
            techniques_found[technique] = hits
            print(f"  → [靜態:{technique}] {len(hits)} 個特徵命中", flush=True)
    hit_categories = set(techniques_found)

    # ── LLM 補充：聚焦 Naive Frontend Cloaking JS ─────────────
    # 注意：LLM 只被要求分析「前端 JS 中明確可見的 bot 偵測邏輯」，
    # 不要求推測 server-side 分流（那是動態驗證的責任）。
    js_snippet = all_js[:2000]
    prompt = (
        "Analyze this JavaScript for NAIVE FRONTEND CLOAKING patterns only.\n"
        "Naive frontend cloaking = bot detection logic explicitly written in client-side JS,\n"
        "such as: checking navigator.webdriver, navigator.plugins.length===0,\n"
        "window.__phantom, conditional redirects based on user-agent strings,\n"
        "or fingerprint-based content switching visible in the source code.\n\n"
        "DO NOT guess at server-side cloaking (IP checks, backend logic).\n"
        "Only flag what is EXPLICITLY visible in the JavaScript below.\n"
        "All output must be in English.\n\n"
        f"JavaScript:\n{js_snippet}\n\n"
        "Respond ONLY in JSON (no markdown):\n"
        '{"naive_cloaking_detected": true/false,\n'
        '  "techniques": ["technique1"],\n'
        '  "confidence": 0.0-1.0,\n'
        '  "explanation": "one sentence in English"}'
    )

    # 靜態 LLM 是佐證，不能單獨裁決：LLM 對「有沒有 cloaking」的布林判斷
    # 容易被一般的 bot 防護程式碼誤導，所以只有在規則層也看到偵測類別時才採信。
    # ⚠ 此 timeout 必須 ≥ main.py 中 llm_cloak 的 API timeout（目前 300s），
    #   否則 future.result() 會先放棄，而 API 還在推理中。
    #   先前設 60s 導致 gemma4:e4b 批次中 57/125 筆 Node4 錯誤
    #   （concurrent.futures.TimeoutError 的 str() 是空字串，所以 log 只顯示
    #    "[Node4-static] LLM error: " 後面沒有任何訊息）。
    _STATIC_LLM_TIMEOUT = 310
    llm_says_cloaking = False
    print(f"  → [靜態:LLM] 呼叫中（timeout={_STATIC_LLM_TIMEOUT}s）...", flush=True)
    try:
        _llm_executor = ThreadPoolExecutor(max_workers=1)
        try:
            future = _llm_executor.submit(llm.invoke, prompt)
            llm_response = future.result(timeout=_STATIC_LLM_TIMEOUT)
        finally:
            _llm_executor.shutdown(wait=False)
        json_match = re.search(r'\{[^{}]*"naive_cloaking_detected"[^{}]*\}', llm_response, re.DOTALL)
        if not json_match:
            json_match = re.search(r'\{.*\}', llm_response, re.DOTALL)
        if json_match:
            llm_result = json.loads(json_match.group())
            llm_says_cloaking = bool(llm_result.get("naive_cloaking_detected", False))
            for t in llm_result.get("techniques", []):
                techniques_found.setdefault("llm_detected", []).append(t)
            print(f"  → [靜態:LLM] naive_cloaking={llm_says_cloaking} | "
                  f"{llm_result.get('explanation', '')[:80]}", flush=True)
    except Exception as e:
        err_type = type(e).__name__
        err_msg  = str(e) or "(no message)"
        print(f"  → [靜態:LLM] 跳過（{err_type}: {err_msg}）", flush=True)
        errs = state.get("errors", [])
        errs.append(f"[Node4-static] LLM error ({err_type}): {err_msg}")
        state["errors"] = errs

    # ── 布林裁決 ──────────────────────────────────────────────
    fired = []
    for rule_id, requirements, label in STATIC_CLOAKING_RULES:
        if all(len(group & hit_categories) >= n for group, n in requirements):
            fired.append(rule_id)
            techniques_found.setdefault("static_rule", []).append(f"[{rule_id}] {label}")
            print(f"  → [靜態:布林裁決] {rule_id}: {label}", flush=True)

    # S4：LLM 說有，且規則層也看到高特異性偵測 → 採信
    #     佐證只認爬蟲框架洩漏與指紋條件分流；一般性偵測不算佐證，
    #     否則等於讓 LLM 對任何現代網站都能單方面裁決。
    if llm_says_cloaking and not fired and (
            hit_categories & (_CRAWLER_ARTIFACTS | _COND_FINGERPRINT)):
        fired.append("S4")
        techniques_found.setdefault("static_rule", []).append(
            "[S4] LLM 判定有 cloaking JS，且規則層有高特異性偵測佐證")
        print("  → [靜態:布林裁決] S4: LLM + 高特異性偵測佐證", flush=True)

    return bool(fired), techniques_found


def _simhash(text: str, bits: int = 64) -> int:
    if not text:
        return 0
    tokens = [text[i:i+4] for i in range(len(text) - 3)]
    v = [0] * bits
    for t in tokens:
        h = int(hashlib.md5(t.encode("utf-8", errors="ignore")).hexdigest(), 16)
        for i in range(bits):
            v[i] += 1 if (h >> i) & 1 else -1
    return sum(1 << i for i in range(bits) if v[i] > 0)


def _similarity_score(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    sh_sim  = 1.0 - bin(_simhash(a) ^ _simhash(b)).count("1") / 64.0
    seq_sim = difflib.SequenceMatcher(None, a[:5000], b[:5000]).ratio()
    return sh_sim * 0.6 + seq_sim * 0.4


def _redirect_forked(chain_a: list, chain_b: list) -> bool:
    def domain(url):
        m = re.search(r"https?://([^/]+)", url)
        return m.group(1) if m else url
    return bool(chain_a and chain_b and domain(chain_a[-1]) != domain(chain_b[-1]))


def _assess_dynamic_reliability(bot_result: dict, human_result: dict) -> str:
    """
    評估這次動態爬取結果的可信度。

    回傳三個等級:
      "HIGH"        — HUMAN 瀏覽器確實以正常用戶身份完成訪問，結果可信
                      → 若兩頁面相同，可以確認「無 Cloaking」
      "LOW"         — HUMAN 爬取流程有缺陷 (預熱失敗 / 載入過快)，
                      頁面相同可能只代表兩者都被識破，不能確認無 Cloaking
      "FAILED"      — BOT 或 HUMAN 其中一方完全失敗，無法進行有效比對

    判斷依據（v2 三段式）:
      FAILED  : 任一方有 error，或兩方 text_content 都是空的，
                或 HUMAN 耗時 < 3s（頁面根本未完整載入，JS fingerprint 未執行）
      LOW     : HUMAN 預熱失敗，或耗時 < 6s（prewarm ~2-4s + JS ~1-2s，合計至少 6s）
      HIGH    : 以上都不成立
    """
    if bot_result.get("error") or human_result.get("error"):
        return "FAILED"
    if not bot_result.get("text_content") and not human_result.get("text_content"):
        return "FAILED"
    human_time = human_result.get("fetch_time_sec", 99)
    # < 3s: 幾乎確定頁面未完整載入（prewarm 本身需 ~2s），視同 FAILED
    if human_time < 3.0:
        return "FAILED"
    # 預熱失敗：HUMAN 沒有 Google session，fingerprint check 可能失敗
    if not human_result.get("prewarm_ok"):
        return "LOW"
    # < 6s：prewarm(2-4s) + JS fingerprint(1-2s)，不足以確認通過所有檢查
    if human_time < 6.0:
        return "LOW"
    return "HIGH"


def decide_cloaking(bot_result: dict, human_result: dict, url: str) -> dict:
    """
    純函式：比對 BOT 與 HUMAN 兩次爬取，判定是否為 Cloaking。全布林，無加權無閾值。

    判準沿用 Node 3 的釣魚偵測（evaluate_page），對兩份 HTML 各跑一次，
    比的是「惡意機制的有無」，不是文字長得像不像。Cloaking 的定義本來就是
    「同一個 URL 對爬蟲和對真人給不同東西」，機制集合差就是這句話的直譯。

    為什麼放棄相似度加權：
      ① 相似度低 ≠ cloaking。多語言網站、A/B test、輪播廣告、個人化推薦
         都會讓兩次爬取的文字相似度掉到 0.5 以下，舊版得靠一整套
         「標題一致就需佐證」的補丁去救誤報。
      ② 相似度高 ≠ 沒有 cloaking。只換一段表單 action 或塞一支外洩腳本，
         文字相似度可以到 0.98，舊版完全抓不到。
      ③ 機制比對的結果是可解釋的集合差，不是一個需要調閾值的浮點數。

    相似度仍然計算並輸出到 CSV，但只作為描述性數據。
    """
    bot_text   = bot_result.get("text_content", "")
    human_text = human_result.get("text_content", "")

    bot_eval   = evaluate_page(bot_result.get("html", ""),   url)
    human_eval = evaluate_page(human_result.get("html", ""), url)
    bot_mech   = bot_eval["mechanisms"]
    human_mech = human_eval["mechanisms"]
    hidden_from_bot = sorted(human_mech - bot_mech)   # 只給真人看的惡意機制
    shown_to_both   = sorted(human_mech & bot_mech)

    bot_sc      = bot_result.get("status_code", 0)
    human_sc    = human_result.get("status_code", 0)
    bot_chain   = bot_result.get("redirect_chain", [])
    human_chain = human_result.get("redirect_chain", [])
    redirect_fork = _redirect_forked(bot_chain, human_chain)
    bot_err   = bot_result.get("error",   "") or ""
    human_err = human_result.get("error", "") or ""

    # ── 布林裁決表（全部是有/無，沒有任何閾值或加權）──────────
    decisions = [
        ("C1", bool(hidden_from_bot),
         f"HUMAN 有惡意機制而 BOT 沒有 → 只對真人展開攻擊: {hidden_from_bot}"),
        ("C2", bot_sc in (403, 404, 503) and human_sc == 200,
         f"爬蟲被封鎖 HTTP {bot_sc}，真人正常 HTTP {human_sc}"),
        ("C3", "ERR_HTTP2_PROTOCOL_ERROR" in bot_err and not human_err,
         "爬蟲被 HTTP/2 協議層中斷 (RST_STREAM/GOAWAY)，真人正常訪問"),
        ("C4", bool(human_text) and not bot_text and not bot_err,
         "爬蟲取得空頁面，真人取得完整內容"),
        ("C5", redirect_fork and bool(human_mech) and not bot_mech,
         f"Redirect 分叉且只有真人端落在含惡意機制的頁面: "
         f"BOT->{bot_chain[-1] if bot_chain else 'N/A'} | "
         f"HUMAN->{human_chain[-1] if human_chain else 'N/A'}"),
    ]
    evidence, fired = [], []
    for rule_id, cond, label in decisions:
        if cond:
            fired.append(rule_id)
            evidence.append(f"[{rule_id}] {label}")

    verified = bool(fired)

    # ── 明確記錄「不是 cloaking」的情形 ────────────────────────
    if not verified:
        if shown_to_both:
            evidence.append(
                f"BOT 與 HUMAN 看到相同的惡意機制 {shown_to_both} → "
                f"是釣魚頁但未對爬蟲隱藏，非 Cloaking"
            )
        elif not human_mech:
            evidence.append("兩端皆未偵測到惡意機制 → 非 Cloaking")
        if redirect_fork:
            evidence.append(
                "Redirect 分叉但兩端惡意機制相同 → 疑似正常地理/裝置導向，非 Cloaking"
            )

    return {
        "verified":           verified,
        "fired":              fired,
        "evidence":           evidence,
        "bot_mechanisms":     bot_mech,
        "human_mechanisms":   human_mech,
        "hidden_from_bot":    hidden_from_bot,
        "bot_eval":           bot_eval,
        "human_eval":         human_eval,
        "content_similarity": _similarity_score(bot_text, human_text),
    }


def _dynamic_verify(state: AnalysisState, static_detected: bool) -> tuple:
    """
    比對 Node 1 已取得的兩份頁面，回傳 (verified, dual_results, errors, dynamic_reliability)

    本節點不再自己爬 —— 爬取在 Node 1 就完成了（見 dual_crawler.dual_crawl）。
    這樣 Node 3 判釣魚與本節點比 cloaking 是在同一批資料上進行，
    也不需要「先判釣魚才決定要不要爬第二次」的前後閘門。

      BOT   = 純爬蟲（_BOT_EXPOSE_JS 主動暴露自動化特徵，不做任何偽裝）
      HUMAN = 盡可能模仿真人（_STEALTH_JS + Google session 預熱 + 滑鼠軌跡）

    判定為布林：對兩份 HTML 各跑一次 Node 3 的釣魚判準，
    只有「HUMAN 有惡意機制而 BOT 沒有」才算 Cloaking。無任何加權或閾值。

    dynamic_reliability 說明:
      "HIGH"   → 結果可信，若 verified=False 代表確認無 Cloaking
      "LOW"    → 結果不可信，verified=False 不能排除 Cloaking
      "FAILED" → 爬取失敗，無法判斷
    """
    url = state.get("url", "")
    if not url:
        return False, {"error": "no_url"}, [], "FAILED"

    errs = []
    bot_result   = state.get("bot_crawl")   or {}
    human_result = state.get("human_crawl") or {}
    if not bot_result and not human_result:
        return False, {"error": "no_crawl_data"},                ["[Node4] Node 1 未提供爬取結果"], "FAILED"

    bot_time   = bot_result.get("fetch_time_sec", 0)
    human_time = human_result.get("fetch_time_sec", 0)
    if bot_result.get("error"):
        errs.append(f"[Node4] BOT crawl error: {bot_result['error']}")
    if human_result.get("error"):
        errs.append(f"[Node4] HUMAN crawl error: {human_result['error']}")
    print(f"  → 比對 Node 1 的兩份頁面 "
          f"(BOT {bot_time}s / HUMAN {human_time}s)", flush=True)

    verdict = decide_cloaking(bot_result, human_result, url)
    verified        = verdict["verified"]
    evidence        = verdict["evidence"]
    fired           = verdict["fired"]
    bot_mech        = verdict["bot_mechanisms"]
    human_mech      = verdict["human_mechanisms"]
    hidden_from_bot = verdict["hidden_from_bot"]
    bot_eval        = verdict["bot_eval"]
    human_eval      = verdict["human_eval"]
    content_sim     = verdict["content_similarity"]

    bot_sc    = bot_result.get("status_code", 0)
    human_sc  = human_result.get("status_code", 0)
    bot_len   = bot_result.get("html_length", 0)
    human_len = human_result.get("html_length", 0)

    print(f"  → [機制:BOT]   {sorted(bot_mech) or '無'}", flush=True)
    print(f"  → [機制:HUMAN] {sorted(human_mech) or '無'}", flush=True)
    print(f"  → 內容相似度: {content_sim:.3f}（僅供參考，不參與判定）", flush=True)
    for line in evidence:
        if line.startswith("["):
            print(f"  → [布林裁決] {line}", flush=True)

    # ── 動態可信度評估 ────────────────────────────────────
    # 這裡解決「動態沒驗到 ≠ 動態確認沒有」的根本問題：
    #   HIGH   → HUMAN 確實以正常用戶身份完成，頁面相同 = 真的沒有 Cloaking
    #   LOW    → HUMAN 預熱失敗或載入過快，頁面相同只代表兩者都被識破，結果不可信
    #   FAILED → 任一方失敗，無法比對
    # fetch_time_sec 已由各 thread wrapper 寫入 result dict
    dynamic_reliability = _assess_dynamic_reliability(bot_result, human_result)
    print(f"  → 動態可信度: {dynamic_reliability}"
          + (" (預熱失敗，結果不可信)" if dynamic_reliability == "LOW" else "")
          + (" (爬取失敗)" if dynamic_reliability == "FAILED" else ""))

    # ── 結合靜態結果（僅描述，不再調整任何分數）──────────────
    if verified and static_detected:
        evidence.append("靜態分析 + 動態雙重驗證共同確認")
        print("  → 靜態 + 動態雙重確認!", flush=True)
    elif verified and not static_detected:
        evidence.append("動態驗證發現靜態分析漏報的隱蔽型 Cloaking")
        print("  → 靜態漏報，動態補抓!", flush=True)
    elif not verified and static_detected:
        if dynamic_reliability == "HIGH":
            evidence.append(
                "靜態偵測到 Cloaking JS，但雙瀏覽器可信且兩端惡意機制一致 → "
                "前端 JS 未實際造成差異化內容"
            )
        else:
            evidence.append(
                f"靜態偵測到 Cloaking JS，動態可信度 {dynamic_reliability} → "
                f"無法以雙瀏覽器排除，維持靜態信號"
            )

    # ── HTTP 回應標頭差異（布林，僅作為附帶證據記錄）────────────
    # 不影響判定：Vary: User-Agent 是合法的快取宣告，CDN 普遍使用；
    # Set-Cookie 差異也常見於同意橫幅與地區導向。列為觀察項而非證據。
    bot_headers   = bot_result.get("response_headers", {})
    human_headers = human_result.get("response_headers", {})
    if bot_headers and human_headers:
        if "user-agent" in bot_headers.get("vary", "").lower():
            evidence.append("[觀察] 回應標頭 Vary: User-Agent（伺服器宣告依 UA 差異化）")
        if bool(human_headers.get("set-cookie", "")) and not bool(bot_headers.get("set-cookie", "")):
            evidence.append("[觀察] HUMAN 收到 Set-Cookie，BOT 未收到")

    # 只保留有消費者或會列印出來的欄位。
    # 截圖 base64、視覺相似度、三方比對、回應標頭、signal 統計都已移除 ——
    # 那些欄位沒有任何讀取端，卻要付出解碼兩張 1440×900 PNG 逐像素相減的成本。
    dual = {
        # ── 判定依據 ──
        "bot_mechanisms":       sorted(bot_mech),
        "human_mechanisms":     sorted(human_mech),
        "hidden_from_bot":      hidden_from_bot,
        "bot_is_phishing":      bot_eval["is_phishing"],
        "human_is_phishing":    human_eval["is_phishing"],
        "fired_rules":          fired,
        "evidence":             evidence,
        "dynamic_reliability":  dynamic_reliability,   # Node 5 讀這個決定 N/A
        # ── 診斷（列印用，不參與判定）──
        "content_similarity":   round(content_sim, 4),
        "bot_status_code":      bot_sc,
        "human_status_code":    human_sc,
        "bot_html_length":      bot_len,
        "human_html_length":    human_len,
        "bot_error":            bot_result.get("error"),
        "human_error":          human_result.get("error"),
        "human_prewarm_ok":     human_result.get("prewarm_ok", False),
    }
    return verified, dual, errs, dynamic_reliability


# ─────────────────────────────────────────────────────────────
# LangGraph Node 函式
# ─────────────────────────────────────────────────────────────
def analyze_cloaking_node(state: AnalysisState, llm) -> AnalysisState:
    """
    Node 4: Cloaking 分析
      ① 靜態特徵掃描（規則 + LLM）— 新定位：
         - Naive Frontend Cloaking JS 偵測（閾值提高至 0.40，降低誤報）
         - Phishing JS 指標偵測（credential harvesting / brand impersonation → 寫入 state 給 Node3）
         - 動態 FAILED 時轉為 fallback evidence，分數完整保留
      ② 動態雙瀏覽器驗證（BOT vs HUMAN Playwright）— 主要 cloaking 偵測機制
    """
    print("\n[Node 4] Cloaking 分析（靜態偵測 → 動態雙瀏覽器驗證）...", flush=True)

    # ── ① 靜態偵測 ────────────────────────────────────────
    static_detected, techniques_found = _static_detect(state, llm)

    # 靜態角色標籤：明確區分「Naive JS 命中」vs「未見 Frontend Cloaking」
    status_static = ("偵測到 Naive Frontend Cloaking JS" if static_detected
                     else "前端 JS 未見明確 Cloaking（Server-side 由動態驗證負責）")
    print(f"  → 靜態結果: {status_static}", flush=True)

    state["cloaking_detected"]   = static_detected
    state["cloaking_techniques"] = [
        f"{tech}: {', '.join(str(h) for h in hits[:2])}"
        for tech, hits in techniques_found.items()
    ]

    # ── ② 動態驗證 ────────────────────────────────────────
    print("  → 啟動動態雙瀏覽器驗證...", flush=True)
    verified, dual_results, dynamic_errs, dynamic_reliability = _dynamic_verify(state, static_detected)

    icon = "實驗確認 Cloaking" if verified else "動態驗證未見 Cloaking"
    print(f"  → 動態結果: {icon} | 動態可信度: {dynamic_reliability}", flush=True)

    # ── 靜態 Fallback 旗標 ─────────────────────────────────
    # 動態 FAILED 時，靜態分數是唯一依據，標記 static_is_fallback 供下游識別
    static_is_fallback = (dynamic_reliability == "FAILED")
    if static_is_fallback and static_detected:
        print("  → 動態失敗，靜態布林裁決作為 Fallback Evidence", flush=True)
    elif static_is_fallback and not static_detected:
        print(f"  → 動態失敗，靜態亦無信號 → Cloaking 不確定", flush=True)

    # ── Cloaking 信心度分級（純布林條件，無分數門檻）─────────────
    # CONFIRMED : 雙瀏覽器可信 + 實驗確認「BOT 看不到、HUMAN 看得到」
    # SUSPECTED : 實驗確認但 HUMAN 可能也被識破（LOW/FAILED），單側證據
    #             或靜態偵測到 Cloaking JS 而動態不可信，無法排除
    # AMBIGUOUS : 兩端一致且動態可信 → 沒有 cloaking
    if verified and dynamic_reliability == "HIGH":
        tier = "CONFIRMED"
    elif verified:
        tier = "SUSPECTED"
    elif static_detected and dynamic_reliability in ("LOW", "FAILED"):
        tier = "SUSPECTED"
    else:
        tier = "AMBIGUOUS"

    state["cloaking_verified"]         = verified
    state["dual_crawl_results"]        = dual_results
    state["static_is_fallback"]        = static_is_fallback
    state["cloaking_confidence_tier"] = tier
    print(f"  → Cloaking 信心度分級: {tier} "
          f"(verified={verified}, dynamic_reliability={dynamic_reliability})")

    errs = state.get("errors", [])
    errs.extend(dynamic_errs)
    state["errors"] = errs

    return state