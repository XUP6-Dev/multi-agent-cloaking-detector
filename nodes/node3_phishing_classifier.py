"""
node3_phishing_classifier.py  判斷是否為釣魚網站
Layer 1 布林裁決（不呼叫 LLM）+ Layer 2 加權累加（LLM 僅在此層以極大值融合參與）

這個節點「不是」閘門：釣魚與 cloaking 是兩個獨立屬性，各自判定、不互為前提，
圖是線性的（見 main.py build_graph）。無論本節點判定為何，都會進 Node 4。
本節點的 evaluate_page() 同時是 Node 4 比對兩份頁面所用的共享判斷函數 φ。
"""
import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import re
import json
import math
from collections import Counter
from urllib.parse import urlparse, urljoin
from state import AnalysisState


# 釣魚網站程式碼特徵規則庫
# 釣魚網站程式碼特徵規則庫（v3）
#
# 設計原則：「單一 pattern 命中不代表釣魚，組合行為才代表釣魚」
#
#   合法網站與釣魚網站在單一規則上幾乎無法區分：
#     合法登入頁  → 有 password 字串、有 sendBeacon（GA）、有 location.href（SPA）
#     釣魚頁面    → 一樣有以上所有
#
#   因此單一規則的權重刻意壓低，讓合法網站基礎分數落在 0.30 以下。
#   真正的判斷依賴「組合信號」（COMBO_RULES）：
#     多個行為同時出現 → 才代表完整的釣魚攻擊鏈。
#
#   新增兩個高權重類別（來自 Node4 cloaking 特徵庫的 JS 層信號）：
#     timed_cloaking_redirect：延遲跳轉 — 釣魚套件讓用戶填完才跳轉
#     ua_bot_detection：前端自動化偵測 — 規避爬蟲分析，合法網站不需要
#
#   註：瀏覽器指紋（fingerprint_apis）已「不列入」釣魚判定。
#     指紋 API 只代表網站在區分真人 / 自動爬蟲，這是 cloaking 的手段之一，
#     由 Node 4 負責；合法企業（GTM / Hotjar / reCAPTCHA）同樣大量採集指紋，
#     拿來當釣魚證據只會製造誤報。
PHISHING_RULES = {
    # ── 決定性信號（decisive：命中即給滿權重，不隨命中數縮放）──────
    # 特徵 1「表單傳輸目標異常」的 JS 版本：直接把竊得資料丟到 IM webhook。
    # 合法網站不會把前端表單直接 POST 到 Telegram Bot / Discord Webhook，
    # 因為 token 寫在前端等於公開，任何人都能讀走整個收件通道。
    # 現代釣魚套件（16shop、Telegram-based kit）幾乎都用這條外洩管道。
    "webhook_exfiltration": {
        "weight": 0.50,          # 實際由 Layer 1 布林裁決，此權重僅備援
        "patterns": [
            r"api\.telegram\.org",
            r"discord(?:app)?\.com/api/webhooks",
            r"bot\d{6,}:[A-Za-z0-9_\-]{30,}",          # Telegram bot token 字面值
            r"sendMessage\?[^'\"]{0,80}chat_id",
            r"hooks\.slack\.com/services",
        ]
    },

    # ── 精準信號（較高權重）──────────────────────────────────
    "form_credential_targeting": {
        "weight": 0.14,    # 直接針對 password input — 最精準的單一信號
        "patterns": [
            r"document\.getElementById.*password",
            r"querySelector\s*\(\s*['\"].*password",
            r"getElementsByName\s*\(\s*['\"]password",
            r"\[type=['\"]?password['\"]?\]"
        ]
    },
    # ── 新增：JS 層 Cloaking 信號（高權重）──────────────────────
    "timed_cloaking_redirect": {
        "weight": 0.20,    # 短延遲跳轉 — 真正的釣魚套件 cloaking 特徵
        # ── 精準化說明（避免企業 session timeout 誤報）────────────────
        # 舊寫法 r"setTimeout\s*\(.*location" 太寬泛：
        #   企業入口網站普遍有 setTimeout(fn, 1800000) 做 30 分鐘 session timeout，
        #   這是標準安全 UX，絕非 cloaking。
        #
        # 新原則：只抓「短延遲（< 1000ms）且 location 在同一 setTimeout call 內」
        #   釣魚套件特徵：setTimeout(()=>location.href='evil',200)（讓用戶來不及看到）
        #   合法 session timeout：setTimeout(fn, 1800000)（30 分鐘）→ 完全不命中
        #
        # 覆蓋的真實 cloaking 寫法：
        #   function body：setTimeout(function(){ location.href='x' }, 500)
        #   named arrow：  setTimeout(x => location.href='x', 100)
        #   ()=> arrow：   setTimeout(()=>location.replace('x'), 200)
        #   外部 URL：     setTimeout(anything, 999, "http://evil.com")
        #   setInterval：  setInterval(fn_with_location, 1000)（合法網站不會這樣做）
        "patterns": [
            r"setInterval\s*\(.*location",
            r"setTimeout\s*\([^)]*https?://[^)]{0,200},\s*\d{1,4}\s*\)",
            r"setTimeout\s*\(\s*function\s*[^{]{0,30}\{[^}]{0,200}location[^}]{0,100}\}\s*,\s*[0-9]{1,3}\s*\)",
            r"setTimeout\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*=>\s*(?:location|\{[^}]{0,150}location)[^)]{0,100},\s*[0-9]{1,3}\s*\)",
            r"setTimeout\s*\(\s*\(\s*\)\s*=>\s*location[^,]{0,100},\s*[0-9]{1,3}\s*\)",
            r"delay.*redirect",
        ]
    },
    "ua_bot_detection": {
        "weight": 0.16,    # 爬蟲框架洩漏特徵 — 釣魚套件用來規避分析
        # ── 精準化說明（避免 reCAPTCHA / HubSpot / Marketo 誤報）────
        # 舊寫法包含 r"navigator\.webdriver"（單獨出現）。
        # 但這個 check 廣泛存在於合法函式庫：
        #   - Google reCAPTCHA v3
        #   - HubSpot Forms
        #   - Marketo Forms 2.0
        #   - 任何使用 bot-protection SDK 的企業網站
        #
        # 新原則：
        #   ① 保留爬蟲框架的專屬洩漏識別符（window._phantom、__selenium 等）
        #      ── 這些絕不會出現在合法 CDN 或 SDK 腳本中
        #   ② navigator.webdriver 只有「check 後立即執行 redirect / 跳轉」才算 cloaking
        #      ── 單純 if(navigator.webdriver) { return false; } 是合法保護，不計分
        "patterns": [
            r"navigator\.plugins\.length\s*===?\s*0",
            r"window\._phantom",
            r"window\.callPhantom",
            r"__selenium",
            r"__webdriver",
            r"document\.__\$webdriverAsyncExecutor",
            r"navigator\.webdriver\s*(?:===?\s*true\s*)?&&",
            r"if\s*\(\s*navigator\.webdriver\s*\)\s*\{?[^}]{0,100}(?:location|redirect|window\.open)",
        ]
    },
    # ── 特徵 3：反分析 / 規避機制（阻止使用者檢查原始碼）──────────
    # 合法網站沒有理由封鎖右鍵與 F12 —— 這是純粹的「不想被看」。
    # 只抓「明確的封鎖動作」，不抓單純的 contextmenu 監聽
    #（畫布類 App、自製右鍵選單也會監聽 contextmenu）。
    "devtools_blocking": {
        "weight": 0.18,
        "patterns": [
            r"oncontextmenu\s*=\s*['\"]?\s*return\s+false",
            r"onselectstart\s*=\s*['\"]?\s*return\s+false",
            r"ondragstart\s*=\s*['\"]?\s*return\s+false",
            r"onkeydown\s*=\s*['\"]?\s*return\s+false",
            r"keyCode\s*===?\s*123",                                  # F12
            r"\.key\s*===?\s*['\"]F12['\"]",
            r"shiftKey[^;{]{0,80}keyCode\s*===?\s*(?:73|74|67)",      # Ctrl+Shift+I/J/C
            r"ctrlKey[^;{]{0,60}keyCode\s*===?\s*85",                 # Ctrl+U 檢視原始碼
            r"['\"]contextmenu['\"][^;]{0,120}preventDefault",
        ]
    },

    # ── 特徵 2：刻意混淆 —— 編碼後動態執行 ────────────────────────
    # 只抓「解碼 + 執行」的組合，不抓單純的 minify。
    # 正常壓縮不會出現 eval(atob(...))；這是為了讓靜態掃描讀不到字串。
    "code_obfuscation_exec": {
        "weight": 0.16,
        "patterns": [
            r"eval\s*\(\s*atob\s*\(",
            r"eval\s*\(\s*(?:window\.)?unescape\s*\(",
            r"eval\s*\(\s*decodeURIComponent\s*\(",
            r"new\s+Function\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(",
            r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e",  # p,a,c,k,e,d packer
            r"atob\s*\(\s*['\"][A-Za-z0-9+/=]{60,}",                  # 長 Base64 字面值解碼
            r"unescape\s*\(\s*['\"](?:%[0-9a-fA-F]{2}){20,}",
            r"(?:\\x[0-9a-fA-F]{2}){25,}",                            # 長 hex escape blob
            r"String\.fromCharCode\s*\((?:\s*\d+\s*,){15,}",
        ]
    },

    # ── 特徵 5：假錯誤 + 真重導向（收完資料後送回官網）────────────
    "post_submit_deception": {
        "weight": 0.12,
        "patterns": [
            r"alert\s*\(\s*['\"][^'\"]{0,80}(?:incorrect|invalid|wrong password|failed|try again)",
            r"(?:password|credential)[^;{]{0,60}(?:incorrect|invalid)[^;{]{0,60}try\s*again",
            r"location\.(?:href|replace)\s*[=(]\s*['\"]https?://(?:www\.)?(?:paypal|apple|microsoft|office|live|google|facebook|amazon|netflix|chase|dhl|coinbase)\.",
        ]
    },

    # ── 特徵 1 延伸：老派 PHP / 免費信箱外洩 ──────────────────────
    # 權重低：合法頁面也可能出現聯絡信箱，需靠 COMBO 佐證。
    "mail_exfiltration": {
        "weight": 0.08,
        "patterns": [
            r"mail\s*\(\s*\$",
            r"['\"][A-Za-z0-9._%+\-]+@(?:gmail|yahoo|yandex|hotmail|outlook|mail)\.(?:com|ru)['\"]",
            r"smtp[^;]{0,40}(?:gmail|yandex|mail\.ru)",
        ]
    },

    # ── 中等信號（中權重）──────────────────────────────────────
    "credential_harvesting": {
        "weight": 0.10,    # password/cvv 字串 — 合法登入頁也有，單獨不夠
        "patterns": [
            r"password", r"passwd", r"creditcard", r"credit_card",
            r"card_number", r"cvv", r"ssn", r"social_security",
            r"account.*number", r"bank.*account"
        ]
    },
    "anti_analysis": {
        "weight": 0.08,    # 反偵測 — 有信號但也見於部分合法工具
        "patterns": [
            r"debugger\s*;",
            r"setInterval.*debugger",
            r"devtools",
            r"console\.clear\s*\(",
            r"document\.oncontextmenu"
        ]
    },
    "suspicious_external": {
        "weight": 0.06,    # 短網址 / localhost IP — 可疑但不足以單獨判斷
        "patterns": [
            r"bit\.ly", r"tinyurl\.com",
            r"pastebin\.com", r"ngrok\.io",
            r"0\.0\.0\.0", r"127\.0\.0\.1"
        ]
    },
    # ── 噪音信號（極低權重，幾乎不計分）────────────────────────
    # 現代合法網站中極為普遍，單獨命中幾乎無判斷價值，
    # 只在 COMBO_RULES 中作為佐證條件使用。
    "data_exfiltration": {
        "weight": 0.04,    # sendBeacon 是 GA/HubSpot 標配
        "patterns": [
            r"XMLHttpRequest.*POST",
            r"fetch\s*\(.*POST",
            r"\.ajax.*type.*POST",
            r"sendBeacon\s*\(",
            r"navigator\.sendBeacon"
        ]
    },
    "malicious_redirect": {
        "weight": 0.04,    # 跳轉到外部 URL — SPA 內部路由不計
        # ── 精準化說明（避免 SPA routing 誤報）──────────────────────
        # 舊寫法 r"location\.href\s*=" 命中所有 SPA routing，
        # 例如 location.href = '/dashboard'（React/Vue Router 標配）。
        # 這不是惡意跳轉，而是正常的前端路由。
        #
        # 新原則：只計「跳轉到外部絕對 URL（http/https）」
        #   釣魚套件：location.href = 'http://phishing.com'
        #   SPA routing：location.href = '/dashboard'  → 不命中
        "patterns": [
            r"location\.href\s*=\s*['\"]https?://",
            r"location\.replace\s*\(\s*['\"]https?://",
            r"window\.location\s*=\s*['\"]https?://",
            r"document\.location\s*=\s*['\"]https?://",
            r"meta.*http-equiv.*refresh",
        ]
    },
    "brand_impersonation": {
        "weight": 0.02,    # JS 引用品牌 CDN ≠ 仿冒，由 _analyze_url_semantics 負責
        "patterns": [
            r"paypal", r"amazon", r"apple\.com",
            r"microsoft", r"google\.com", r"facebook",
            r"instagram", r"netflix", r"secure.*login",
            r"verify.*account", r"update.*payment"
        ]
    },
    "dynamic_injection": {
        "weight": 0.02,    # innerHTML 是所有前端框架的底層操作
        "patterns": [
            r"document\.write\s*\(",
            r"innerHTML\s*=",
            r"outerHTML\s*=",
            r"insertAdjacentHTML"
        ]
    },
}

PHISHING_CONFIDENCE_THRESHOLD = 0.45

# ══════════════════════════════════════════════════════════════
#  Layer 1：布林裁決層（DECISIVE_RULES）
# ══════════════════════════════════════════════════════════════
#
# 為什麼這一層不用加權：
#   加權的存在意義是「讓弱訊號累積」。但下列條件不是弱訊號 ——
#   它們的特異性（specificity）夠高，合法網站沒有任何理由滿足，
#   給 0.5 還是 1.0 對判定結果沒有差別，只會製造需要調的數字。
#
# 收錄標準（兩者都要滿足，否則放 Layer 2）：
#   ① 合法網站沒有合理情境會觸發（已扣除 SSO / CDN / analytics 白名單）
#   ② 攻擊者規避的成本高 —— 不用 Telegram 外洩就得自架收件伺服器，
#      這是真成本；改個 URL 長度不是，所以 URL 詞彙特徵一律留在 Layer 2。
#
# 明確不放進來的（實測 Dataset.csv 116,600 筆，純布林 recall 僅 34.3%）：
#   URL 長度 / 熵值 / 連字符 / 數字密度 —— 統計性特徵，布林化會漏掉三分之二。
#
# 格式：flags 為連言（AND），全部命中即裁決為釣魚，不再計算 Layer 2。
DECISIVE_RULES = [
    {
        "id": "D1",
        "flags": ["webhook_exfiltration"],
        "label": "前端直接把資料送往 Telegram/Discord Webhook"
                 "（token 寫在前端等於公開收件通道，合法網站不會這樣做）",
    },
    {
        "id": "D2",
        "flags": ["cred_form", "form_action_to_ip"],
        "label": "憑證表單送往裸 IP",
    },
    {
        "id": "D3",
        "flags": ["cred_form", "form_action_free_host"],
        "label": "憑證表單送往免費主機 / 動態 DNS 網域（無合法 SSO 情境）",
    },
    {
        "id": "D4",
        "flags": ["brand_squatting_suspicious_host"],
        "label": "品牌名出現在 weebly / pages.dev 類免費託管平台",
    },
    {
        "id": "D5",
        "flags": ["at_symbol_in_url"],
        "label": "URL 含 @ 符號（瀏覽器實際連往 @ 之後的網域）",
    },
    {
        "id": "D6",
        "flags": ["cred_form", "punycode_domain"],
        "label": "Punycode 同形字網域上的憑證表單",
    },
    {
        "id": "D7",
        "flags": ["cred_form", "code_obfuscation_exec", "devtools_blocking"],
        "label": "收憑證 + 解碼後 eval 執行 + 封鎖開發者工具（三重規避）",
    },
]

# Layer 1 命中時輸出的固定信心度。
# 不是 1.0：保留餘裕表示「規則命中」而非「絕對確定」，
# 且此數值只餵給 Node 5 的風險加總，不參與 Node 3 的判定。
DECISIVE_CONFIDENCE = 0.95
# Layer 2 的信心度上限，確保兩層在下游可區分
LAYER2_CONFIDENCE_CAP = 0.90

# ── 組合信號規則（COMBO_RULES）────────────────────────────────
# 核心判斷邏輯：多個規則類別同時命中 → 才代表完整的釣魚攻擊鏈。
#
# 設計說明：
#   每條規則定義「需要哪些類別同時命中」及「各類別最少幾個 pattern 命中」。
#   min_hits 的作用：區分「廣泛使用的合法 pattern」vs「釣魚專用的精準操作」。
#   例如 form_credential_targeting 要求 2+：
#     合法登入頁只有 [type=password]（1 個 pattern）→ 不觸發
#     釣魚套件同時用 getElementById、querySelector、[type=password]（2-3 個 pattern）→ 觸發
#
#   "required": {category: min_pattern_hits, ...}
#   "bonus": 加到 rule_score 的分數
#   "label": 顯示用說明
COMBO_RULES = [
    # ── 最強：完整竊取鏈（精準表單 + 憑證 + 跳轉）───────────
    {
        "required": {
            "form_credential_targeting": 2,  # 至少 2 種 password targeting 手法
            "credential_harvesting":     1,
            "malicious_redirect":        2,  # 至少 2 種跳轉手法（主動跳轉）
        },
        "bonus": 0.28,
        "label": "完整竊取鏈：精準表單(2+) + 憑證採集 + 多重跳轉(2+)",
    },
    # ── 精準表單 + 反偵測（主動隱藏 password 竊取行為）─────────
    {
        "required": {
            "form_credential_targeting": 2,  # 精準操作 password input（2 種手法）
            "anti_analysis":             1,  # 同時反偵測
        },
        "bonus": 0.25,
        "label": "精準表單定向(2+) + 反偵測（主動隱藏竊取行為）",
    },
    # ── 定時跳轉 + 表單定向（weebly phishing kit 典型模式）────
    {
        "required": {
            "timed_cloaking_redirect": 1,   # 延遲後跳轉（JS 層 cloaking 行為）
            "form_credential_targeting": 1, # 同時針對 password input
        },
        "bonus": 0.22,
        "label": "定時跳轉 + 表單定向（JS cloaking + phishing 組合）",
    },
    # ── 自動化偵測 + 表單定向（server-side cloaking + 前端 phishing）
    {
        "required": {
            "ua_bot_detection":          1,  # 前端偵測爬蟲（規避分析）
            "form_credential_targeting": 1,  # 同時收集 password
        },
        "bonus": 0.25,
        "label": "Bot 偵測 + 表單定向（主動規避 + 憑證竊取）",
    },
    # ── 定時跳轉 + 多重憑證採集（即使沒有精準 form targeting）──
    {
        "required": {
            "timed_cloaking_redirect": 1,
            "credential_harvesting":   2,   # 至少 2 種憑證關鍵字（如 password + cvv）
        },
        "bonus": 0.20,
        "label": "定時跳轉 + 多重憑證採集",
    },
    # ── 封鎖開發者工具 + 表單定向（不想被看 + 正在收憑證）─────
    {
        "required": {
            "devtools_blocking":         1,
            "form_credential_targeting": 1,
        },
        "bonus": 0.22,
        "label": "封鎖右鍵/F12 + 表單定向（阻止分析 + 憑證竊取）",
    },
    # ── 編碼後動態執行 + 憑證採集（藏起竊取邏輯）──────────────
    {
        "required": {
            "code_obfuscation_exec": 1,
            "credential_harvesting": 1,
        },
        "bonus": 0.20,
        "label": "解碼後 eval 執行 + 憑證採集（隱藏竊取邏輯）",
    },
    # ── 免費信箱 / PHP 外洩 + 表單定向（老派釣魚套件）──────────
    {
        "required": {
            "mail_exfiltration":         1,
            "form_credential_targeting": 1,
        },
        "bonus": 0.18,
        "label": "郵件外洩管道 + 表單定向（老派 PHP 釣魚套件）",
    },
    # ── 假錯誤/真重導向 + 表單定向（收完資料送回官網）─────────
    {
        "required": {
            "post_submit_deception":     1,
            "form_credential_targeting": 1,
        },
        "bonus": 0.16,
        "label": "假錯誤提示 / 導回官網 + 表單定向",
    },
    # ── 精準表單 + 資料外傳 + 跳轉（完整外傳鏈）──────────────
    {
        "required": {
            "form_credential_targeting": 2,  # 提高至 2：合法登入頁只有 1 個 pattern，釣魚套件才有 2+
            "data_exfiltration":         1,
            "malicious_redirect":        2,
        },
        "bonus": 0.22,
        "label": "表單定向(2+) + 資料外傳 + 多重跳轉",
    },
]

# ══════════════════════════════════════════════════════════════
#  URL 分析輔助：品牌仿冒偵測 + 結構釣魚偵測 + 詞彙特徵分析
# ══════════════════════════════════════════════════════════════

# ── 官方域名白名單：品牌名出現在這些域名上不算仿冒 ─────────────
BRAND_OFFICIAL_DOMAINS = {
    "google":        {"google.com", "google.co.uk", "google.com.au",
                      "google.co.jp", "google.com.tw"},
    "facebook":      {"facebook.com", "fb.com", "instagram.com"},
    "microsoft":     {"microsoft.com", "live.com", "outlook.com",
                      "azure.com", "office.com"},
    "apple":         {"apple.com"},
    "amazon":        {"amazon.com", "amazon.co.uk", "amazon.co.jp",
                      "amazon.com.au", "amazonaws.com"},
    "paypal":        {"paypal.com", "paypal.me"},
    "netflix":       {"netflix.com"},
    "coinbase":      {"coinbase.com"},
    "ledger":        {"ledger.com"},
    "ledgr":         {"ledger.com"},          # 常見錯拼
    "trezor":        {"trezor.io"},
    "metamask":      {"metamask.io"},
    "binance":       {"binance.com"},
    "kraken":        {"kraken.com"},
    "exodus":        {"exodus.com"},
    "exodas":        {"exodus.com"},          # 常見錯拼
    "gemini":        {"gemini.com"},
    "geminii":       {"gemini.com"},          # 常見錯拼
    "dhl":           {"dhl.com"},
    "fedex":         {"fedex.com"},
    "ups":           {"ups.com"},
    "usps":          {"usps.com"},
    "chase":         {"chase.com"},
    "wellsfargo":    {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "allegro":       {"allegro.pl"},
    "postnord":      {"postnord.se", "postnord.dk"},
    "telstra":       {"telstra.com", "telstra.com.au"},
    "bt":            {"bt.com"},
    "namecheap":     {"namecheap.com"},
    "webex":         {"webex.com", "cisco.com"},
}

# ── 可疑託管平台：合法品牌不會把登入頁放在這些平台 ─────────────
SUSPICIOUS_HOSTING = {
    "pages.dev", "weebly.com", "weeblysite.com",
    "web.app", "firebaseapp.com", "netlify.app",
    "framer.app", "blogspot.com", "wixsite.com",
    "ukit.me", "blogspot.ca", "usercontent.dev",
}

# ── 已知合法 TLD / 域名：套用信心度上限，防止誤判合法大型機構 ──
# 這些機構有 bot 防護（對爬蟲回傳 403），不代表是 phishing
# ── 免費子域名 / 動態 DNS：正式品牌不會使用這些服務 ───────────
SUSPICIOUS_REGISTRARS = {
    # 西方免費子域名 / 動態 DNS
    "it.com", "duckdns.org", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "loca.lt", "serveo.net",
    "000webhostapp.com", "infinityfreeapp.com",
    "glitch.me", "replit.dev", "render.com",
    # 日本 / 亞洲免費子域名 / 虛擬主機
    "main.jp", "starfree.jp", "chicappa.jp",
    "ciao.jp", "dip.jp", "mydns.jp",
    # No-IP 系列
    "zapto.org", "hopto.org", "myftp.biz",
    "ddns.net", "sytes.net", "redirectme.net",
    "2ix.net", "3utilities.com",
}
# 其中釣魚高頻率服務給較高的加分
_HIGH_RISK_REGISTRARS = {
    "main.jp", "duckdns.org", "it.com",
    "000webhostapp.com", "ddns.net",
    "hopto.org", "zapto.org", "sytes.net",
    "starfree.jp", "chicappa.jp",
}

# 短目錄前綴排除清單（合法路徑，不觸發 opaque path 偵測）
_LEGIT_SHORT_PREFIXES = {
    "dp", "gp",           # Amazon
    "v1", "v2", "v3",    # API 版本
    "en", "fr", "de",    # 主流語言代碼
    "us", "uk", "au",    # 地區代碼
}

# 子域名偽裝服務名稱 patterns
_FAKE_SERVICE_PATTERNS = [
    r"captc", r"verif", r"validat", r"secure",
    r"signin", r"support\d", r"helpdesk",
    r"update\d", r"portal\d", r"account\d",
    r"srv\d{2,}", r"node\d*",
]

# 查詢字串中的憑證收集參數
_CRED_QUERY_PARAMS = [
    "email", "user", "username", "login",
    "password", "passwd", "pass",
    "token", "verify", "confirm",
    "account", "phone", "mobile",
]

# 路徑中的敏感操作關鍵字
_SUSPICIOUS_PATH_KEYWORDS = [
    "verify", "validation", "secure", "update",
    "confirm", "signin", "login", "checkpoint",
    "recover", "unlock", "reactivate", "suspended",
]

# 短前綴 + 不透明長字串路徑 pattern（如 /bn/troftnikon）
_OPAQUE_PATH_RE = re.compile(r"^/([a-z]{1,3})/([a-z0-9]{6,})$", re.IGNORECASE)

# ── 詞彙特徵分析（URL Lexical Features）─────────────────────
# 這些特徵純靠 URL 字串結構判斷，不需要 DNS / HTTP 請求，零成本。
# 參考: PhishLumos, CrawlPhish, APWG EcrimeX 研究文獻
#
# IPv4 直連：合法品牌絕不用裸 IP 做登入頁
_IP_HOST_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
# URL 中的 @ 符號：browser 會把 @ 前的部分視為 user:pass，
# 攻擊者用 https://paypal.com@evil.com/ 讓受害者誤以為在 paypal.com
_AT_IN_URL_RE   = re.compile(r"://[^/]*@")
# Punycode 編碼域名（國際化域名同形攻擊）：xn-- 前綴
_PUNYCODE_RE    = re.compile(r"xn--", re.IGNORECASE)
# 顯式非標準 port（釣魚套件常見，合法網站幾乎不用 8080/8888 等做登入頁）
_EXPLICIT_PORT_RE = re.compile(r":\d{2,5}/")
_LEGIT_PORTS    = {"80", "443"}   # 僅保留標準 HTTP/HTTPS port；8080 是釣魚套件常見 port，不列入白名單
# 域名中的連字符（hyphen）計數：secure-account-login-verify.com 類型
# 4 個以上連字符且不是 TLD 中的連字符（如 .co.uk）才算可疑
_HYPHEN_THRESHOLD   = 4
# URL 總長度閾值（Dataset.csv 實測：>75 → P(釣魚)=61.2%，>120 → 89.6%）
_URL_LEN_LONG    = 75
_URL_LEN_EXTREME = 120
# 數字密度 / 熵值閾值（Dataset.csv 實測：85.2% / 56.7%）
_DIGIT_RATIO_THRESHOLD = 0.10
_ENTROPY_THRESHOLD     = 4.2


def _shannon_entropy(s: str) -> float:
    """URL 字元分佈的 Shannon 熵（bits）—— 隨機字串明顯高於人寫的 URL"""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _registered_domain(netloc: str) -> str:
    """
    netloc → 註冊域名（處理 co.uk / com.tw 這類兩段式 TLD）

    免費託管 / 動態 DNS 視同 public suffix：
      a.duckdns.org 與 b.duckdns.org 是兩個不同的擁有者，
      若只取 eTLD+1 會把「表單送到別人的 duckdns 子網域」誤判為同網域。
    """
    netloc = (netloc or "").lower().split(":")[0]
    parts  = netloc.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "gov", "net", "edu"}:
        base, n = ".".join(parts[-3:]), 3
    elif len(parts) >= 2:
        base, n = ".".join(parts[-2:]), 2
    else:
        return netloc
    if len(parts) > n and base in (SUSPICIOUS_HOSTING | SUSPICIOUS_REGISTRARS):
        return ".".join(parts[-(n + 1):])
    return base


def _analyze_url_semantics(url: str) -> tuple:
    """
    品牌仿冒偵測（Brand Squatting）：
    品牌關鍵字出現在 URL 中，但域名不是官方域名 → 疑似仿冒。

    回傳 (score_boost: float, indicators: list[str], flags: set[str])
    """
    if not url:
        return 0.0, [], set()
    score, indicators, flags = 0.0, [], set()
    try:
        parsed     = urlparse(url)
        netloc     = parsed.netloc.lower()
        full       = netloc + parsed.path.lower()
        registered = _registered_domain(netloc)

        for brand, official_set in BRAND_OFFICIAL_DOMAINS.items():
            if brand not in full:
                continue
            if any(registered == od or registered.endswith("." + od)
                   for od in official_set):
                continue   # 官方域名，跳過
            on_suspicious = any(
                registered == h or registered.endswith("." + h)
                for h in SUSPICIOUS_HOSTING
            )
            if on_suspicious:
                score += 0.50
                flags.add("brand_squatting_suspicious_host")
                indicators.append(f"brand_squatting_suspicious_host: {brand}@{registered}")
            else:
                score += 0.30
                flags.add("brand_squatting")
                indicators.append(f"brand_squatting: {brand}@{registered}")
            break   # 每個 URL 只計最強一個信號
    except Exception:
        pass
    return min(0.55, score), indicators, flags


def _analyze_url_structure(url: str) -> tuple:
    """
    URL 結構釣魚偵測（補充品牌仿冒的盲點）：
    偵測不使用已知品牌名、但結構本身可疑的 URL。

    偵測維度：
    ① 查詢字串中含憑證參數（?email= / ?user= ...）
    ② 使用已知免費子域名服務（main.jp / duckdns.org ...）
    ③ 子域名帶有偽裝服務名（captc / verif / node ...）
    ④ 路徑含敏感操作關鍵字（verify / signin / checkpoint ...）
    ⑤ 短目錄前綴 + 不透明長字串路徑（如 /bn/troftnikon）

    回傳 (score_boost: float, indicators: list[str], flags: set[str])
    """
    if not url:
        return 0.0, [], set()
    score, indicators, flags = 0.0, [], set()
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        parts  = netloc.split(".")

        # ── ① 查詢字串憑證參數 ──────────────────────────
        hit_params = [p for p in _CRED_QUERY_PARAMS
                      if re.search(rf"(?:^|&|%26){re.escape(p)}(?:=|%3D)", query)]
        if hit_params:
            score += 0.22
            flags.add("cred_param_in_url")
            indicators.append(f"cred_param_in_url: {','.join(hit_params)}")

        # ── ② 免費子域名服務 ─────────────────────────────
        if len(parts) >= 2:
            reg2 = ".".join(parts[-2:])
            reg3 = ".".join(parts[-3:]) if len(parts) >= 3 else ""
            for sr in SUSPICIOUS_REGISTRARS:
                if reg2 == sr or (reg3 and reg3.endswith("." + sr)):
                    boost = 0.30 if sr in _HIGH_RISK_REGISTRARS else 0.18
                    score += boost
                    flags.add("suspicious_registrar")
                    indicators.append(f"suspicious_registrar: {sr}")
                    break

        # ── ③ 子域名偽裝服務名稱 ────────────────────────
        subdomain = parts[0] if (len(parts) >= 3 and parts[0] != "www") else ""
        if subdomain:
            fake_hits = [p for p in _FAKE_SERVICE_PATTERNS
                         if re.search(p, subdomain)]
            if fake_hits:
                score += 0.15
                flags.add("fake_service_subdomain")
                indicators.append(f"fake_service_subdomain: {subdomain}")

        # ── ④ 路徑敏感操作關鍵字 ────────────────────────
        path_hits = [k for k in _SUSPICIOUS_PATH_KEYWORDS if k in path]
        if path_hits:
            score += 0.08
            flags.add("suspicious_path_keyword")
            indicators.append(f"suspicious_path_keyword: {','.join(path_hits[:2])}")

        # ── ⑤ 短目錄前綴 + 不透明長字串路徑 ─────────────
        stripped = parsed.path.rstrip("/")
        if stripped:
            m = _OPAQUE_PATH_RE.match(stripped)
            if m and m.group(1).lower() not in _LEGIT_SHORT_PREFIXES:
                score += 0.14
                flags.add("opaque_path_pattern")
                indicators.append(f"opaque_path_pattern: {stripped}")

    except Exception:
        pass
    return min(0.55, score), indicators, flags


def _analyze_url_lexical(url: str) -> tuple:
    """
    URL 詞彙特徵分析（Lexical Feature Analysis）
    純字串計算，零成本，不需要 DNS / HTTP。

    偵測維度：
    ① IP 直連（裸 IP 做域名）
    ② URL 中的 @ 符號（browser 誤導攻擊）
    ③ Punycode / xn-- 同形字攻擊
    ④ URL 總長度異常（> 75 / > 120）
    ⑤ 域名中連字符密度過高（> 4 個）
    ⑥ 子域名深度過深（> 4 層點號）
    ⑦ 顯式非標準 Port（非 80/443）

    上限: 0.60
    回傳: (score_boost: float, indicators: list[str], flags: set[str])

    ── 權重來源（2026-07 於 Dataset.csv 實測，116,600 筆 / 釣魚 16,600）──
    weight = k × WoE，WoE = ln[ P(特徵|釣魚) / P(特徵|正常) ]
    這是加總式評分等價於 naive Bayes log-odds 時的正確係數。

      特徵                WoE     P(釣魚|命中)   權重
      url_len>120        +3.94      89.6%      0.16
      digit_ratio>0.1    +3.54      85.2%      0.14
      url_len>75         +2.25      61.2%      0.09
      entropy>4.2        +2.06      56.7%      0.08
      dash>=4            +1.28      37.3%      0.05
      dot>=4             -0.33      10.6%      已移除（反向證據）

    k = 0.04，由一條不變式決定，而非湊數：
      「本函式所有 WoE 校準特徵全部命中，總分仍須低於判定閾值」
      0.16+0.14+0.09+0.08+0.05 = 0.43 < 0.45（url_len 兩檔互斥，實際更低）
    理由：資料集的正常樣本 56.9% 是 http，取自舊爬取的短首頁，
      現代電商 / SaaS 的正常 URL 普遍又長又高熵，實測 WoE 高估了這些特徵。
      因此 URL 詞彙特徵永遠只能當佐證，不能單獨判定 —— 必須有內容或結構信號同時成立。
      （test_node3_phishing.py 的 test_lexical_alone_cannot_decide 鎖住這條不變式）

    未採用 is_https=0（WoE -2.02）與 query_len>0（WoE +1.98）：
      兩者皆為資料集年代偏誤 —— 正常樣本 56.9% 是 http，
      顯示 benign 來自舊爬取、phish 來自近期蒐集，訊號不可信。
    ip / @ / punycode / port 四項資料集樣本過少（覆蓋率 <0.1%）無法校準，
      維持手調值並標記為 unfitted。
    """
    if not url:
        return 0.0, [], set()
    score, indicators, flags = 0.0, [], set()

    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        host   = parsed.hostname or ""   # 不含 port 的純 hostname
        full   = url

        # ── ① IP 直連（unfitted：資料集僅 13 筆，無法校準）──────
        if host and _IP_HOST_RE.match(host):
            score += 0.30
            flags.add("ip_in_hostname")
            indicators.append(f"ip_in_hostname: {host}")

        # ── ② URL 中的 @ 符號（unfitted）─────────────────
        # https://paypal.com@attacker.com/ → 瀏覽器實際連到 attacker.com
        if _AT_IN_URL_RE.search(full):
            score += 0.45
            flags.add("at_symbol_in_url")
            indicators.append("at_symbol_in_url: URL 含 @ 符號（browser 誤導攻擊）")

        # ── ③ Punycode 同形字攻擊（unfitted）────────────
        # xn--pple.com（a→а 西里爾文）等，肉眼無法分辨
        if _PUNYCODE_RE.search(netloc):
            score += 0.35
            flags.add("punycode_domain")
            indicators.append(f"punycode_domain: {netloc}")

        # ── ④ URL 總長度（WoE 校準）──────────────────────
        url_len = len(full)
        if url_len > _URL_LEN_EXTREME:
            score += 0.16
            flags.add("url_extreme_length")
            indicators.append(f"url_extreme_length: {url_len} chars (>{_URL_LEN_EXTREME})")
        elif url_len > _URL_LEN_LONG:
            score += 0.09
            flags.add("url_long")
            indicators.append(f"url_long: {url_len} chars (>{_URL_LEN_LONG})")

        # ── ⑤ 數字密度（WoE 校準，新增）──────────────────
        # 釣魚 URL 常帶隨機數字 ID / 編碼過的受害者參數
        if url_len:
            digit_ratio = sum(c.isdigit() for c in full) / url_len
            if digit_ratio > _DIGIT_RATIO_THRESHOLD:
                score += 0.14
                flags.add("high_digit_ratio")
                indicators.append(f"high_digit_ratio: {digit_ratio:.2f}")

        # ── ⑥ URL 熵值（WoE 校準，新增）──────────────────
        # 隨機產生的路徑 / 子域名熵值明顯高於人寫的可讀 URL
        ent = _shannon_entropy(full)
        if ent > _ENTROPY_THRESHOLD:
            score += 0.08
            flags.add("high_entropy")
            indicators.append(f"high_entropy: {ent:.2f} (>{_ENTROPY_THRESHOLD})")

        # ── ⑦ 域名連字符密度（WoE 校準）──────────────────
        # secure-account-login-verify-paypal.com 類型攻擊
        parts = host.split(".")
        reg_domain = parts[-2] if len(parts) >= 2 else host
        hyphen_count = reg_domain.count("-")
        if hyphen_count >= _HYPHEN_THRESHOLD:
            score += 0.05
            flags.add("high_hyphen_density")
            indicators.append(
                f"high_hyphen_density: {hyphen_count} hyphens in '{reg_domain}'"
            )

        # ── ⑧ 子域名深度：已移除 ─────────────────────────
        # 實測 WoE -0.33（P(釣魚|dot>=4) = 10.6% < 基準率 14.2%），
        # 命中者多為 www.xxx.edu.au / www.xxx.co.jp 這類正常多段 TLD。
        # 原本 +0.12 是反向加分，直接刪除。

        # ── ⑨ 顯式非標準 Port（unfitted）─────────────────
        port = str(parsed.port) if parsed.port else ""
        if port and port not in _LEGIT_PORTS:
            score += 0.12
            flags.add("non_standard_port")
            indicators.append(f"non_standard_port: :{port}")

    except Exception:
        pass

    return min(0.60, score), indicators, flags


# ══════════════════════════════════════════════════════════════
#  HTML 結構分析：表單傳輸目標 + 資源盜連 + 隱藏 iframe
#  （特徵 1 / 4 / 5 中需要「比對 host」才能判斷的部分，
#    純 regex 做不到 —— 必須知道頁面自己是誰）
# ══════════════════════════════════════════════════════════════

_FORM_BLOCK_RE  = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_ACTION_ATTR_RE = re.compile(r"\baction\s*=\s*['\"]([^'\"]*)['\"]", re.I)
# 憑證欄位：type=password，或 name/id 帶有金融/身分關鍵字
_CRED_FIELD_RE  = re.compile(
    r"<input\b[^>]*(?:type\s*=\s*['\"]?password"
    r"|(?:name|id)\s*=\s*['\"]?(?:pass|passwd|password|pwd|cvv|cvc|"
    r"card(?:number|no)?|ssn|pin|otp)\b)",
    re.I,
)
# 表單驗證屬性：合法登入頁幾乎必有其一
_VALIDATION_ATTR_RE = re.compile(
    r"\b(?:required\b|pattern\s*=|minlength\s*=|maxlength\s*=|type\s*=\s*['\"]?email)", re.I
)
# 釣魚套件常見的收件腳本檔名
_KIT_SCRIPT_RE = re.compile(
    r"/(?:login|next|post|send|mail|verify|result|action|process|submit|data)\d*\.php\b", re.I
)
_IFRAME_TAG_RE = re.compile(r"<iframe\b[^>]*>", re.I)
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0"
    r"|(?:width|height)\s*=\s*['\"]?0\b|\bhidden\b", re.I
)
_ASSET_URL_RE = re.compile(
    r"<(?:img|script|link)\b[^>]*?\b(?:src|href)\s*=\s*['\"](https?://[^'\"]+)['\"]", re.I
)

# 全網通用 CDN / 分析服務：任何網站引用都正常，不算盜連、隱藏 iframe 也合法
_COMMON_THIRD_PARTY = {
    "googletagmanager.com", "google-analytics.com", "googleapis.com",
    "gstatic.com", "doubleclick.net", "googlesyndication.com",
    "googleadservices.com", "facebook.net", "hotjar.com", "clarity.ms",
    "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net",
    "unpkg.com", "bootstrapcdn.com", "jquery.com", "cdnjs.com",
    "fontawesome.com", "typekit.net", "youtube.com", "vimeo.com",
    "recaptcha.net", "hcaptcha.com", "cloudflare.net",
}

# 合法 SSO / IdP：憑證表單 POST 到這些網域是正常的單一登入，不是外洩
# （沒有這份白名單，所有用 Okta / Auth0 / Azure AD 的企業站都會被誤判）
_SSO_PROVIDERS = {
    "okta.com", "okta-emea.com", "auth0.com", "onelogin.com",
    "pingidentity.com", "pingone.com", "duosecurity.com",
    "microsoftonline.com", "windows.net", "live.com", "microsoft.com",
    "accounts.google.com", "google.com", "apple.com", "facebook.com",
    "github.com", "gitlab.com", "salesforce.com", "oraclecloud.com",
    "amazoncognito.com", "cloudflareaccess.com", "jumpcloud.com",
}

# 品牌官方域名的扁平集合（供盜連比對用）
_ALL_BRAND_DOMAINS = {d for s in BRAND_OFFICIAL_DOMAINS.values() for d in s}


def _analyze_html_structure(html: str, url: str) -> tuple:
    """
    HTML 結構釣魚偵測

    ① 表單傳輸目標異常（最核心特徵）
       憑證表單的 action 指向：裸 IP / 免費主機 / 任何跨網域目標 / 套件腳本檔名
    ② 資源盜連（Hotlinking）
       頁面自己不是該品牌，卻直接引用品牌官網的 logo / css
    ③ 隱藏 iframe（排除 GTM / analytics 等合法用法）
    ④ 憑證表單缺乏任何前端驗證屬性（粗劣前端邏輯）

    回傳 (score_boost: float, indicators: list[str], flags: set[str])，score 上限 0.60
    """
    if not html:
        return 0.0, [], set()

    score, indicators, flags = 0.0, [], set()
    page_host = (urlparse(url).hostname or "").lower()
    page_reg  = _registered_domain(page_host)

    def _in(reg: str, domains: set) -> bool:
        return any(reg == d or reg.endswith("." + d) for d in domains)

    # ── ① 憑證表單的 action ───────────────────────────────────
    for attrs, body in _FORM_BLOCK_RE.findall(html):
        if not _CRED_FIELD_RE.search(body):
            continue          # 非憑證表單（搜尋框 / 電子報）→ 跳過
        flags.add("cred_form")

        m      = _ACTION_ATTR_RE.search(attrs)
        action = (m.group(1).strip() if m else "")

        if action and not action.lower().startswith(("javascript:", "#", "mailto:")):
            target      = urljoin(url, action)
            target_host = (urlparse(target).hostname or "").lower()
            target_reg  = _registered_domain(target_host)

            if target_host and _IP_HOST_RE.match(target_host):
                score += 0.45
                flags.add("form_action_to_ip")
                indicators.append(f"form_action_to_ip: {target_host}")
            elif (target_reg and target_reg != page_reg
                  and not _in(target_reg, _COMMON_THIRD_PARTY)
                  and not _in(target_reg, _SSO_PROVIDERS)):
                # 免費主機 / 動態 DNS 目標沒有任何合法 SSO 情境 → 決定性
                if _in(target_reg, SUSPICIOUS_HOSTING | SUSPICIOUS_REGISTRARS):
                    score += 0.45
                    flags.add("form_action_free_host")
                else:
                    score += 0.35
                    flags.add("form_action_cross_domain")
                indicators.append(f"form_action_cross_domain: {page_reg} → {target_reg}")
            elif _KIT_SCRIPT_RE.search(urlparse(target).path):
                score += 0.12
                flags.add("form_action_kit_script")
                indicators.append(f"form_action_kit_script: {urlparse(target).path}")

        # ── ④ 完全沒有驗證屬性 → 粗劣前端（照單全收）─────────
        if not _VALIDATION_ATTR_RE.search(body):
            score += 0.05
            flags.add("form_without_validation")
            indicators.append("form_without_validation: 憑證表單無任何驗證屬性")

    # ── ② 品牌資源盜連 ────────────────────────────────────────
    hotlinked = set()
    for asset in _ASSET_URL_RE.findall(html):
        asset_reg = _registered_domain(urlparse(asset).hostname or "")
        if not asset_reg or asset_reg == page_reg or _in(asset_reg, _COMMON_THIRD_PARTY):
            continue
        if asset_reg in _ALL_BRAND_DOMAINS:
            hotlinked.add(asset_reg)
    if hotlinked:
        # 只有頁面同時在收憑證時才視為仿冒（純新聞引用品牌圖不算）
        score += 0.25 if "cred_form" in flags else 0.08
        flags.add("brand_asset_hotlink")
        indicators.append(f"brand_asset_hotlink: {','.join(sorted(hotlinked)[:3])}")

    # ── ③ 隱藏 iframe ─────────────────────────────────────────
    for tag in _IFRAME_TAG_RE.findall(html):
        if not _HIDDEN_STYLE_RE.search(tag):
            continue
        src_m   = re.search(r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]", tag, re.I)
        src_reg = _registered_domain(urlparse(urljoin(url, src_m.group(1))).hostname or "") if src_m else ""
        if src_reg and _in(src_reg, _COMMON_THIRD_PARTY):
            continue          # GTM noscript iframe 等合法隱藏 iframe
        score += 0.12
        flags.add("hidden_iframe")
        indicators.append(f"hidden_iframe: {(src_reg or 'inline')}")
        break                 # 每頁只計一次

    return min(0.60, score), indicators, flags


def _format_indicators(indicator_hits: dict) -> list:
    return [f"{cat}: {', '.join(str(h) for h in hits[:2])}"
            for cat, hits in indicator_hits.items()]


# 惡意機制類別：Node 4 用來判斷「這份 HTML 裡有沒有釣魚機制」。
# 只收「行為」類別 —— URL 詞彙 / 結構特徵不算頁面內的機制，
# 因為 BOT 與 HUMAN 拿的是同一個 URL，那些特徵兩邊必然相同，比對不出差異。
MALICIOUS_MECHANISM_FLAGS = {
    "webhook_exfiltration", "form_credential_targeting", "credential_harvesting",
    "devtools_blocking", "code_obfuscation_exec", "post_submit_deception",
    "mail_exfiltration", "timed_cloaking_redirect", "ua_bot_detection",
    "anti_analysis", "malicious_redirect", "data_exfiltration",
    "cred_form", "form_action_to_ip", "form_action_free_host",
    "form_action_cross_domain", "form_action_kit_script",
    "brand_asset_hotlink", "hidden_iframe",
}


def evaluate_page(html: str, url: str = "", extra_js: str = "") -> dict:
    """
    對單一份 HTML 套用 Node 3 的釣魚判準（Layer 1 布林裁決 + Layer 2 累加），不含 LLM。

    Node 3 與 Node 4 共用同一個實作 —— Node 4 的雙瀏覽器比對必須用「和判定釣魚
    完全一樣的標準」去看 BOT 與 HUMAN 兩份頁面，否則比出來的差異沒有意義。

    回傳 {
      "is_phishing": bool,          # 純規則判定（未含混淆加成與 LLM）
      "decisive":    list[str],     # 觸發的 Layer 1 規則 id
      "flags":       set[str],      # 所有命中的條件名稱
      "mechanisms":  set[str],      # flags ∩ MALICIOUS_MECHANISM_FLAGS
      "indicators":  dict,          # category → hits
      "score":       float,         # Layer 2 累加分數
    }
    """
    content = (html or "") + "\n" + (extra_js or "")
    indicator_hits, flags, score = {}, set(), 0.0

    for category, rule in PHISHING_RULES.items():
        hits = [p for p in rule["patterns"]
                if re.search(p, content, re.IGNORECASE)]
        if hits:
            indicator_hits[category] = hits
            flags.add(category)
            score += rule["weight"] * min(1.0, len(hits) / 3)

    for key, (boost, inds, fl) in (
        ("html_structure", _analyze_html_structure(html or "", url)),
        ("url_semantics",  _analyze_url_semantics(url)),
        ("url_structure",  _analyze_url_structure(url)),
        ("url_lexical",    _analyze_url_lexical(url)),
    ):
        flags |= fl
        if inds:
            indicator_hits.setdefault(key, []).extend(inds)
            score = min(1.0, score + boost)

    decisive = [r["id"] for r in DECISIVE_RULES
                if all(f in flags for f in r["flags"])]
    for r in DECISIVE_RULES:
        if r["id"] in decisive:
            indicator_hits.setdefault("decisive_rule", []).append(f"[{r['id']}] {r['label']}")

    if not decisive:
        counts = {c: len(h) for c, h in indicator_hits.items()}
        for combo in COMBO_RULES:
            if all(counts.get(cat, 0) >= n for cat, n in combo["required"].items()):
                score = min(1.0, score + combo["bonus"])
                indicator_hits.setdefault("combo_signal", []).append(combo["label"])

    return {
        "is_phishing": bool(decisive) or score >= PHISHING_CONFIDENCE_THRESHOLD,
        "decisive":    decisive,
        "flags":       flags,
        "mechanisms":  flags & MALICIOUS_MECHANISM_FLAGS,
        "indicators":  indicator_hits,
        "score":       min(LAYER2_CONFIDENCE_CAP, score),
    }


def classify_phishing_node(state: AnalysisState, llm) -> AnalysisState:
    """
    Node 3: 判斷是否為釣魚網站（兩層架構）

      Layer 1  布林裁決：特異性夠高、合法網站無合理情境的條件，
                        連言命中即定案，不計分、不呼叫 LLM。
      Layer 2  統計累加：弱訊號（URL 詞彙、泛用 JS pattern）加權後比對閾值。
                        URL 詞彙權重已用 Dataset.csv 的 WoE 校準。

    瀏覽器指紋兩層都不計分（僅代表區分真人/爬蟲，屬 cloaking，由 Node 4 處理）。
    """
    print("\n[Node 3] 判斷釣魚網站...")

    all_content = state["raw_html"] + "\n" + "\n".join(
        s["deobfuscated"] for s in state["deobfuscated_js"]
    )
    # 注意：不對 all_content 做 .lower()。
    # 改為在每次 re.search 加 re.IGNORECASE，確保 XMLHttpRequest、sendBeacon 等
    # 大小寫混合 pattern 都能正確命中。

    # ══════════════════════════════════════════════════════════
    #  規則評估（與 Node 4 共用同一實作，避免兩處判準漂移）
    # ══════════════════════════════════════════════════════════
    result = evaluate_page(
        state.get("raw_html", ""),
        state.get("url", ""),
        extra_js="\n".join(s["deobfuscated"] for s in state["deobfuscated_js"]),
    )
    indicator_hits = result["indicators"]
    rule_score     = result["score"]

    for cat in ("html_structure", "url_semantics", "url_structure", "url_lexical"):
        if cat in indicator_hits:
            print(f"  → [{cat}] {indicator_hits[cat]}")
    for lbl in indicator_hits.get("combo_signal", []):
        print(f"  → [組合信號] {lbl}")

    # ── 瀏覽器指紋：不計分 ────────────────────────────────
    # 指紋採集只說明「網站想分辨真人與自動爬蟲」，是 cloaking 的手段，
    # 不是釣魚的證據 —— 合法企業（GTM / Hotjar / reCAPTCHA）採集得更兇。
    # 這項資訊留給 Node 4 做 cloaking 判定，此處完全不加權。

    # ══════════════════════════════════════════════════════════
    #  Layer 1：布林裁決 —— 命中即定案，跳過評分與 LLM
    # ══════════════════════════════════════════════════════════
    if result["decisive"]:
        for line in indicator_hits.get("decisive_rule", []):
            print(f"  → [布林裁決] {line}")
        state["is_phishing"]         = True
        state["phishing_confidence"] = DECISIVE_CONFIDENCE
        state["phishing_indicators"] = _format_indicators(indicator_hits)
        print(f"  → 判定: ⚠️  釣魚網站（Layer 1 布林裁決 "
              f"{','.join(result['decisive'])}）")
        return state

    # ══════════════════════════════════════════════════════════
    #  Layer 2：統計累加 —— 只處理弱訊號，需跨過閾值
    # ══════════════════════════════════════════════════════════

    # ── 混淆程度加權 ──────────────────────────────────────
    high_obf_count = sum(
        1 for s in state["deobfuscated_js"]
        if s.get("obfuscation_score", 0) > 0.6
    )
    if high_obf_count:
        rule_score += min(0.15, high_obf_count * 0.05)
        indicator_hits["heavy_obfuscation"] = [f"{high_obf_count} 個高混淆腳本"]

    # ── LLM 語意分析 ──────────────────────────────────────
    # 預設 0.0：LLM 若失敗/超時，不應憑空替 score 加分。
    llm_confidence = 0.0
    # 縮減至 800 chars：deepseek-coder 處理長輸入容易超時
    snippet = all_content[:800]
    # 以「程式碼分析」框架呈現任務，避免 deepseek-coder 觸發 cybersecurity refusal
    prompt = (
        "Analyze this JavaScript/HTML code for phishing attack patterns.\n"
        "Look for: credential harvesting forms, suspicious redirects, "
        "brand name misuse, anti-debugging tricks.\n"
        "Respond ONLY with valid JSON on a single line, no explanation:\n"
        '{"is_phishing": true/false, "confidence": 0.0-1.0, '
        '"key_indicators": ["pattern1"]}\n\n'
        f"Code:\n{snippet}"
    )

    try:
        from concurrent.futures import ThreadPoolExecutor
        # 不使用 with 語句：with 的 __exit__ 呼叫 shutdown(wait=True)，
        # future.result(timeout=90) 超時後仍會等待 llm.invoke thread 結束 → 永久阻塞。
        _llm_executor = ThreadPoolExecutor(max_workers=1)
        try:
            future = _llm_executor.submit(llm.invoke, prompt)
            llm_response = future.result(timeout=90)
        finally:
            _llm_executor.shutdown(wait=False)
        json_match = re.search(r'\{[^{}]*"is_phishing"[^{}]*\}', llm_response, re.DOTALL)
        if not json_match:
            json_match = re.search(r'\{.*\}', llm_response, re.DOTALL)
        if json_match:
            llm_result = json.loads(json_match.group())
            llm_confidence = float(llm_result.get("confidence", 0.0))
            for ind in llm_result.get("key_indicators", []):
                indicator_hits.setdefault("llm_detected", []).append(ind)
    except Exception as e:
        errs = state.get("errors", [])
        errs.append(f"[Node3] LLM error: {e}")
        state["errors"] = errs

    # ── 最終信心度融合 ────────────────────────────────────
    blended    = rule_score * 0.7 + llm_confidence * 0.3
    confidence = min(LAYER2_CONFIDENCE_CAP, max(rule_score, blended))

    is_phishing = confidence >= PHISHING_CONFIDENCE_THRESHOLD

    state["is_phishing"]         = is_phishing
    state["phishing_confidence"] = round(confidence, 3)
    state["phishing_indicators"] = _format_indicators(indicator_hits)

    status = "⚠️  釣魚網站" if is_phishing else "✅ 正常網站"
    print(f"  → 判定: {status}（Layer 2 累加）| 信心度: {confidence:.2%}")
    return state
