"""
dual_crawler.py  雙重爬取層（BOT ‖ HUMAN）

從 node4_cloaking_analyzer.py 抽出，因為架構調整後「取得兩份頁面」
發生在 Node 1，而不再是 Node 4 的內部步驟：

  BOT   = 純爬蟲。_BOT_EXPOSE_JS 主動暴露 webdriver / headless 特徵，
          不做任何偽裝 —— 目的是讓有 cloaking 的伺服器認出它是機器人。
  HUMAN = 盡可能模仿真人。_STEALTH_JS 修補所有自動化痕跡，
          外加 Google session 預熱與貝茲曲線滑鼠軌跡。

兩者並行（錯開 stagger 秒），回傳結構相同的 result dict，
交給 Node 3 判釣魚（用 HUMAN 那份）與 Node 4 比對 cloaking（比兩份的差異）。
"""
import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import os
import re
import time
import random
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# ── 網路層：Proxy 設定（可選）────────────────────────────────
# 從環境變數讀取，不設定則不使用 proxy
# 建議使用住宅代理 (Residential Proxy) 以避免 ASN 被標記為資料中心
# 範例: export CLOAKING_PROXY="http://user:pass@proxy.provider.com:8080"
PROXY_URL: str = os.environ.get("CLOAKING_PROXY", "")

# BOT / HUMAN 各自的出口，讓 IP 也成為極端化維度之一。
#
# 為什麼要拆開：形式模型把可觀測請求屬性定義為
#   ℛ = UA × IP × Headers × TLS × JS_props × Behavior，
# 並主張兩個身分在 ℛ 上「最大分離」。但只用單一 CLOAKING_PROXY 時，
# 兩邊走同一個出口 IP —— IP 這個維度完全沒有分離，而 CrawlPhish 與
# PhishParrot 都指出 IP-based cloaking 是最主流的手法之一。
# 換句話說，不拆開的話「最大分離」這個假設在實作上是假的，
# 純 IP 判別的 cloaking 對這個差分是全盲的（兩端拿到相同待遇 → 無差異 → 漏報）。
#
# 建議配置：BOT 走資料中心 IP（易被識別為爬蟲），HUMAN 走住宅 IP。
# 未設定則各自 fallback 回 CLOAKING_PROXY，維持與舊設定相容。
BOT_PROXY_URL: str   = os.environ.get("CLOAKING_PROXY_BOT",   PROXY_URL)
HUMAN_PROXY_URL: str = os.environ.get("CLOAKING_PROXY_HUMAN", PROXY_URL)


def _proxy_for(is_human: bool) -> str:
    return HUMAN_PROXY_URL if is_human else BOT_PROXY_URL

# ── 網路層：curl_cffi TLS 指紋偽裝（可選）────────────────────
# 安裝: pip install curl_cffi
# 啟用後 BOT 的初始 HTTP 請求 JA3/JA4 指紋與 Python requests 不同，
# HUMAN 的指紋則與真實 Chrome 125 一致
try:
    from curl_cffi import requests as _cffi_requests
    CURL_CFFI_AVAILABLE = True
    logger.info("curl_cffi 已載入，TLS 指紋偽裝啟用")
except ImportError:
    CURL_CFFI_AVAILABLE = False
    import requests as _std_requests
    logger.debug("curl_cffi 未安裝，使用標準 requests (Python TLS 指紋)")


# ── 動態驗證常數 ──────────────────────────────────────────────
MAX_CONTENT_LEN      = 60_000
LOAD_TIMEOUT         = 25_000
PREWARM_TIMEOUT      = 15_000
BOT_HUMAN_DELAY      = (2.0, 4.0)   # 並行模式下只作為 stagger，不再等待 BOT 完成

# BOT：不加 AutomationControlled 抑制旗標，讓 webdriver=true 完整暴露
_BOT_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-http2",
    # 刻意不加 --disable-blink-features=AutomationControlled
    # → navigator.webdriver 維持 true，讓 cloaking JS 偵測到
    #
    # --disable-http2 的作用：
    #   某些伺服器在偵測到爬蟲 UA 後，不回傳 HTTP 403，
    #   而是直接在 HTTP/2 協議層送出 RST_STREAM / GOAWAY frame，
    #   導致 Playwright 拋出 ERR_HTTP2_PROTOCOL_ERROR。
    #   強制使用 HTTP/1.1 可繞過此協議層封鎖，讓 BOT 拿到完整頁面供比對。
    #   注意：即使加了此旗標，協議層封鎖本身仍會被下方信號邏輯捕捉。
]

# HUMAN：抑制所有自動化旗標
_HUMAN_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-blink-features=AutomationControlled",
]

# BOT：刻意使用奇怪的 viewport、無語言偏好、無 Referer
# 目標是讓 cloaking JS 的多個偵測維度都命中
BOT_CONTEXT_OPTIONS = {
    "user_agent": (
        "Mozilla/5.0 (compatible; Googlebot/2.1; "
        "+http://www.google.com/bot.html)"
    ),
    "extra_http_headers": {
        "Accept": "text/html,application/xhtml+xml",
        "From":   "googlebot(at)googlebot.com",
        # 刻意不設 Accept-Language → navigator.languages 顯示空或預設值
        # 刻意不設 Referer → document.referrer 為空字串
    },
    "locale":      "en-US",
    "timezone_id": "UTC",
    # 1024×768：老舊爬蟲常見解析度，與 HUMAN 的 1440×900 形成明顯差距
    "viewport":    {"width": 1024, "height": 768},
    # 刻意不設 geolocation → 讓 navigator.geolocation 行為異常
}

# ── HUMAN profile 預設集 ─────────────────────────────────────
# 為什麼要參數化：極端化處理的是「bot ↔ human」這條軸，但 PhishParrot
# (IEEE GLOBECOM 2025) 實測攻擊者的 targeting 大量發生在「地理 / 平台」軸上
# —— 觀察到 91 種不同的最佳 profile，其中日本住宅網路佔 53.83%、
# 美國資料中心 30.71%、macOS Safari + 日本住宅 8.77%。
# 這兩條軸是正交的：把 bot 特徵推到極端，不會讓一個「只服務日本行動用戶」的
# kit 認為我們的台灣桌機 HUMAN 是目標；那種情況兩端都拿到 decoy，
# 對稱 → 機制集合差為空 → 漏報。
#
# 因此本系統的主張不是「兩個 profile 就能觸及所有 cloaked 內容」，而是
# 「一組極端化的配對是做出 cloaking 判定的最小單位」：profile 的『選擇』
# 與 profile 的『差分』是可分離的，前者可由 PhishParrot 式的最佳化供給，
# 後者（本系統）不受影響。這些預設值就是讓該主張可被實驗檢驗的旋鈕。
_ACCEPT_HTML = (
    "text/html,application/xhtml+xml,application/xml;"
    "q=0.9,image/avif,image/webp,*/*;q=0.8"
)
_UA_WIN_CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
_UA_ANDROID_CHROME = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
)
_UA_MAC_SAFARI = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
)

HUMAN_PROFILES = {
    # 預設：與先前版本完全相同，換 profile 才會改變行為
    "tw-desktop": {
        "user_agent": _UA_WIN_CHROME,
        "extra_http_headers": {
            "Accept": _ACCEPT_HTML,
            "Accept-Language": "zh-TW,zh;q=0.9,en-US;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
        },
        "locale": "zh-TW", "timezone_id": "Asia/Taipei",
        "viewport": {"width": 1440, "height": 900},
        "geolocation": {"latitude": 25.033, "longitude": 121.565},
        "permissions": ["geolocation"],
    },
    # PhishParrot 觀察到的最大宗目標（日本住宅網路合計 53.83%）
    "jp-mobile": {
        "user_agent": _UA_ANDROID_CHROME,
        "extra_http_headers": {
            "Accept": _ACCEPT_HTML,
            "Accept-Language": "ja-JP,ja;q=0.9,en-US;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
        },
        "locale": "ja-JP", "timezone_id": "Asia/Tokyo",
        "viewport": {"width": 390, "height": 844},
        "is_mobile": True, "has_touch": True, "device_scale_factor": 3,
        "geolocation": {"latitude": 35.6895, "longitude": 139.6917},
        "permissions": ["geolocation"],
    },
    "jp-desktop": {
        "user_agent": _UA_WIN_CHROME,
        "extra_http_headers": {
            "Accept": _ACCEPT_HTML,
            "Accept-Language": "ja-JP,ja;q=0.9,en-US;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
        },
        "locale": "ja-JP", "timezone_id": "Asia/Tokyo",
        "viewport": {"width": 1440, "height": 900},
        "geolocation": {"latitude": 35.6895, "longitude": 139.6917},
        "permissions": ["geolocation"],
    },
    "us-desktop": {
        "user_agent": _UA_WIN_CHROME,
        "extra_http_headers": {
            "Accept": _ACCEPT_HTML,
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        },
        "locale": "en-US", "timezone_id": "America/New_York",
        "viewport": {"width": 1920, "height": 1080},
        "geolocation": {"latitude": 40.7128, "longitude": -74.0060},
        "permissions": ["geolocation"],
    },
    # PhishParrot Table V 第四名（8.77%）：攻擊者對 Apple 用戶的偏好
    "jp-mac-safari": {
        "user_agent": _UA_MAC_SAFARI,
        "extra_http_headers": {
            "Accept": _ACCEPT_HTML,
            "Accept-Language": "ja-JP,ja;q=0.9,en-US;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
        },
        "locale": "ja-JP", "timezone_id": "Asia/Tokyo",
        "viewport": {"width": 1512, "height": 982},
        "geolocation": {"latitude": 35.6895, "longitude": 139.6917},
        "permissions": ["geolocation"],
    },
}

HUMAN_PROFILE_NAME = os.environ.get("HUMAN_PROFILE", "tw-desktop").lower()
if HUMAN_PROFILE_NAME not in HUMAN_PROFILES:
    logger.warning("未知的 HUMAN_PROFILE=%r，可用: %s；退回 tw-desktop",
                   HUMAN_PROFILE_NAME, ", ".join(HUMAN_PROFILES))
    HUMAN_PROFILE_NAME = "tw-desktop"

HUMAN_CONTEXT_OPTIONS = HUMAN_PROFILES[HUMAN_PROFILE_NAME]

# ── BOT 主動暴露腳本 ─────────────────────────────────────────
# 與 HUMAN 的 _STEALTH_JS 相反：主動還原 / 強化 bot 特徵
# 讓 cloaking JS 在多個維度都能偵測到我們是爬蟲
_BOT_EXPOSE_JS = r"""
// 確保 navigator.webdriver = true（防止某些環境被意外覆蓋）
Object.defineProperty(navigator, 'webdriver', { get: () => true, configurable: true });

// plugins 為空（典型爬蟲特徵）
Object.defineProperty(navigator, 'plugins', { get: () => [], configurable: true });

// languages 為空陣列（沒有語言偏好）
Object.defineProperty(navigator, 'languages', { get: () => [], configurable: true });

// 移除 chrome 物件（真正的 Googlebot 沒有 window.chrome）
try { delete window.chrome; } catch(e) {}

// outerHeight / outerWidth 設為 0（headless 預設值，刻意保留）
Object.defineProperty(window, 'outerHeight', { get: () => 0, configurable: true });
Object.defineProperty(window, 'outerWidth',  { get: () => 0, configurable: true });

// hardwareConcurrency 設為 1（低階爬蟲環境）
Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 1, configurable: true });

// deviceMemory 設為 0.25（最低值）
Object.defineProperty(navigator, 'deviceMemory', { get: () => 0.25, configurable: true });

// connection 設為慢速（爬蟲不模擬網路品質）
Object.defineProperty(navigator, 'connection', {
    get: () => ({ effectiveType: 'slow-2g', rtt: 2000, downlink: 0.4, saveData: true }),
    configurable: true
});
"""

_STEALTH_JS = r"""
// ── 0. 原生函式偽裝（必須在所有修補之前執行）──────────────────
// 依據 Amin Azad et al., "Taming the Shape Shifter: Detecting Anti-fingerprinting
// Browsers" (2020)：JS 注入式的指紋偽裝可被 Function.prototype.toString 直接拆穿 ——
// 原生函式回傳 "function x() { [native code] }"，而我們覆寫上去的 JS 函式會把
// 整段原始碼吐出來。不補這一層，下面 17 個修補全部等於白做：攻擊者只要一行
// Permissions.prototype.query.toString() 就知道這是自動化瀏覽器。
(() => {
    const _nativeToString = Function.prototype.toString;
    const _masked = new WeakMap();
    const patchedToString = function () {
        if (_masked.has(this)) return _masked.get(this);
        return _nativeToString.call(this);
    };
    // toString 自己也要偽裝，否則 Function.prototype.toString.toString() 露餡
    _masked.set(patchedToString, 'function toString() { [native code] }');
    Function.prototype.toString = patchedToString;
    // 供下方修補使用；腳本結尾會刪除，避免自己留下比 webdriver 更明顯的指紋
    window.__mask = (fn, name) => {
        _masked.set(fn, 'function ' + name + '() { [native code] }');
        return fn;
    };
})();
// 綁進區域常數：下面有些 getter 是「存取時才執行」的（例如 navigator.plugins
// 每次讀取都重建陣列），若它們在函式體內寫 window.__mask，等腳本結尾把
// window.__mask 刪掉之後，那個 getter 一被存取就會 TypeError —— 整個
// navigator.plugins 直接壞掉，比沒偽裝還明顯。改用閉包捕獲的區域常數就不受刪除影響。
const _m = window.__mask;
// ── 1. navigator.webdriver ────────────────────────────────────
Object.defineProperty(navigator, 'webdriver', {
    get: _m(() => false, 'get webdriver'),
    configurable: true
});

// ── 2. navigator.plugins (headless 下為空) ────────────────────
const _plugins = [
    { name: 'Chrome PDF Plugin',       filename: 'internal-pdf-viewer',   description: 'Portable Document Format' },
    { name: 'Chrome PDF Viewer',       filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
    { name: 'Native Client',           filename: 'internal-nacl-plugin',  description: '' },
];
Object.defineProperty(navigator, 'plugins', {
    get: _m(() => {
        const arr = Object.assign([], _plugins);
        arr.namedItem = _m((n) => arr.find(p => p.name === n) || null, 'namedItem');
        arr.refresh   = _m(() => {}, 'refresh');
        arr.item      = _m((i) => arr[i], 'item');
        arr[Symbol.iterator] = Array.prototype[Symbol.iterator];
        return arr;
    }, 'get plugins')
});

// ── 3. navigator.languages ────────────────────────────────────
Object.defineProperty(navigator, 'languages', {
    get: _m(() => ['zh-TW', 'zh', 'en-US', 'en'], 'get languages'),
    configurable: true
});

// ── 4. window.chrome (headless 下缺失) ───────────────────────
if (!window.chrome) {
    window.chrome = {
        app: { isInstalled: false, InstallState: {}, RunningState: {} },
        runtime: {
            OnInstalledReason: {},
            OnRestartRequiredReason: {},
            PlatformArch: {},
            PlatformOs: {},
            RequestUpdateCheckStatus: {},
            connect: _m(() => {}, 'connect'),
            sendMessage: _m(() => {}, 'sendMessage')
        },
        loadTimes: _m(function() {
            return {
                commitLoadTime: Date.now() / 1000 - Math.random() * 2,
                connectionInfo: 'h2',
                finishDocumentLoadTime: 0,
                finishLoadTime: 0,
                firstPaintAfterLoadTime: 0,
                firstPaintTime: 0,
                navigationType: 'Other',
                npnNegotiatedProtocol: 'h2',
                requestTime: Date.now() / 1000 - Math.random() * 3,
                startLoadTime: Date.now() / 1000 - Math.random() * 2.5,
                wasAlternateProtocolAvailable: false,
                wasFetchedViaSpdy: true,
                wasNpnNegotiated: true
            };
        }, 'loadTimes'),
        csi: _m(function() {
            return { onloadT: Date.now(), pageT: Math.random() * 5000 + 1000, startE: Date.now() - 3000, tran: 15 };
        }, 'csi')
    };
}

// ── 5. permissions API ────────────────────────────────────────
const _origQuery = window.Permissions && window.Permissions.prototype.query;
if (_origQuery) {
    window.Permissions.prototype.query = _m(function(perm) {
        if (perm.name === 'notifications') {
            return Promise.resolve({ state: Notification.permission });
        }
        return _origQuery.call(this, perm);
    }, 'query');
}

// ── 6. outerHeight / outerWidth ───────────────────────────────
Object.defineProperty(window, 'outerHeight', { get: _m(() => 1040, 'get outerHeight'), configurable: true });
Object.defineProperty(window, 'outerWidth',  { get: _m(() => 1440, 'get outerWidth'), configurable: true });
Object.defineProperty(window, 'screenY',     { get: _m(() => 23, 'get screenY'), configurable: true });
Object.defineProperty(window, 'screenX',     { get: _m(() => 0, 'get screenX'), configurable: true });

// ── 7. Canvas 指紋 ────────────────────────────────────────────
const _toDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = _m(function(type, quality) {
    if (this.width > 10 && this.height > 10) {
        const ctx = this.getContext('2d');
        if (ctx) {
            const _imageData = ctx.getImageData;
            ctx.getImageData = _m(function(x, y, w, h) {
                const data = _imageData.call(this, x, y, w, h);
                const noise = 1;
                for (let i = 0; i < data.data.length; i += 100) {
                    data.data[i] = Math.min(255, data.data[i] + (Math.random() > 0.5 ? noise : -noise));
                }
                return data;
            }, 'getImageData');
        }
    }
    return _toDataURL.call(this, type, quality);
}, 'toDataURL');

// ── 8. WebGL 指紋 ─────────────────────────────────────────────
const _getParam = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = _m(function(param) {
    if (param === 37445) return 'Intel Inc.';
    if (param === 37446) return 'Intel Iris OpenGL Engine';
    return _getParam.call(this, param);
}, 'getParameter');
if (typeof WebGL2RenderingContext !== 'undefined') {
    const _getParam2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = _m(function(param) {
        if (param === 37445) return 'Intel Inc.';
        if (param === 37446) return 'Intel Iris OpenGL Engine';
        return _getParam2.call(this, param);
    }, 'getParameter');
}

// ── 9. AudioContext 指紋 ──────────────────────────────────────
if (typeof AudioContext !== 'undefined') {
    const _createOscillator = AudioContext.prototype.createOscillator;
    AudioContext.prototype.createOscillator = _m(function() {
        const osc = _createOscillator.call(this);
        const _origConnect = osc.connect.bind(osc);
        osc.connect = _m(function(dest) {
            try { return _origConnect(dest); } catch(e) {}
        }, 'connect');
        return osc;
    }, 'createOscillator');
}

// ── 10. navigator.connection ──────────────────────────────────
Object.defineProperty(navigator, 'connection', {
    get: _m(() => ({
        effectiveType: '4g',
        rtt: 50 + Math.floor(Math.random() * 50),
        downlink: 10,
        saveData: false,
    }), 'get connection'),
    configurable: true
});

// ── 11. navigator.hardwareConcurrency / deviceMemory ─────────
Object.defineProperty(navigator, 'hardwareConcurrency', { get: _m(() => 8, 'get hardwareConcurrency'), configurable: true });
Object.defineProperty(navigator, 'deviceMemory',        { get: _m(() => 8, 'get deviceMemory'), configurable: true });

// ── 12. Date.prototype.getTimezoneOffset ─────────────────────
Date.prototype.getTimezoneOffset = _m(function() { return -480; }, 'getTimezoneOffset');

// ── 13. Notification.permission ──────────────────────────────
// headless 下預設為 "default"，真實用戶通常是 "denied"
try {
    Object.defineProperty(Notification, 'permission', {
        get: _m(() => 'denied', 'get permission'),
        configurable: true
    });
} catch(e) {}

// ── 14. navigator.mediaDevices.enumerateDevices ───────────────
// headless 下回傳空陣列，真實用戶有麥克風 / 攝影機 / 喇叭
if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
    navigator.mediaDevices.enumerateDevices = _m(function() {
        return Promise.resolve([
            { deviceId: 'default', groupId: 'default', kind: 'audioinput',  label: '' },
            { deviceId: 'default', groupId: 'default', kind: 'audiooutput', label: '' },
            { deviceId: 'default', groupId: 'default', kind: 'videoinput',  label: '' },
        ]);
    }, 'enumerateDevices');
}

// ── 15. document.hasFocus ─────────────────────────────────────
// headless 下永遠回傳 false，真實用戶通常為 true
document.hasFocus = _m(function() { return true; }, 'hasFocus');

// ── 16. performance.memory ────────────────────────────────────
// headless 下結構異常，注入合理的記憶體使用值
try {
    Object.defineProperty(performance, 'memory', {
        get: _m(() => ({
            jsHeapSizeLimit:  2172649472,
            totalJSHeapSize:  Math.floor(Math.random() * 50000000) + 20000000,
            usedJSHeapSize:   Math.floor(Math.random() * 20000000) + 10000000,
        }), 'get memory'),
        configurable: true
    });
} catch(e) {}

// ── 17. screen.colorDepth / pixelDepth ───────────────────────
// headless 下可能回傳 24，真實螢幕通常為 24 或 30，明確設定避免異常值
Object.defineProperty(screen, 'colorDepth', { get: _m(() => 24, 'get colorDepth'), configurable: true });
Object.defineProperty(screen, 'pixelDepth',  { get: _m(() => 24, 'get pixelDepth'), configurable: true });

// ── 收尾：刪除 __mask ────────────────────────────────────────
// 不刪的話，window.__mask 本身就是一個比 navigator.webdriver 更明顯的自製指紋。
try { delete window.__mask; } catch(e) { window.__mask = undefined; }
"""


# ─────────────────────────────────────────────────────────────
# 動態雙瀏覽器驗證
# ─────────────────────────────────────────────────────────────
async def _prewarm_google_session(page, target_url: str) -> bool:
    try:
        await page.goto("https://www.google.com", timeout=PREWARM_TIMEOUT,
                        wait_until="domcontentloaded")
        await page.wait_for_timeout(random.randint(1000, 2000))
        await page.goto(target_url, timeout=LOAD_TIMEOUT,
                        wait_until="domcontentloaded",
                        referer="https://www.google.com/")
        return True
    except Exception as e:
        logger.debug(f"Google prewarm failed: {e}")
        try:
            await page.goto(target_url, timeout=LOAD_TIMEOUT, wait_until="domcontentloaded")
            return False
        except Exception:
            raise


async def _bezier_mouse_move(page, x1, y1, x2, y2, steps=20):
    cx = random.uniform(min(x1, x2), max(x1, x2))
    cy = random.uniform(min(y1, y2) - 100, max(y1, y2) + 100)
    for i in range(steps + 1):
        t = i / steps
        x = (1-t)**2 * x1 + 2*(1-t)*t * cx + t**2 * x2
        y = (1-t)**2 * y1 + 2*(1-t)*t * cy + t**2 * y2
        await page.mouse.move(x, y)
        await page.wait_for_timeout(random.randint(8, 35))


async def _human_behavior(page):
    vw, vh = 1440, 900
    cur_x = random.uniform(200, vw - 200)
    cur_y = random.uniform(100, vh - 200)
    for _ in range(random.randint(4, 6)):
        tx = random.uniform(100, vw - 100)
        ty = random.uniform(100, vh - 100)
        await _bezier_mouse_move(page, cur_x, cur_y, tx, ty)
        cur_x, cur_y = tx, ty
        await page.wait_for_timeout(random.randint(200, 600))
    for _ in range(random.randint(3, 5)):
        await page.evaluate(f"window.scrollBy({{top: {random.randint(150, 400)}, behavior: 'smooth'}});")
        await page.wait_for_timeout(random.randint(600, 1800))
    if random.random() < 0.4:
        await page.evaluate(f"window.scrollBy({{top: -{random.randint(50, 150)}, behavior: 'smooth'}})")
        await page.wait_for_timeout(random.randint(300, 800))


# ── 互動閘門跨越（只有 HUMAN 做）──────────────────────────────
# 為什麼這不是外掛補丁，而是「補完既有設計」：
# 形式模型把可觀測屬性定義為 ℛ = UA × IP × Headers × TLS × JS_props × Behavior，
# 但先前的實作只做了 Behavior 的一半（滑鼠移動與捲動），沒有點擊。
# CrawlPhish (IEEE S&P 2021) Table V 統計 User Interaction 類佔客戶端 cloaking
# 實作的 57.60%（ClickThrough 22.11% / Alert 17.19% / MouseDetection 16.53% /
# Notification 4.34%），而「BOT 不互動、HUMAN 互動」本身就是一條乾淨的極端化軸。
#
# 安全上限（不可放寬）：
#   ① 絕不點擊 <form> 內的元素或 type=submit —— 分析的是釣魚站，
#      誤點等於代替受害者把資料送給攻擊者，也可能觸發外部副作用。
#   ② 絕不解 CAPTCHA。那是 PhishDecloaker 一整篇論文的工作量，
#      且涉及法律與倫理問題。遇到就讓 Node 4 誠實回報 N/A。
#   ③ 只點「看起來像閘門」的元素，且最多點一個就停。
_GATE_TEXTS = [
    "continue", "proceed", "i am human", "i'm human", "verify", "enter",
    "click here", "view document", "access", "next",
    "繼續", "進入", "確認", "查看", "下一步",
    "続ける", "次へ", "確認する",
]

# 這些字樣代表「送出資料」而不是「跨越閘門」，即使不在 <form> 內也絕不點
_FORBIDDEN_TEXTS = [
    "sign in", "log in", "login", "signin", "submit", "send", "pay", "buy",
    "confirm payment", "delete", "登入", "登錄", "送出", "提交", "付款", "刪除",
]

_GATE_PROBE_JS = """(args) => {
  const [okTexts, badTexts] = args;
  const cands = document.querySelectorAll(
    'button, a[role=button], [onclick], input[type=button], div[class*=btn], div[class*=gate]');
  for (let i = 0; i < cands.length; i++) {
    const el = cands[i];
    // ── 安全鎖 ①：表單內元素、submit 一律跳過 ──
    if (el.closest('form')) continue;
    const t = (el.getAttribute('type') || '').toLowerCase();
    if (t === 'submit' || t === 'password') continue;
    // ── 安全鎖 ②：帶有送出語意的字樣一律跳過 ──
    const label = (el.innerText || el.value || el.getAttribute('aria-label') || '')
                    .trim().toLowerCase();
    if (!label || label.length > 40) continue;
    if (badTexts.some(b => label.includes(b))) continue;
    // ── 必須看起來像閘門 ──
    if (!okTexts.some(k => label.includes(k))) continue;
    // ── 必須可見且夠大（隱藏元素多半是陷阱或無關）──
    const r = el.getBoundingClientRect();
    if (r.width < 24 || r.height < 16) continue;
    const st = getComputedStyle(el);
    if (st.display === 'none' || st.visibility === 'hidden' || +st.opacity === 0) continue;
    el.setAttribute('data-cloakprobe', '1');
    return { found: true, label: label.slice(0, 40) };
  }
  return { found: false };
}"""


async def _cross_gates(page, result: dict):
    """
    嘗試跨越一個互動閘門。回傳是否有跨越動作發生（寫入 result['gate_crossed']）。
    任何失敗都只記錄、不拋出 —— 跨閘門是加分項，不能讓它拖垮整次爬取。
    """
    crossed = []
    # ── alert / confirm：Playwright 預設會自動 dismiss，改成 accept ──
    # CrawlPhish 統計 Alert 類佔 17.19%，且真人本來就會把 alert 按掉。
    try:
        page.on("dialog", lambda d: asyncio.ensure_future(d.accept()))
        crossed.append("dialog_auto_accept")
    except Exception as e:
        logger.debug(f"dialog handler 掛載失敗: {e}")

    # ── click gate ──
    try:
        probe = await asyncio.wait_for(
            page.evaluate(_GATE_PROBE_JS, [_GATE_TEXTS, _FORBIDDEN_TEXTS]), timeout=5.0)
        if probe and probe.get("found"):
            el = await page.query_selector("[data-cloakprobe='1']")
            if el:
                await el.click(timeout=3000)
                await page.wait_for_timeout(1800)
                crossed.append(f"click:{probe.get('label', '')}")
                logger.debug(f"跨越閘門: {probe.get('label')}")
    except Exception as e:
        logger.debug(f"閘門跨越失敗（不影響主流程）: {e}")

    result["gate_crossed"] = crossed
    return bool(crossed)


async def _fetch_with_playwright(url: str, *, is_human: bool) -> dict:
    from playwright.async_api import async_playwright
    try:
        from playwright.async_api import TargetClosedError
    except ImportError:
        # Playwright < 1.41 沒有 TargetClosedError，用通用 Exception 替代
        TargetClosedError = Exception
    from bs4 import BeautifulSoup

    result = {
        "status_code": 0, "final_url": url, "text_content": "", "html": "",
        "html_length": 0, "redirect_chain": [], "title": "",
        "prewarm_ok": False,
        "gate_crossed": [],
        "tls_fingerprint": "curl_cffi_chrome" if (is_human and CURL_CFFI_AVAILABLE) else "playwright_chromium",
        "proxy_used": bool(_proxy_for(is_human)),
        "response_headers": {},   # 新增：擷取關鍵回應標頭供差異比對
        "error": None,
    }

    # ── 網路層⑨：curl_cffi TLS 指紋預熱 ──────────────────────
    # 在 Playwright 開啟前，先用 curl_cffi 做一次 GET 暖身。
    # 目的：讓目標伺服器的 access log 先看到一個 Chrome TLS 指紋，
    # 而非之後 Playwright 的 Chromium 指紋（兩者在 GREASE 值上有差異）。
    # 對於只看第一次請求 TLS 指紋的 WAF 尤其有效。
    if CURL_CFFI_AVAILABLE and is_human:
        try:
            _px = _proxy_for(is_human)
            proxies = {"http": _px, "https": _px} if _px else None
            _cffi_requests.get(
                url,
                impersonate="chrome120",   # 模擬 Chrome 120 的 JA3/JA4
                timeout=10,
                allow_redirects=True,
                proxies=proxies,
                verify=False,
            )
            logger.debug("curl_cffi TLS 預熱完成")
        except Exception as e:
            logger.debug(f"curl_cffi 預熱失敗（不影響主流程）: {e}")

    # ── asyncio 異常處理器：壓制 TargetClosedError 的「Future exception was never retrieved」警告
    # 當外層 timeout 觸發關閉 browser 時，Playwright 內部某些 future 會拋出 TargetClosedError，
    # 但因為 future 已不被任何人 await，Python 會印出警告。此處靜默忽略這類殘留。
    _loop = asyncio.get_event_loop()
    _orig_exc_handler = _loop.get_exception_handler()
    def _suppress_target_closed(loop, ctx):
        exc = ctx.get("exception")
        if isinstance(exc, TargetClosedError):
            logger.debug("asyncio 忽略 TargetClosedError future 殘留（browser 已關閉）")
            return
        if _orig_exc_handler:
            _orig_exc_handler(loop, ctx)
        else:
            loop.default_exception_handler(ctx)
    _loop.set_exception_handler(_suppress_target_closed)

    try:
        async with async_playwright() as pw:
            launch_args = _HUMAN_LAUNCH_ARGS if is_human else _BOT_LAUNCH_ARGS
            # 修正：加入 launch timeout（30s）。
            # 原本沒有 timeout：Chromium 啟動失敗（資源不足、殭屍程序佔用 FD）時
            # pw.chromium.launch() 永久 await，asyncio 層無法介入，
            # 導致 worker thread 永遠不退出，殭屍 thread 累積後 submit() 阻塞。
            browser = await pw.chromium.launch(headless=True, args=launch_args,
                                               timeout=30_000)   # 30s
            ctx_opts = (HUMAN_CONTEXT_OPTIONS if is_human else BOT_CONTEXT_OPTIONS).copy()

            # ── 網路層⑧：Proxy 支援 ──────────────────────────
            _px = _proxy_for(is_human)
            if _px:
                ctx_opts["proxy"] = {"server": _px}
                logger.debug(f"Proxy 啟用 ({'HUMAN' if is_human else 'BOT'}): {_px[:30]}...")

            context = await browser.new_context(**ctx_opts, ignore_https_errors=True)

            if is_human:
                # HUMAN：注入完整 stealth 腳本（修補所有洩漏點）
                await context.add_init_script(_STEALTH_JS)
            else:
                # BOT：注入主動暴露腳本（確保爬蟲特徵完整保留）
                await context.add_init_script(_BOT_EXPOSE_JS)

            page = await context.new_page()

            redirect_chain = []
            # 只記錄目標網站的重定向，排除 Google prewarm 的無關 3xx
            try:
                from urllib.parse import urlparse
                _target_host = urlparse(url).netloc
            except Exception:
                _target_host = ""

            def _on_redirect(r):
                if r.status not in (301, 302, 303, 307, 308):
                    return
                try:
                    host = urlparse(r.url).netloc
                except Exception:
                    host = ""
                # 只追蹤目標域名（或其子域名）發出的重定向
                if _target_host and (_target_host in host or host in _target_host):
                    redirect_chain.append(r.url)
                elif not _target_host:
                    redirect_chain.append(r.url)

            page.on("response", _on_redirect)

            try:
                if is_human:
                    # _last_status 只追蹤原始 URL 的回應。
                    # 若原始 URL 回 301/302，後續 redirect 落點的 200 不會被此 listener 捕捉。
                    # 因此 _last_status 作為備用；優先用 Performance Navigation API 取得最終狀態。
                    _last_status = [200]
                    _first_resp_headers: list = [{}]   # 擷取目標 URL 的第一個回應標頭
                    async def _on_resp(r):
                        if r.url == url or r.url.rstrip('/') == url.rstrip('/'):
                            _last_status[0] = r.status
                            if not _first_resp_headers[0]:
                                try:
                                    h = {k.lower(): v for k, v in r.headers.items()}
                                    _first_resp_headers[0] = {
                                        "vary":            h.get("vary", ""),
                                        "server":          h.get("server", ""),
                                        "content-type":    h.get("content-type", ""),
                                        "set-cookie":      h.get("set-cookie", ""),
                                        "cf-cache-status": h.get("cf-cache-status", ""),
                                    }
                                except Exception:
                                    pass
                    page.on("response", _on_resp)
                    prewarm_ok = await _prewarm_google_session(page, url)
                    result["prewarm_ok"] = prewarm_ok
                    try:
                        await page.wait_for_load_state("networkidle", timeout=8000)
                    except Exception:
                        pass
                    await _human_behavior(page)
                    # 互動閘門：只有 HUMAN 跨，BOT 不跨 ——
                    # 「爬蟲不互動、真人會互動」本身就是極端化的一個維度
                    await _cross_gates(page, result)
                    # 優先從 Performance Navigation API 取得最終頁面的真實 HTTP 狀態碼
                    # （跟隨 redirect 後的落點狀態，而非中間 3xx）
                    try:
                        nav_status = await asyncio.wait_for(
                            page.evaluate(
                                "() => { "
                                "  const e = window.performance.getEntriesByType('navigation')[0]; "
                                "  return (e && e.responseStatus) ? e.responseStatus : null; "
                                "}"
                            ),
                            timeout=5.0,
                        )
                        result["status_code"] = int(nav_status) if nav_status else _last_status[0]
                    except Exception:
                        result["status_code"] = _last_status[0]
                    result["response_headers"] = _first_resp_headers[0]
                else:
                    resp = await page.goto(url, timeout=LOAD_TIMEOUT, wait_until="domcontentloaded")
                    if resp:
                        result["status_code"] = resp.status
                        try:
                            h = {k.lower(): v for k, v in resp.headers.items()}
                            result["response_headers"] = {
                                "vary":            h.get("vary", ""),
                                "server":          h.get("server", ""),
                                "content-type":    h.get("content-type", ""),
                                "set-cookie":      h.get("set-cookie", ""),
                                "cf-cache-status": h.get("cf-cache-status", ""),
                            }
                        except Exception:
                            pass
                    await page.wait_for_timeout(500)

                result["final_url"]      = page.url
                try:
                    result["title"] = await asyncio.wait_for(page.title(), timeout=5.0)
                except Exception:
                    result["title"] = ""
                redirect_chain.append(page.url)
                result["redirect_chain"] = redirect_chain

                try:
                    html = await asyncio.wait_for(page.content(), timeout=15.0)
                except Exception:
                    html = ""
                result["html_length"] = len(html)
                # 保留原始 HTML：Node 3 的釣魚判準要看 <script> 與表單屬性，
                # text_content 已把這些剝掉，不能用來比對惡意機制。
                result["html"] = html[:MAX_CONTENT_LEN]
                if html:
                    soup = BeautifulSoup(html[:MAX_CONTENT_LEN], "html.parser")
                    for tag in soup(["script", "style", "meta", "link", "noscript"]):
                        tag.decompose()
                    result["text_content"] = re.sub(r"\s+", " ", soup.get_text()).strip()[:MAX_CONTENT_LEN]

                # 截圖已移除：唯一的消費端是視覺相似度比對，而那個數值沒有
                # 任何讀取者。每個 URL 省下兩次 1440×900 PNG 編碼 + base64。
            finally:
                # 修正：無論是否發生例外，確保 browser 在 async_playwright context 退出前關閉。
                # 若省略此步驟，async_playwright().__aexit__ 需要自己強制終止瀏覽器子程序，
                # 在某些平台上會導致 loop.close() 掛起（等待孤兒 pipe FD 被清理）。
                # timeout=8s：若瀏覽器程序已殭屍，close() 永遠無法返回，須強制截斷。
                try:
                    await asyncio.wait_for(browser.close(), timeout=8.0)
                except Exception:
                    pass
    except Exception as e:
        result["error"] = str(e)
        logger.warning(f"Playwright ({'human' if is_human else 'bot'}) error: {e}")
    return result


def _run_async(coro, timeout: float = 110.0):
    """
    在新的 asyncio event loop 中執行 coroutine，帶有 asyncio 層 timeout。

    為何需要 asyncio 層 timeout（而非只靠 future.result(timeout=150)）：
      future.result(timeout=N) 是 threading 層計時，它在 N 秒後讓「呼叫端 thread」
      拋出 TimeoutError 並繼續，但「worker thread」仍被卡在 loop.run_until_complete()
      裡，該 thread 永遠無法正常退出，成為殭屍 thread。
      殭屍 thread 堆積後，新的 submit() 無法取得 thread slot，看起來像是
      「靜態分析完成，動態完全不動」（實際上是 submit() 本身排隊卡住）。

      asyncio.wait_for(coro, timeout=N) 在 coroutine 下一個 await 點注入
      CancelledError，讓 Playwright 的 async context manager 觸發 __aexit__ 清理，
      瀏覽器子程序 pipe FD 正確釋放，loop.run_until_complete() 正常返回，
      worker thread 得以退出。這才是真正消滅殭屍 thread 的方法。

    兩層 timeout 互為備援：
      asyncio 層（110s） ── 先觸發，確保 coroutine 正常退出
      thread  層（150s） ── 最後防線，即使 asyncio 層失效也不會永久阻塞
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(asyncio.wait_for(coro, timeout=timeout))
    except (asyncio.TimeoutError, TimeoutError):
        raise   # 交給 _run_bot_timed / _run_human_timed 包裝成 error dict
    except BaseException:
        raise
    finally:
        # Playwright 的 async context manager 在 CancelledError 觸發後會呼叫
        # browser.close()，但 close() 本身也是 coroutine。
        # 需要讓 pending tasks 真正執行完（不只是 cancel 標記），
        # 否則 pipe FD 仍未釋放，loop.close() 在特定平台下掛起。
        try:
            pending = asyncio.all_tasks(loop)
            if pending:
                for task in pending:
                    task.cancel()
                try:
                    loop.run_until_complete(
                        asyncio.wait_for(
                            asyncio.gather(*pending, return_exceptions=True),
                            timeout=8.0,   # cleanup 本身也須有上限，防止 browser.close() 殭屍掛起
                        )
                    )
                except (RecursionError, asyncio.TimeoutError, Exception):
                    pass
        except Exception:
            pass
        try:
            loop.close()
        except (RecursionError, Exception):
            pass
        asyncio.set_event_loop(None)


# ─────────────────────────────────────────────────────────────
# 對外入口：並行雙重爬取
# ─────────────────────────────────────────────────────────────
# asyncio 層 140s > HUMAN 最壞情況 (110.6s)，< thread 層 150s
_PLAYWRIGHT_TIMEOUT = 140.0


def _empty_result(url: str, err: str, is_human: bool) -> dict:
    r = {
        "error": err, "status_code": 0, "title": "", "text_content": "",
        "html": "", "html_length": 0, "redirect_chain": [], "final_url": url,
        "prewarm_ok": False,
        "gate_crossed": [],
        "proxy_used": False, "response_headers": {}, "fetch_time_sec": 0,
    }
    if is_human:
        r["prewarm_ok"] = False
    return r


def _timed_fetch(url: str, is_human: bool) -> dict:
    role = "HUMAN" if is_human else "BOT"
    t = time.time()
    try:
        r = _run_async(_fetch_with_playwright(url, is_human=is_human),
                       timeout=_PLAYWRIGHT_TIMEOUT)
    except (asyncio.TimeoutError, TimeoutError):
        r = _empty_result(url, f"asyncio.TimeoutError: {role} Playwright 超過 "
                               f"{_PLAYWRIGHT_TIMEOUT:.0f}s 強制終止", is_human)
    except Exception as e:
        r = _empty_result(url, str(e), is_human)
    r["fetch_time_sec"] = round(time.time() - t, 1)
    return r


def dual_crawl(url: str) -> tuple:
    """
    並行執行 BOT 與 HUMAN 兩次爬取，回傳 (bot_result, human_result, errors)。

    兩者各自在獨立 thread 跑自己的 asyncio event loop，互不干擾。
    BOT 先啟動、HUMAN 錯開 stagger 秒 —— 讓伺服器端的 cloaking 判斷
    先被 BOT 觸發，比較貼近真實的「爬蟲先到、使用者後到」情境。
    """
    errs = []
    if not url:
        return _empty_result("", "no_url", False), _empty_result("", "no_url", True), ["[crawler] no_url"]

    stagger = random.uniform(*BOT_HUMAN_DELAY)
    print(f"  → [爬取:並行] BOT 立即啟動，HUMAN 將在 {stagger:.1f}s 後啟動", flush=True)
    wall_t0 = time.time()

    # 不使用 with：__exit__ 會呼叫 shutdown(wait=True)，timeout 後仍等待
    # Playwright thread 結束 → 永久阻塞。
    executor = ThreadPoolExecutor(max_workers=2)
    try:
        bot_future = executor.submit(_timed_fetch, url, False)
        time.sleep(stagger)
        human_future = executor.submit(_timed_fetch, url, True)
        try:
            bot_result = bot_future.result(timeout=150)
        except Exception as e:
            bot_result = _empty_result(url, str(e), False)
        try:
            human_result = human_future.result(timeout=150)
        except Exception as e:
            human_result = _empty_result(url, str(e), True)
    finally:
        executor.shutdown(wait=False)

    bot_time   = bot_result.get("fetch_time_sec", 0)
    human_time = human_result.get("fetch_time_sec", 0)
    wall_time  = round(time.time() - wall_t0, 1)

    if bot_result.get("error"):
        errs.append(f"[crawler] BOT error: {bot_result['error']}")
        print(f"  → [爬取:BOT]   失敗: {bot_result['error']}", flush=True)
    else:
        print(f"  → [爬取:BOT]   {bot_time}s | HTTP {bot_result['status_code']} "
              f"| {bot_result['title'][:50]}", flush=True)

    if human_result.get("error"):
        errs.append(f"[crawler] HUMAN error: {human_result['error']}")
        print(f"  → [爬取:HUMAN] 失敗: {human_result['error']}", flush=True)
    else:
        prewarm = "預熱成功" if human_result.get("prewarm_ok") else "預熱失敗"
        print(f"  → [爬取:HUMAN] {human_time}s | HTTP {human_result['status_code']} "
              f"| {prewarm} | {human_result['title'][:50]}", flush=True)

    print(f"  → [爬取:並行] 總耗時 {wall_time}s"
          f"（序列估計: {bot_time + human_time + stagger:.1f}s）", flush=True)
    return bot_result, human_result, errs


def crawl_human_only(url: str) -> dict:
    """
    只重爬一次 HUMAN，供 Node 4 的「陽性確認」使用（見 node4 的 C1 確認邏輯）。

    為什麼需要這個：Cloak of Visibility (IEEE S&P 2016) 每個 profile 爬 3 次，
    用「同 profile 內的變異」正規化「跨 profile 的差異」，目的是排除頁面自身
    的自然變動（輪播廣告、A/B test、個人化）造成的誤判。

    本系統的判準是離散的機制集合，不是連續相似度，所以不需要全量 3×：
    只在「即將宣稱有 cloaking 且該結論僅由單次觀測到的機制支撐」時，
    重爬一次確認機制是否穩定重現即可。成本 = 1 × 陽性率，而非 2×。
    """
    if not url:
        return _empty_result("", "no_url", True)
    return _timed_fetch(url, True)
