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

HUMAN_CONTEXT_OPTIONS = {
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
    "extra_http_headers": {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "zh-TW,zh;q=0.9,en-US;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT":             "1",
    },
    "locale":      "zh-TW",
    "timezone_id": "Asia/Taipei",
    "viewport":    {"width": 1440, "height": 900},
    "geolocation": {"latitude": 25.033, "longitude": 121.565},
    "permissions": ["geolocation"],
}

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
// ── 1. navigator.webdriver ────────────────────────────────────
Object.defineProperty(navigator, 'webdriver', {
    get: () => false,
    configurable: true
});

// ── 2. navigator.plugins (headless 下為空) ────────────────────
const _plugins = [
    { name: 'Chrome PDF Plugin',       filename: 'internal-pdf-viewer',   description: 'Portable Document Format' },
    { name: 'Chrome PDF Viewer',       filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
    { name: 'Native Client',           filename: 'internal-nacl-plugin',  description: '' },
];
Object.defineProperty(navigator, 'plugins', {
    get: () => {
        const arr = Object.assign([], _plugins);
        arr.namedItem = (n) => arr.find(p => p.name === n) || null;
        arr.refresh   = () => {};
        arr.item      = (i) => arr[i];
        arr[Symbol.iterator] = Array.prototype[Symbol.iterator];
        return arr;
    }
});

// ── 3. navigator.languages ────────────────────────────────────
Object.defineProperty(navigator, 'languages', {
    get: () => ['zh-TW', 'zh', 'en-US', 'en'],
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
            connect: () => {},
            sendMessage: () => {}
        },
        loadTimes: function() {
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
        },
        csi: function() {
            return { onloadT: Date.now(), pageT: Math.random() * 5000 + 1000, startE: Date.now() - 3000, tran: 15 };
        }
    };
}

// ── 5. permissions API ────────────────────────────────────────
const _origQuery = window.Permissions && window.Permissions.prototype.query;
if (_origQuery) {
    window.Permissions.prototype.query = function(perm) {
        if (perm.name === 'notifications') {
            return Promise.resolve({ state: Notification.permission });
        }
        return _origQuery.call(this, perm);
    };
}

// ── 6. outerHeight / outerWidth ───────────────────────────────
Object.defineProperty(window, 'outerHeight', { get: () => 1040, configurable: true });
Object.defineProperty(window, 'outerWidth',  { get: () => 1440, configurable: true });
Object.defineProperty(window, 'screenY',     { get: () => 23,   configurable: true });
Object.defineProperty(window, 'screenX',     { get: () => 0,    configurable: true });

// ── 7. Canvas 指紋 ────────────────────────────────────────────
const _toDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(type, quality) {
    if (this.width > 10 && this.height > 10) {
        const ctx = this.getContext('2d');
        if (ctx) {
            const _imageData = ctx.getImageData;
            ctx.getImageData = function(x, y, w, h) {
                const data = _imageData.call(this, x, y, w, h);
                const noise = 1;
                for (let i = 0; i < data.data.length; i += 100) {
                    data.data[i] = Math.min(255, data.data[i] + (Math.random() > 0.5 ? noise : -noise));
                }
                return data;
            };
        }
    }
    return _toDataURL.call(this, type, quality);
};

// ── 8. WebGL 指紋 ─────────────────────────────────────────────
const _getParam = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(param) {
    if (param === 37445) return 'Intel Inc.';
    if (param === 37446) return 'Intel Iris OpenGL Engine';
    return _getParam.call(this, param);
};
if (typeof WebGL2RenderingContext !== 'undefined') {
    const _getParam2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(param) {
        if (param === 37445) return 'Intel Inc.';
        if (param === 37446) return 'Intel Iris OpenGL Engine';
        return _getParam2.call(this, param);
    };
}

// ── 9. AudioContext 指紋 ──────────────────────────────────────
if (typeof AudioContext !== 'undefined') {
    const _createOscillator = AudioContext.prototype.createOscillator;
    AudioContext.prototype.createOscillator = function() {
        const osc = _createOscillator.call(this);
        const _origConnect = osc.connect.bind(osc);
        osc.connect = function(dest) {
            try { return _origConnect(dest); } catch(e) {}
        };
        return osc;
    };
}

// ── 10. navigator.connection ──────────────────────────────────
Object.defineProperty(navigator, 'connection', {
    get: () => ({
        effectiveType: '4g',
        rtt: 50 + Math.floor(Math.random() * 50),
        downlink: 10,
        saveData: false,
    }),
    configurable: true
});

// ── 11. navigator.hardwareConcurrency / deviceMemory ─────────
Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8,  configurable: true });
Object.defineProperty(navigator, 'deviceMemory',        { get: () => 8,  configurable: true });

// ── 12. Date.prototype.getTimezoneOffset ─────────────────────
Date.prototype.getTimezoneOffset = function() { return -480; };

// ── 13. Notification.permission ──────────────────────────────
// headless 下預設為 "default"，真實用戶通常是 "denied"
try {
    Object.defineProperty(Notification, 'permission', {
        get: () => 'denied',
        configurable: true
    });
} catch(e) {}

// ── 14. navigator.mediaDevices.enumerateDevices ───────────────
// headless 下回傳空陣列，真實用戶有麥克風 / 攝影機 / 喇叭
if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
    navigator.mediaDevices.enumerateDevices = function() {
        return Promise.resolve([
            { deviceId: 'default', groupId: 'default', kind: 'audioinput',  label: '' },
            { deviceId: 'default', groupId: 'default', kind: 'audiooutput', label: '' },
            { deviceId: 'default', groupId: 'default', kind: 'videoinput',  label: '' },
        ]);
    };
}

// ── 15. document.hasFocus ─────────────────────────────────────
// headless 下永遠回傳 false，真實用戶通常為 true
document.hasFocus = function() { return true; };

// ── 16. performance.memory ────────────────────────────────────
// headless 下結構異常，注入合理的記憶體使用值
try {
    Object.defineProperty(performance, 'memory', {
        get: () => ({
            jsHeapSizeLimit:  2172649472,
            totalJSHeapSize:  Math.floor(Math.random() * 50000000) + 20000000,
            usedJSHeapSize:   Math.floor(Math.random() * 20000000) + 10000000,
        }),
        configurable: true
    });
} catch(e) {}

// ── 17. screen.colorDepth / pixelDepth ───────────────────────
// headless 下可能回傳 24，真實螢幕通常為 24 或 30，明確設定避免異常值
Object.defineProperty(screen, 'colorDepth', { get: () => 24, configurable: true });
Object.defineProperty(screen, 'pixelDepth',  { get: () => 24, configurable: true });
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
        "tls_fingerprint": "curl_cffi_chrome" if (is_human and CURL_CFFI_AVAILABLE) else "playwright_chromium",
        "proxy_used": bool(PROXY_URL),
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
            proxies = {"http": PROXY_URL, "https": PROXY_URL} if PROXY_URL else None
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
            if PROXY_URL:
                ctx_opts["proxy"] = {"server": PROXY_URL}
                logger.debug(f"Proxy 啟用: {PROXY_URL[:30]}...")

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
