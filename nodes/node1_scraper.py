"""
node1_scraper.py - Node 1: 抓取 JS
靜態 (requests + BeautifulSoup) + 動態 (Playwright) 雙模式抓取

設計定位：
  Node1 使用「中性 UA」——既不像 Googlebot（BOT 模式），也不注入 stealth JS（HUMAN 模式）。
  這使 raw_html 成為 Node4 三方基準比對的「中立參考點」。
  Playwright 加入基本 UA 偽裝以避免被裸 headless 特徵立即拒絕，
  但不注入 fingerprint 修補腳本，保持中性。

修正紀錄：
  v2 修正 1 (Bug): 動態 HTML 更新 raw_html 後，js_scripts 未同步更新
                   → 現在從動態 HTML 重新抽取 inline script，並補抓靜態未見的外部 JS
  v2 修正 2: Playwright 補上中性 UA + AutomationControlled 抑制，
             避免被裸 headless 特徵立即觸發 CAPTCHA
  v2 修正 3: 擷取靜態 HTTP 狀態碼，被封鎖時寫入 errors 供下游參考
  v2 修正 4: 外部 JS 以 src URL 去重，避免同一腳本被抓取兩次
  v3 修正 5 (Bug): 新增 verify=False 繞過 SSL 憑證驗證
                   → 釣魚網站大量使用自簽/過期憑證，未設定時全部 SSL 錯誤失敗
  v3 修正 6 (Bug): Playwright context 新增 ignore_https_errors=True
                   → 動態抓取同樣因 SSL 錯誤全部失敗
  v3 修正 7: 統一壓制 InsecureRequestWarning，避免 SSL bypass 產生大量警告雜訊
"""
import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import hashlib
import warnings
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from state import AnalysisState
from nodes.dual_crawler import dual_crawl

# 修正 7：壓制 SSL bypass 產生的 InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── 常數 ──────────────────────────────────────────────────────
# 中性 UA：比裸 requests 預設值更像真實瀏覽器，但不做完整 stealth 修補
# （Node4 HUMAN 才做完整修補；Node1 保持中性供三方比對用）
_NEUTRAL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_STATIC_HEADERS = {
    "User-Agent":      _NEUTRAL_UA,
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
}
# Playwright 中性啟動參數：只抑制 AutomationControlled 旗標，不加 stealth JS
_NEUTRAL_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-blink-features=AutomationControlled",  # 修正 2：避免裸 headless 被立即拒絕
]
_INLINE_MIN_LEN = 50   # inline script 最小長度（字元），過短的通常是 analytics 片段
_STATIC_TIMEOUT  = 15  # requests.get timeout
_EXT_JS_TIMEOUT  = 10  # 單個外部 JS 抓取 timeout
_PLAYWRIGHT_GOTO_TIMEOUT    = 20_000   # ms
_PLAYWRIGHT_NETWORK_TIMEOUT = 15_000   # ms


def _extract_js_from_html(html: str, base_url: str, headers: dict,
                           seen_srcs: set, errors: list) -> list:
    """
    從 HTML 字串中抽取 inline 與 external JS。
    seen_srcs: 已抓取的外部 JS src URL 集合（去重用），會被就地修改。
    回傳: list of script dicts
    """
    scripts = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return scripts

    # ── Inline <script> ──────────────────────────────────
    for tag in soup.find_all("script"):
        if tag.string and len(tag.string.strip()) >= _INLINE_MIN_LEN:
            scripts.append({
                "type":    "inline",
                "src":     None,
                "content": tag.string,
            })

    # ── External <script src="..."> ──────────────────────
    for tag in soup.find_all("script", src=True):
        src = tag.get("src", "").strip()
        if not src:
            continue
        if src.startswith("//"):
            scheme = base_url.split("://")[0] if "://" in base_url else "https"
            src = f"{scheme}:{src}"
        elif not src.startswith("http"):
            src = urljoin(base_url, src)

        # 修正 4：以 src URL 去重，避免同一腳本抓取兩次
        if src in seen_srcs:
            continue
        seen_srcs.add(src)

        try:
            # 修正 5：verify=False 繞過 SSL 憑證驗證
            js_resp = requests.get(
                src, headers=headers,
                timeout=_EXT_JS_TIMEOUT,
                verify=False,          # ← 修正 5
            )
            scripts.append({
                "type":    "external",
                "src":     src,
                "content": js_resp.text,
            })
        except Exception as e:
            errors.append(f"[Node1] External JS fetch error ({src}): {e}")

    return scripts


def _static_fallback(url: str, errors: list) -> str:
    """兩次 Playwright 爬取都失敗時的最後手段（verify=False 繞過自簽憑證）"""
    try:
        resp = requests.get(url, headers=_STATIC_HEADERS, timeout=_STATIC_TIMEOUT,
                            verify=False, allow_redirects=True)
        if resp.status_code in (403, 429, 503):
            errors.append(f"[Node1] 靜態 fallback 被封鎖 HTTP {resp.status_code}")
        print(f"  → [靜態 fallback] HTTP {resp.status_code}")
        return resp.text
    except Exception as e:
        errors.append(f"[Node1] Static fallback error: {e}")
        print(f"  → [靜態 fallback] 失敗: {e}")
        return ""


def scrape_js_node(state: AnalysisState) -> AnalysisState:
    """
    Node 1: 雙重爬取（BOT ‖ HUMAN）+ 抽取 JS

    為什麼兩份都要在這裡抓完：
      釣魚判定必須看「真人看到的那份頁面」。舊版用中性 UA 抓一份就交給 Node 3，
      等於拿「攻擊者想讓爬蟲看到的乾淨頁」去判斷它是不是釣魚 —— cloaking 做得
      越好越判不出來。現在 Node 3 判 HUMAN 那份，Node 4 比兩份的差異，
      兩件事都在同一批資料上完成，也不需要任何前後閘門。

    raw_html 對下游的語意 = HUMAN 頁面（HUMAN 失敗時退回 BOT，再失敗才靜態 fallback）
    """
    print("\n[Node 1] 雙重爬取（BOT ‖ HUMAN）...")
    url    = state["url"]
    errors = state.get("errors", [])

    bot_result, human_result, crawl_errs = dual_crawl(url)
    errors.extend(crawl_errs)

    human_html = human_result.get("html", "") or ""
    bot_html   = bot_result.get("html", "") or ""

    # 判定用的頁面：優先 HUMAN；HUMAN 失敗才退而求其次
    raw_html = human_html or bot_html
    source   = "HUMAN" if human_html else ("BOT" if bot_html else "")
    if not raw_html:
        raw_html = _static_fallback(url, errors)
        source   = "靜態 fallback" if raw_html else "無"
    print(f"  → 判定用頁面來源: {source}（{len(raw_html)} chars）")

    # JS 只從判定用的那份頁面抽（Node 2 去混淆的成本很高，抽兩份不划算；
    # Node 4 的比對是兩邊都用原始 HTML，仍然是對等比較）
    seen_srcs: set = set()
    js_scripts = _extract_js_from_html(raw_html, url, _STATIC_HEADERS, seen_srcs, errors) \
        if raw_html else []

    state["raw_html"]    = raw_html
    state["bot_crawl"]   = bot_result
    state["human_crawl"] = human_result
    state["js_scripts"]  = js_scripts
    state["errors"]      = errors
    print(f"  → 抓取完成: {len(js_scripts)} 個 JS 腳本")
    return state