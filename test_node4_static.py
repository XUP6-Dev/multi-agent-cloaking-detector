"""
test_node4_static.py — Node 4 靜態偵測布林規則自檢
執行: python test_node4_static.py

靜態 cloaking 的定義：偵測環境 → 依結果改變使用者看到的東西。
兩半都不能單獨成立，所以每條規則都是連言。
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nodes.node4_cloaking_analyzer import _static_detect


def _state(js="", html=""):
    return {"deobfuscated_js": [{"deobfuscated": js}], "raw_html": html, "errors": []}


def _detect(js="", html=""):
    """llm=None → 靜態 LLM 呼叫會丟 AttributeError 被吃掉，測純規則層"""
    return _static_detect(_state(js, html), llm=None)


def test_crawler_artifact_plus_redirect():
    """S1：爬蟲框架洩漏識別符 + 差異化跳轉"""
    detected, techs = _detect("""
        if (window.__cdc_ || window._phantom || navigator.webdriver) {
            location.href = 'https://benign-decoy.example/';
        }
    """)
    assert detected, techs
    assert any("[S1]" in t for t in techs.get("static_rule", [])), techs


def test_detection_alone_is_not_cloaking():
    """反例：只有 bot 偵測沒有差異化行動 —— anti-bot SDK 就長這樣"""
    detected, techs = _detect("""
        // DataDome / PerimeterX 類 SDK 的典型片段
        var isBot = navigator.webdriver || window._phantom || window.__cdc_;
        telemetry.push({bot: isBot});
    """)
    assert not detected, f"純偵測被誤判為 cloaking: {techs.get('static_rule')}"


def test_redirect_alone_is_not_cloaking():
    """反例：只有跳轉沒有偵測 —— 一般的外部導向"""
    detected, techs = _detect("location.href = 'https://www.example.com/welcome';")
    assert not detected, f"純跳轉被誤判為 cloaking: {techs.get('static_rule')}"


def test_modern_spa_is_not_cloaking():
    """關鍵回歸：一般的現代 React 站 —— DevTools hook + RWD + referrer 追蹤
    + 外部連結跳轉。四個類別命中，舊加權版會累積過門檻，布林版不裁決。"""
    detected, techs = _detect("""
        if (typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined') { hook(); }
        if (screen.width < 768) { mobileLayout(); }
        document.referrer && track(document.referrer);
        if (navigator.userAgent.indexOf('Safari') > -1) { polyfill(); }
        location.href = 'https://docs.example.com/guide';
    """)
    assert len(techs) >= 4, f"應該記錄到證據: {list(techs)}"
    assert not detected, f"現代 SPA 被誤判為 cloaking: {techs.get('static_rule')}"


def test_generic_probes_never_decide():
    """一般性環境偵測是統計性特徵，任何組合 + 跳轉都不裁決"""
    detected, techs = _detect("""
        if (screen.width < 768) { location.href = 'https://m.example.com/'; }
        if (document.referrer.includes('google')) { track(); }
        if (navigator.userAgent.match(/bot/i)) { flag(); }
        geoip.lookup(remote_addr);
    """)
    assert not detected, f"一般性偵測不該裁決: {techs.get('static_rule')}"


def test_fingerprint_conditional_plus_redirect():
    """S2：指紋條件分流 + 跳轉"""
    detected, techs = _detect("""
        var fp = getCanvasFp();
        if (knownBot(fp) && fingerprint.match(fp)) { location.replace('http://decoy/'); }
    """)
    assert detected and any("[S2]" in t for t in techs.get("static_rule", [])), techs


def test_clean_page():
    detected, techs = _detect("console.log('hello'); document.querySelector('.btn');")
    assert not detected and not techs.get("static_rule"), techs


if __name__ == "__main__":
    for fn in (test_crawler_artifact_plus_redirect,
               test_detection_alone_is_not_cloaking,
               test_redirect_alone_is_not_cloaking,
               test_modern_spa_is_not_cloaking,
               test_generic_probes_never_decide,
               test_fingerprint_conditional_plus_redirect,
               test_clean_page):
        fn()
        print(f"PASS  {fn.__name__}")
