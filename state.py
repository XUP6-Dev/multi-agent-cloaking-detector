"""
state.py - 共享狀態定義
所有節點透過此 TypedDict 共享資料
"""
from typing import TypedDict, List, Dict, Any


class AnalysisState(TypedDict):
    url: str
    # raw_html = HUMAN 端看到的頁面。釣魚判定要看真人看到的那份 ——
    # 攻擊面是使用者，不是爬蟲。BOT 那份只用來比對 cloaking。
    raw_html: str
    bot_crawl: Dict[str, Any]              # Node 1 output（純爬蟲視角）
    human_crawl: Dict[str, Any]            # Node 1 output（模仿真人視角）
    js_scripts: List[Dict[str, Any]]       # Node 1 output（取自 HUMAN 頁面）
    deobfuscated_js: List[Dict[str, Any]]  # Node 2 output
    is_phishing: bool                      # Node 3 output
    phishing_confidence: float
    phishing_indicators: List[str]
    cloaking_detected: bool                # Node 4 output
    cloaking_techniques: List[str]
    cloaking_verified: bool                # Node 4 output (雙重爬取實驗確認)
    cloaking_confidence_tier: str          # Node 4 output: CONFIRMED / SUSPECTED / AMBIGUOUS
    dual_crawl_results: Dict[str, Any]     # Node 4 output (雙重爬取詳細結果)
    static_is_fallback: bool               # Node 4 output（動態驗證 FAILED 時，靜態結果是唯一依據）
    report: str                            # Node 5 output
    errors: List[str]
