"""
node5_risk_output.py
最終輸出節點：只回報三件事 —— URL、是否為釣魚網站、是否有 Cloaking。

CSV 行為：
  - 同一執行階段：結果逐筆 append 至同一 CSV
  - 程式重啟後：自動建立新的 CSV（以啟動時間戳命名）

設計說明（為什麼沒有風險分數）：
  判定已經在 Node 3 / Node 4 用布林規則做完了。
  再把兩個布林乘上權重合成一個 0~1 的 risk_score，只是把明確的結論
  重新變回一個需要解釋的數字，而且那些權重沒有任何資料依據。
  報告直接呈現兩個布林 + 一個 URL。
"""
import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import csv
import threading
from datetime import datetime
from pathlib import Path

from state import AnalysisState

# ── CSV 輸出常數 ──────────────────────────────────────────────
OUTPUT_DIR = Path(__file__).parent.parent / "csv_reports"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

_SESSION_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
SESSION_CSV = OUTPUT_DIR / f"phishing_report_{_SESSION_TIMESTAMP}.csv"

# 並行寫入保護鎖（max_concurrent ≥ 2 時防止多 thread 同時 append 同一行）
_CSV_LOCK = threading.Lock()

FIELDNAMES = ["url", "is_phishing", "cloaking"]

# cloaking 欄位的第三種值：未分析 / 無法判斷。
# 不寫成 False —— 「沒驗到」和「驗過沒有」是兩件事，混為一談會讓
# 未經 Node 4 分析的正常網站看起來像是「已確認無 cloaking」。
CLOAKING_UNKNOWN = "N/A"


def _cloaking_verdict(state: AnalysisState):
    """回傳 True / False / "N/A" """
    dual = state.get("dual_crawl_results") or {}
    if not dual:
        # Node 3 判定非釣魚 → 條件路由直接跳到 Node 5，從未做 cloaking 分析
        return CLOAKING_UNKNOWN
    if state.get("cloaking_verified"):
        return True
    if dual.get("dynamic_reliability") in ("LOW", "FAILED"):
        # HUMAN 端可能被識破或爬取失敗 → 無法排除
        return CLOAKING_UNKNOWN
    return False


def _ensure_csv_header():
    with _CSV_LOCK:
        if not SESSION_CSV.exists():
            with open(SESSION_CSV, "w", newline="", encoding="utf-8-sig") as f:
                csv.DictWriter(f, fieldnames=FIELDNAMES).writeheader()
            print(f"  → 建立新 CSV：{SESSION_CSV.name}")


# ─────────────────────────────────────────────────────────────
# LangGraph Node 函式
# ─────────────────────────────────────────────────────────────
def risk_output_node(state: AnalysisState, llm=None, llm_registry: dict = None) -> AnalysisState:
    """
    Node 5: 輸出報告（URL / 是否釣魚 / 是否 Cloaking）

    llm 與 llm_registry 保留在簽章中僅為相容 main.py 的 make_node 包裝，
    本節點不再呼叫任何模型 —— 三個欄位都是前面節點已經決定好的事實。
    """
    print("\n[Node 5] 輸出報告...")

    row = {
        "url":         state.get("url", ""),
        "is_phishing": state.get("is_phishing", False),
        "cloaking":    _cloaking_verdict(state),
    }

    _ensure_csv_header()
    with _CSV_LOCK:
        with open(SESSION_CSV, "a", newline="", encoding="utf-8-sig") as f:
            csv.DictWriter(f, fieldnames=FIELDNAMES).writerow(row)

    cloak_zh = {True: "是", False: "否"}.get(row["cloaking"], "未分析")
    state["report"] = "\n".join([
        f"URL：{row['url']}",
        f"是否為釣魚網站：{'是' if row['is_phishing'] else '否'}",
        f"是否有 Cloaking：{cloak_zh}",
    ])
    print(f"  → {row['url']} | 釣魚={row['is_phishing']} | Cloaking={row['cloaking']}")
    print(f"  → 已寫入：{SESSION_CSV.name}")
    return state
