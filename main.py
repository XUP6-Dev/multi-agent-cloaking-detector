"""
main.py - 主程式入口
支援單一 / 批次 URL 分析，含 Rich 進度條視覺化
"""
import sys
import os
import re
import json
import csv
import threading
import functools
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

# ── 路徑修正 ──────────────────────────────────────────────────
# 確保不論從何處執行，都能找到同目錄的模組
# IDE（Pylance/Pyright）紅線問題請參考 pyrightconfig.json 與 .vscode/settings.json
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

# ── .env（DEEPSEEK_API_KEY 等）─────────────────────────────────
# 指定絕對路徑，從任何 cwd 執行都讀得到；已存在的環境變數優先。
from dotenv import load_dotenv
load_dotenv(Path(_BASE_DIR) / ".env")

# ── Rich (進度條 + 美化輸出) ──────────────────────────────────
try:
    from rich.console import Console
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn,
        TextColumn, TimeElapsedColumn, TaskProgressColumn
    )
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("[Warning] rich 未安裝，將使用純文字進度條。執行: pip install rich")

# ── LLM ──────────────────────────────────────────────────────
from langchain_openai import ChatOpenAI

from langgraph.graph import StateGraph, END
from state import AnalysisState
from nodes.node1_scraper            import scrape_js_node
from nodes.node2_js_analyzer        import analyze_js_node
from nodes.node3_phishing_classifier import classify_phishing_node
from nodes.node4_cloaking_analyzer  import analyze_cloaking_node
from nodes.node5_risk_output        import risk_output_node, _cloaking_verdict, CLOAKING_UNKNOWN

console = Console() if RICH_AVAILABLE else None

# ─────────────────────────────────────────────────────────────
#  DeepSeek API 設定
# ─────────────────────────────────────────────────────────────
#
# DeepSeek 提供 OpenAI 相容端點，直接用 langchain_openai.ChatOpenAI
# 指到 api.deepseek.com 即可，不需要另裝 provider 套件。
#
# 環境變數：
#   DEEPSEEK_API_KEY   必填；未設定時所有 LLM 節點退化為純規則模式
#   LLM_MODEL          選填，預設 deepseek-chat（推理版：deepseek-reasoner）
#   DEEPSEEK_BASE_URL  選填，預設 https://api.deepseek.com

import time

# ── 供應商設定表 ──────────────────────────────────────────────
#   env_key  : 讀哪個環境變數當 API key
#   default  : 未指定 LLM_MODEL 時的預設模型
#   no_temp  : True 表示該供應商拒絕 temperature 參數
#   no_key   : True 表示不需要真的 API key（本地端點不驗證），
#              未設定對應環境變數時自動帶入佔位字串
#
# ⚠️ Claude 5 系列（claude-opus-5 / claude-sonnet-5）已移除 temperature /
#   top_p / top_k —— 送出會直接回 400。舊的 _make_llm 寫死 temperature=0，
#   直接接上去會全部失敗，所以工廠依供應商決定要不要帶這個參數。
LLM_PROVIDERS = {
    "deepseek": {
        "env_key": "DEEPSEEK_API_KEY",
        "default": "deepseek-chat",
        "no_temp": False,
        "base_url_env": "DEEPSEEK_BASE_URL",
        "base_url_default": "https://api.deepseek.com",
    },
    "anthropic": {
        "env_key": "ANTHROPIC_API_KEY",
        "default": "claude-opus-5",        # 其他可用: claude-sonnet-5 / claude-haiku-4-5
        "no_temp": True,
    },
    "openai": {
        "env_key": "OPENAI_API_KEY",
        "default": "gpt-4o",               # 以 LLM_MODEL 覆寫成你帳號可用的型號
        "no_temp": False,
    },
    "google": {
        "env_key": "GOOGLE_API_KEY",
        "default": "gemini-2.0-flash",     # 以 LLM_MODEL 覆寫
        "no_temp": False,
    },
    "lmstudio": {
        # LM Studio 開的是本地 OpenAI 相容端點，跟 deepseek 走同一條
        # ChatOpenAI(base_url=...) 路徑，不需要另裝套件。
        # LLM_MODEL 必須換成 LM Studio「Local Server」分頁顯示的確切
        # 模型 identifier（不是隨便一個字串——多模型時 LM Studio 靠這個
        # 欄位決定路由到哪個已載入的模型）。
        "env_key": "LMSTUDIO_API_KEY",   # 選填，LM Studio 不驗證這個值
        "no_key": True,
        "default": "local-model",        # 幾乎一定要用 LLM_MODEL 覆寫
        "no_temp": False,
        "base_url_env": "LMSTUDIO_BASE_URL",
        "base_url_default": "http://localhost:1234/v1",
    },
}

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "deepseek").lower()
if LLM_PROVIDER not in LLM_PROVIDERS:
    print(f"\n[!] 未知的 LLM_PROVIDER='{LLM_PROVIDER}'，"
          f"可用: {', '.join(LLM_PROVIDERS)}；退回 deepseek\n")
    LLM_PROVIDER = "deepseek"

_PROVIDER  = LLM_PROVIDERS[LLM_PROVIDER]
MODEL_NAME = os.environ.get("LLM_MODEL", _PROVIDER["default"])
API_KEY    = os.environ.get(_PROVIDER["env_key"], "")

if not API_KEY and _PROVIDER.get("no_key"):
    API_KEY = "not-needed"   # 佔位字串：本地端點不檢查，但 SDK 要求非空

if not API_KEY:
    print("\n" + "=" * 60)
    print(f"  [!] 未設定 {_PROVIDER['env_key']}，所有 LLM 節點將退化為純規則模式")
    print(f"  修復方式 (PowerShell): $env:{_PROVIDER['env_key']} = '...'")
    print(f"  切換供應商: $env:LLM_PROVIDER = "
          f"'{'|'.join(LLM_PROVIDERS)}'")
    print("=" * 60 + "\n")
elif LLM_PROVIDER == "lmstudio":
    print(f"[LLM] provider=lmstudio model={MODEL_NAME} "
          f"base_url={os.environ.get(_PROVIDER['base_url_env'], _PROVIDER['base_url_default'])}")
    print("  → 確認 LM Studio 的 Local Server 已啟動，且 LLM_MODEL 與載入的模型一致")
else:
    print(f"[LLM] provider={LLM_PROVIDER} model={MODEL_NAME}")


# ─────────────────────────────────────────────────────────────
#  LLM 工廠 + Retry 包裝
# ─────────────────────────────────────────────────────────────
#
# 兩個關鍵設計：
#
# 1. 依節點輸入量分配 timeout / max_tokens:
#    Node 4 (cloaking) 輸入包含完整的去混淆 JS，prompt 最長、最容易 timeout。
#
# 2. _RetryLLM:
#    吸收網路抖動、429 等偶發失敗，單次失敗後自動 retry 1 次。
#    同時把 ChatModel 回傳的 AIMessage 轉成純字串——各 node 都直接對
#    llm.invoke() 的結果做 regex，介面必須維持「invoke 回字串」。

class _RetryLLM:
    """對 llm.invoke() 加一次 retry 的薄 wrapper，對呼叫端保持介面相容。"""
    def __init__(self, llm, retries: int = 1, backoff_sec: float = 2.0):
        self._llm = llm
        self._retries = retries
        self._backoff = backoff_sec

    def invoke(self, *args, **kwargs):
        last_err = None
        for attempt in range(self._retries + 1):
            try:
                resp = self._llm.invoke(*args, **kwargs)
                # ChatOpenAI 回 AIMessage，node 端期待字串
                return getattr(resp, "content", resp)
            except Exception as e:
                last_err = e
                if attempt < self._retries:
                    time.sleep(self._backoff)
                    continue
                raise
        raise last_err  # defensive

    def __getattr__(self, name):
        # 代理其他屬性（model 名稱、langchain 內建方法等）
        return getattr(self._llm, name)


def _make_llm(num_predict: int = 512, timeout: int = 180):
    """
    依 LLM_PROVIDER 建立 chat model；沒有 API key 時回傳 None
    （node 端的 try/except 會退化為純規則模式）。

    各供應商的套件採延遲 import：只裝了其中一個也能正常執行，
    不會因為缺少 langchain-anthropic 之類的套件讓整支程式起不來。
    """
    if not API_KEY:
        return None

    common = {"timeout": timeout, "max_retries": 0}   # retry 統一交給 _RetryLLM
    if not _PROVIDER["no_temp"]:
        common["temperature"] = 0

    try:
        if LLM_PROVIDER == "anthropic":
            from langchain_anthropic import ChatAnthropic
            base = ChatAnthropic(model=MODEL_NAME, api_key=API_KEY,
                                 max_tokens=num_predict, **common)

        elif LLM_PROVIDER == "google":
            from langchain_google_genai import ChatGoogleGenerativeAI
            # Gemini 用 max_output_tokens，且不吃 max_retries
            common.pop("max_retries", None)
            base = ChatGoogleGenerativeAI(model=MODEL_NAME, google_api_key=API_KEY,
                                          max_output_tokens=num_predict, **common)

        elif LLM_PROVIDER == "openai":
            base = ChatOpenAI(model=MODEL_NAME, api_key=API_KEY,
                              max_tokens=num_predict, **common)

        else:   # deepseek / lmstudio —— 都是 ChatOpenAI + base_url 覆寫的 OpenAI 相容端點
            base = ChatOpenAI(
                model=MODEL_NAME, api_key=API_KEY,
                base_url=os.environ.get(_PROVIDER["base_url_env"],
                                        _PROVIDER["base_url_default"]),
                max_tokens=num_predict, **common,
            )
    except ImportError as e:
        pkg = {"anthropic": "langchain-anthropic",
               "google":    "langchain-google-genai"}.get(LLM_PROVIDER, "langchain-openai")
        print(f"\n[!] LLM_PROVIDER={LLM_PROVIDER} 需要套件 {pkg}：pip install {pkg}")
        print(f"    ({e}) → 退化為純規則模式\n")
        return None

    return _RetryLLM(base, retries=1, backoff_sec=2.0)


# 依節點輸入量給不同的 num_predict 與 timeout：
# - llm_code  : Node 2 去混淆需輸出完整 JS           → 2048 tokens / 240s
# - llm       : Node 3 / Node 5 輸入中等、輸出短 JSON →  512 tokens / 180s
# - llm_cloak : Node 4 輸入含完整去混淆 JS，最易 timeout →  512 tokens / 300s
llm_code  = _make_llm(num_predict=2048, timeout=240)
llm       = _make_llm(num_predict=512,  timeout=180)
llm_cloak = _make_llm(num_predict=512,  timeout=300)


def make_node(fn, **kwargs):
    return functools.partial(fn, **kwargs)


def build_graph():
    graph = StateGraph(AnalysisState)

    graph.add_node("node1_scraper",              scrape_js_node)
    graph.add_node("node2_js_analyzer",          make_node(analyze_js_node,        llm=llm_code))  # 去混淆需要長輸出
    graph.add_node("node3_phishing_classifier",  make_node(classify_phishing_node, llm=llm))
    graph.add_node("node4_cloaking_analyzer",    make_node(analyze_cloaking_node,  llm=llm_cloak))
    graph.add_node("node5_risk_output",          make_node(risk_output_node,       llm=llm))

    # 線性，沒有條件路由。
    # 舊版是「Node 3 判釣魚才進 Node 4」，但 Node 3 當時判的是爬蟲看到的頁面 ——
    # cloaking 成功的網站會給爬蟲乾淨頁 → 判非釣魚 → 永遠不進 Node 4。
    # 換句話說 cloaking 做得越好越不會被分析。現在兩份頁面在 Node 1 就取齊，
    # 釣魚與 cloaking 是兩個獨立屬性、各自判定，不互為前提。
    graph.add_edge("node1_scraper",           "node2_js_analyzer")
    graph.add_edge("node2_js_analyzer",       "node3_phishing_classifier")
    graph.add_edge("node3_phishing_classifier", "node4_cloaking_analyzer")
    graph.add_edge("node4_cloaking_analyzer", "node5_risk_output")
    graph.add_edge("node5_risk_output",       END)
    graph.set_entry_point("node1_scraper")
    return graph.compile()


# Graph 快取：compile 只做一次，所有 URL 共用同一個 compiled graph
# LangGraph 的 compiled graph 本身是 stateless（每次 invoke 傳入新的 state），
# 多 thread 並行呼叫 invoke() 是安全的。
_COMPILED_GRAPH = None

def get_graph():
    """回傳模組級快取的 compiled graph，避免每次 analyze_url/batch 都重新 compile。"""
    global _COMPILED_GRAPH
    if _COMPILED_GRAPH is None:
        _COMPILED_GRAPH = build_graph()
    return _COMPILED_GRAPH


def create_initial_state(url: str) -> AnalysisState:
    return AnalysisState(
        url=url, raw_html="", js_scripts=[], deobfuscated_js=[],
        bot_crawl={}, human_crawl={},
        is_phishing=False, phishing_confidence=0.0,
        phishing_indicators=[], cloaking_detected=False, cloaking_techniques=[],
        cloaking_verified=False,
        cloaking_confidence_tier="AMBIGUOUS", dual_crawl_results={},
        report="", errors=[]
    )


# ─────────────────────────────────────────────────────────────
#  進度條節點包裝
# ─────────────────────────────────────────────────────────────

NODE_STEPS = [
    ("node1_scraper",             "雙重爬取 BOT ‖ HUMAN"),
    ("node2_js_analyzer",         "JS 去混淆"),
    ("node3_phishing_classifier", "釣魚判定"),
    ("node4_cloaking_analyzer",   "Cloaking 比對"),
    ("node5_risk_output",         "輸出報告"),
]


def _plain_progress(current: int, total: int, label: str):
    """Rich 不可用時的簡單進度條"""
    bar_len = 30
    filled = int(bar_len * current / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    print(f"\r[{bar}] {current}/{total}  {label}", end="", flush=True)


# ─────────────────────────────────────────────────────────────
#  單一 URL 分析
# ─────────────────────────────────────────────────────────────

def analyze_url(url: str, quiet: bool = False) -> Dict[str, Any]:
    """分析單一 URL，quiet=True 時抑制節點內部 print"""
    app = get_graph()

    if not quiet:
        if RICH_AVAILABLE:
            console.print(Panel(f"[bold cyan]分析目標[/bold cyan]: {url}",
                                title="🔍 Phishing Analyzer"))
        else:
            print(f"\n{'='*60}\n  目標: {url}\n{'='*60}")

    final_state = app.invoke(create_initial_state(url))
    return final_state


# ─────────────────────────────────────────────────────────────
#  批次分析（含進度條）
# ─────────────────────────────────────────────────────────────

def analyze_batch(
    urls: List[str],
    output_dir: str = "results",
    save_csv: bool = True,
    save_individual_reports: bool = True,
    max_concurrent: int = 1,
) -> List[Dict[str, Any]]:
    """
    批次分析多個 URL
    - 並行執行（預設 max_concurrent=2），有效降低總耗時
    - max_concurrent 建議值：
        2 → 適合大多數機器（每個 URL 需 ~300MB RAM 給 Playwright；LLM 走遠端 API 不吃本機資源）
        1 → 降回串行，用於除錯或低記憶體環境
    - Rich 進度條顯示整體進度（並行時不顯示 per-URL 節點進度，避免多 thread 競爭更新）
    - 完成後輸出彙整表格 + CSV
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    CSV_DIR = Path(_BASE_DIR) / "csv_reports"
    CSV_DIR.mkdir(parents=True, exist_ok=True)

    app   = get_graph()   # 共用快取 graph，不在每個 thread 重建
    total = len(urls)
    # 結果依原始順序存放；all_results[i] 對應 urls[i]
    all_results: List[Dict[str, Any]] = [None] * total

    # Rich 進度條的 update 需要 lock 保護（多 thread 同時 advance）
    _progress_lock = threading.Lock()

    def _process_one(idx: int, url: str):
        """單一 URL 的完整分析流程，跑在 worker thread 裡"""
        try:
            final_state = app.invoke(create_initial_state(url))
            result      = _extract_result(final_state)
            result["status"] = "✅ 成功"
        except Exception as e:
            result = _empty_result(url)
            result["status"] = f"❌ 失敗: {e}"

        if save_individual_reports and result.get("report"):
            _save_report(result, output_dir, idx)

        return idx, result

    if RICH_AVAILABLE:
        console.print(f"\n[bold]批次分析 {total} 個網站（並行={max_concurrent}）[/bold]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=35),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:

            overall_task = progress.add_task("[cyan]整體進度", total=total)

            with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
                futures = {
                    executor.submit(_process_one, idx, url): idx
                    for idx, url in enumerate(urls)
                }

                for future in as_completed(futures):
                    idx, result = future.result()
                    all_results[idx] = result
                    with _progress_lock:
                        progress.update(
                            overall_task,
                            advance=1,
                            description=f"[cyan]整體進度  [{sum(r is not None for r in all_results)}/{total}]"
                        )

        _print_rich_summary(all_results, total)

    else:
        print(f"\n批次分析 {total} 個網站（並行={max_concurrent}）\n")

        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            futures = {
                executor.submit(_process_one, idx, url): idx
                for idx, url in enumerate(urls)
            }

            for future in as_completed(futures):
                idx, result = future.result()
                all_results[idx] = result
                done = sum(r is not None for r in all_results)
                _plain_progress(done, total, urls[idx][:60])

        print()
        _print_plain_summary(all_results)

    if save_csv:
        csv_path = _save_csv(all_results, CSV_DIR)
        if RICH_AVAILABLE:
            console.print(f"\n[bold green]✅ CSV 已儲存:[/bold green] {csv_path}")
        else:
            print(f"\n✅ CSV 已儲存: {csv_path}")

    return all_results


# ─────────────────────────────────────────────────────────────
#  輔助函式
# ─────────────────────────────────────────────────────────────

def _extract_result(state: AnalysisState) -> Dict[str, Any]:
    """從 state 提取彙整結果（欄位與 Node 5 報告一致：URL / 釣魚 / Cloaking）"""
    return {
        "url":         state["url"],
        "is_phishing": state["is_phishing"],
        "cloaking":    _cloaking_verdict(state),
        "error_count": len(state.get("errors", [])),
        "report":      state.get("report", ""),
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _empty_result(url: str) -> Dict[str, Any]:
    """分析失敗時的空結果"""
    return {
        "url": url, "is_phishing": None, "cloaking": CLOAKING_UNKNOWN,
        "error_count": 1, "report": "",
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _save_report(result: Dict, output_dir: str, idx: int):
    """儲存個別 Markdown 報告"""
    safe_name = result["url"]
    # 先替換 scheme 分隔符與路徑斜線，再清除 Windows 非法字元
    safe_name = safe_name.replace("://", "_").replace("/", "_")
    safe_name = re.sub(r'[\\?%*:|"<>]', "_", safe_name)  # Windows 保留字元
    safe_name = safe_name.strip(". ")[:60]                # 去除前後點/空白，限長
    path = Path(output_dir) / f"{idx+1:03d}_{safe_name}.md"
    path.write_text(result["report"], encoding="utf-8")


def _save_csv(results: List[Dict], output_dir: str) -> str:
    """儲存 CSV 彙整表（不含 report 欄位）"""
    if not results:
        return ""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path  = Path(output_dir) / f"batch_results_{timestamp}.csv"
    cols = [k for k in results[0].keys() if k != "report"]
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()
        for r in results:
            writer.writerow({k: r.get(k, "") for k in cols})
    return str(csv_path)


_CLOAK_ICON = {True: "✅", False: "❌"}
_CLOAK_ZH   = {True: "是", False: "否"}


def _print_rich_summary(results: List[Dict], total: int):
    """Rich 彙整摘要表格"""
    table = Table(title=f"\n📊 批次分析彙整 ({total} 個網站)",
                  show_header=True, header_style="bold magenta")
    table.add_column("#",        width=4,  justify="right")
    table.add_column("URL",      width=50, no_wrap=True)
    table.add_column("釣魚",     width=6,  justify="center")
    table.add_column("Cloaking", width=9,  justify="center")
    table.add_column("狀態",     width=12)

    for i, r in enumerate(results, 1):
        table.add_row(
            str(i),
            r["url"][:50] + "…" if len(r["url"]) > 50 else r["url"],
            "✅" if r.get("is_phishing") else "❌",
            _CLOAK_ICON.get(r.get("cloaking"), "－"),
            r.get("status", "")[:12],
        )
    console.print(table)

    phishing_count = sum(1 for r in results if r.get("is_phishing"))
    cloaking_count = sum(1 for r in results if r.get("cloaking") is True)
    unknown_count  = sum(1 for r in results if r.get("cloaking") not in (True, False))
    console.print(
        f"\n[bold]統計:[/bold] "
        f"釣魚網站 [red]{phishing_count}[/red]/{total}  |  "
        f"含 Cloaking [yellow]{cloaking_count}[/yellow]/{total}  |  "
        f"未分析/無法判斷 [dim]{unknown_count}[/dim]/{total}"
    )


def _print_plain_summary(results: List[Dict]):
    """純文字彙整摘要"""
    print(f"\n{'='*80}")
    print(f"{'#':<4} {'URL':<55} {'釣魚':<6} {'Cloaking':<10}")
    print(f"{'-'*80}")
    for i, r in enumerate(results, 1):
        print(
            f"{i:<4} {r['url'][:54]:<55} "
            f"{'是' if r.get('is_phishing') else '否':<6} "
            f"{_CLOAK_ZH.get(r.get('cloaking'), '未分析'):<10}"
        )
    print(f"{'='*80}")


# ─────────────────────────────────────────────────────────────
#  執行入口：自動讀取同目錄下的 urls.txt
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    urls_file = Path(_BASE_DIR) / "urls.txt"

    if not urls_file.exists():
        urls_file.write_text(
            "# 每行填入一個網址，# 開頭為註解\n"
            "https://example.com\n",
            encoding="utf-8"
        )
        print(f"[提示] 已建立 urls.txt，請填入要分析的網址後再執行。")
        print(f"       路徑: {urls_file}")
    else:
        urls = [
            line.strip()
            for line in urls_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not urls:
            print("[提示] urls.txt 內沒有網址，請填入後再執行。")
        elif len(urls) == 1:
            final = analyze_url(urls[0])
            print(final["report"])
            out = _extract_result(final)
            out.pop("report", None)
            _csv_dir = Path(_BASE_DIR) / "csv_reports"
            _csv_dir.mkdir(exist_ok=True)
            with open(_csv_dir / "result.json", "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
        else:
            analyze_batch(urls)