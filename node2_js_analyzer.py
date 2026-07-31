"""
node2_js_analyzer.py  JS 去混淆

去混淆支援類型：
  1. Dean Edwards Packer       (eval(function(p,a,c,k,e,...)))
  2. eval(atob()) / eval(unescape())
  3. Hex / Unicode 跳脫        (\\xNN / \\uXXXX)
  4. obfuscator.io 字串陣列    (_0x 前綴 + 旋轉查找函式)
  5. JSFuck / JJencode 偵測    ([][(![]+[])...] / $=~[])
  6. 字串常數合併              ("a"+"b" → "ab")
  7. js-beautify 格式化
  8. LLM 輔助（分塊處理大腳本，多輪迭代）
"""
import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import re
import base64
import subprocess
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, Any, List

import jsbeautifier
from state import AnalysisState

# ── 常數 ─────────────────────────────────────────────────────
MAX_ITERATIONS   = 3      # 最多迭代幾輪
LLM_CHUNK_SIZE   = 2500   # 每塊送給 LLM 的字元上限
LLM_TIMEOUT_SEC  = 90     # 單次 LLM timeout
OBF_SCORE_THRESH = 0.45   # 觸發 LLM 的混淆分數門檻

class Deobfuscator:

    def beautify(self, code: str) -> str:
        opts = jsbeautifier.default_options()
        opts.indent_size           = 2
        opts.break_chained_methods = True
        opts.unescape_strings      = True
        opts.jslint_happy          = False
        try:
            return jsbeautifier.beautify(code, opts)
        except Exception:
            return code

    def try_de4js_cli(self, code: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["de4js", "--input", "-"],
                input=code, capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    def decode_eval_patterns(self, code: str) -> str:
        def decode_atob(m):
            try:
                return base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            except Exception:
                return m.group(0)

        def decode_unescape(m):
            try:
                return urllib.parse.unquote(m.group(1))
            except Exception:
                return m.group(0)

        code = re.sub(
            r"eval\s*\(\s*atob\s*\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*\)\s*\)",
            decode_atob, code
        )
        code = re.sub(
            r"eval\s*\(\s*unescape\s*\(\s*['\"]([^'\"]+)['\"]\s*\)\s*\)",
            decode_unescape, code
        )
        return code

    def decode_hex_strings(self, code: str) -> str:
        def decode_hex(m):
            try:
                return bytes.fromhex(m.group(1)).decode("utf-8", errors="replace")
            except Exception:
                return m.group(0)
        return re.sub(r"\\x([0-9a-fA-F]{2})", decode_hex, code)

    def decode_unicode_escapes(self, code: str) -> str:
        def replace_unicode(m: re.Match) -> str:
            try:
                return chr(int(m.group(1), 16))
            except (ValueError, OverflowError):
                return m.group(0)
        return re.sub(r"\\u([0-9a-fA-F]{4})", replace_unicode, code)

    def decode_obfuscator_io(self, code: str) -> tuple:
        changed = False
        array_pattern = re.compile(
            r"var\s+(_0x[0-9a-fA-F]+)\s*=\s*\[([^\]]*)\]\s*;",
            re.DOTALL
        )
        for m in array_pattern.finditer(code):
            arr_name = m.group(1)
            raw_items = m.group(2)

            items: List[str] = []
            for item_m in re.finditer(
                r"'((?:[^'\\]|\\.)*)'\s*,?|\"((?:[^\"\\]|\\.)*)\"\s*,?",
                raw_items
            ):
                items.append(
                    item_m.group(1) if item_m.group(1) is not None
                    else item_m.group(2)
                )
            if not items:
                continue

            lookup_pattern = re.compile(
                r"function\s+(_0x[0-9a-fA-F]+)\s*\([^)]*\)\s*\{"
                r"[^}]*return\s+" + re.escape(arr_name) + r"\s*\[",
                re.DOTALL
            )
            lm = lookup_pattern.search(code)
            if not lm:
                continue
            lookup_fn = lm.group(1)

            def replace_call(cm, _items=items):
                try:
                    idx = int(cm.group(1), 16)
                    if 0 <= idx < len(_items):
                        return repr(_items[idx])
                except Exception:
                    pass
                return cm.group(0)

            new_code = re.sub(
                re.escape(lookup_fn) + r"\s*\(\s*0x([0-9a-fA-F]+)\s*\)",
                replace_call, code
            )
            if new_code != code:
                code = new_code
                changed = True

        return code, changed

    def is_jsfuck_or_jjencode(self, code: str) -> bool:
        stripped = re.sub(r'\s', '', code)
        if not stripped:
            return False
        jsfuck_chars = set('[]!+()')
        jsfuck_ratio = sum(1 for c in stripped if c in jsfuck_chars) / len(stripped)
        is_jjencode  = stripped.startswith('$=~[]') or stripped.startswith('$$$=~[]')
        return jsfuck_ratio > 0.85 or is_jjencode

    def fold_string_concat(self, code: str) -> str:
        pattern = re.compile(
            r"""(['"])((?:[^'"\\]|\\.)*)\1\s*\+\s*(['"])((?:[^'"\\]|\\.)*)\3"""
        )
        for _ in range(5):
            new_code = pattern.sub(
                lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1),
                code
            )
            if new_code == code:
                break
            code = new_code
        return code

    def llm_deobfuscate(self, code: str, llm_instance) -> str:
        if len(code) <= LLM_CHUNK_SIZE:
            return self._llm_invoke_chunk(code, llm_instance)
        chunks  = self._split_by_boundary(code, LLM_CHUNK_SIZE)
        results = []
        for i, chunk in enumerate(chunks):
            print(f"    [LLM] 分塊 {i+1}/{len(chunks)} ({len(chunk)} chars)...")
            results.append(self._llm_invoke_chunk(chunk, llm_instance))
        return "\n".join(results)

    def _split_by_boundary(self, code: str, chunk_size: int) -> List[str]:
        chunks, start = [], 0
        while start < len(code):
            end = start + chunk_size
            if end >= len(code):
                chunks.append(code[start:])
                break
            boundary = code.rfind('\n', start, end)
            if boundary <= start:
                boundary = end
            chunks.append(code[start:boundary])
            start = boundary
        return chunks

    def _llm_invoke_chunk(self, chunk: str, llm_instance) -> str:
        prompt = (
            "You are a JavaScript deobfuscation expert.\n"
            "Deobfuscate the following JavaScript code.\n"
            "Rules:\n"
            "- Return ONLY the cleaned JavaScript code\n"
            "- Rename meaningless variable names (_0x, a, b...) to descriptive names\n"
            "- Resolve string arrays and replace lookup calls with actual string values\n"
            "- Remove dead code and self-defending code\n"
            "- All inline comments must be in English\n"
            "- Do NOT add any explanation outside the code\n\n"
            f"Obfuscated JS:\n```javascript\n{chunk}\n```"
        )
        # 注意：不使用 with 語句管理 executor。
        # with ThreadPoolExecutor 的 __exit__ 會呼叫 shutdown(wait=True)，
        # 即使 future.result(timeout=) 已超時拋出例外，shutdown 仍會無限等待
        # llm.invoke 線程結束——若 API 卡住，主流程永遠無法繼續。
        # 改用 shutdown(wait=False) 讓線程在背景自行結束，不阻塞主流程。
        _llm_executor = ThreadPoolExecutor(max_workers=1)
        try:
            future = _llm_executor.submit(llm_instance.invoke, prompt)
            result = future.result(timeout=LLM_TIMEOUT_SEC)
        except Exception:
            return chunk
        finally:
            _llm_executor.shutdown(wait=False)
        result = re.sub(r"^```(?:javascript)?\n?", "", result.strip())
        result = re.sub(r"\n?```$", "", result.strip())
        return result

    def _measure_obfuscation(self, code: str) -> float:
        if not code:
            return 0.0
        words = re.findall(r'[a-zA-Z_$][a-zA-Z0-9_$]*', code)
        if not words:
            return 0.0
        avg_len     = sum(len(w) for w in words) / len(words)
        short_ratio = sum(1 for w in words if len(w) <= 2) / len(words)
        hex_ratio   = len(re.findall(r'\\x[0-9a-fA-F]{2}', code)) / max(len(code), 1)
        obfio_ratio = sum(1 for w in words if w.startswith('_0x')) / max(len(words), 1)
        stripped    = re.sub(r'\s', '', code)
        jsfuck_chars  = set('[]!+()')
        jsfuck_ratio  = (
            sum(1 for c in stripped if c in jsfuck_chars) / len(stripped)
            if stripped else 0
        )
        score = (
            short_ratio  * 0.25 +
            obfio_ratio  * 0.35 +
            (hex_ratio * 100) * 0.15 +
            (max(0, 4 - avg_len) / 4) * 0.15 +
            jsfuck_ratio * 0.10
        )
        return min(1.0, score)

    def deobfuscate(self, code: str, llm_instance) -> Dict[str, Any]:
        techniques_used: List[str] = []
        prev_score = self._measure_obfuscation(code)

        for iteration in range(MAX_ITERATIONS):
            changed = False
            tag = f"[round{iteration+1}]"

            if re.search(r"eval\s*\(function\s*\(p,a,c,k,e", code):
                result = self.try_de4js_cli(code)
                if result:
                    code = result
                    techniques_used.append(f"{tag} de4js (Dean Edwards Packer)")
                    changed = True

            if re.search(r"eval\s*\(\s*atob\s*\(", code) or \
               re.search(r"eval\s*\(\s*unescape\s*\(", code):
                new = self.decode_eval_patterns(code)
                if new != code:
                    code = new
                    techniques_used.append(f"{tag} eval decode (atob/unescape)")
                    changed = True

            if re.search(r"\\x[0-9a-fA-F]{2}", code):
                code = self.decode_hex_strings(code)
                techniques_used.append(f"{tag} hex decode (\\xNN)")
                changed = True

            if re.search(r"\\u[0-9a-fA-F]{4}", code):
                code = self.decode_unicode_escapes(code)
                techniques_used.append(f"{tag} unicode decode (\\uXXXX)")
                changed = True

            if re.search(r"var\s+_0x[0-9a-fA-F]+\s*=\s*\[", code):
                code, io_changed = self.decode_obfuscator_io(code)
                if io_changed:
                    techniques_used.append(f"{tag} obfuscator.io string array decode")
                    changed = True

            new = self.fold_string_concat(code)
            if new != code:
                code = new
                techniques_used.append(f"{tag} string concat folding")
                changed = True

            code = self.beautify(code)

            current_score = self._measure_obfuscation(code)
            if not changed and current_score >= prev_score - 0.02:
                break
            prev_score = current_score

        final_score = self._measure_obfuscation(code)
        is_special  = self.is_jsfuck_or_jjencode(code)

        if final_score > OBF_SCORE_THRESH or is_special:
            label = "JSFuck/JJencode" if is_special else f"score={final_score:.2f}"
            print(f"    → 觸發 LLM 去混淆 ({label})")
            code = self.llm_deobfuscate(code, llm_instance)
            code = self.beautify(code)
            techniques_used.append(f"LLM-assisted ({label})")

        if not techniques_used:
            techniques_used.append("no obfuscation detected")

        return {
            "deobfuscated":      code,
            "techniques_used":   techniques_used,
            "obfuscation_score": self._measure_obfuscation(code),
        }


# ─────────────────────────────────────────────────────────────
# LangGraph Node 函式
# ─────────────────────────────────────────────────────────────
def analyze_js_node(state: AnalysisState, llm) -> AnalysisState:
    """
    Node 2: JS 去混淆

    對所有抓取到的 JS 執行完整去混淆，供 Node 3（釣魚判準）與
    Node 4（靜態 cloaking regex）使用 —— 兩者都需要還原後的可讀原始碼，
    壓縮過的 `n.wD` 比對不到 `navigator.webdriver`。
    """
    print("\n[Node 2] JS 去混淆...")

    deobfuscator = Deobfuscator()
    deobfuscated = []
    total = len(state["js_scripts"])

    for i, script in enumerate(state["js_scripts"]):
        print(f"  → [去混淆 {i+1}/{total}] {script['type']} ({len(script['content'])} chars)...")
        result = deobfuscator.deobfuscate(script["content"], llm)
        deobfuscated.append({
            **script,
            "deobfuscated":      result["deobfuscated"],
            "techniques_used":   result["techniques_used"],
            "obfuscation_score": result["obfuscation_score"],
        })
        print(f"     分數: {result['obfuscation_score']:.2f} "
              f"| 工具: {', '.join(result['techniques_used'])}")

    state["deobfuscated_js"] = deobfuscated
    print(f"  → 去混淆完成: {len(deobfuscated)} 個腳本")
    return state

    return state