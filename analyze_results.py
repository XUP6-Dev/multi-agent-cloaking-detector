"""
analyze_results.py — 讀 csv_reports/ 直接算出論文 §V 的表 IX、表 X、χ²、Cohen's κ

用法:
    python analyze_results.py                      # 讀 csv_reports/ 下每個子資料夾
    python analyze_results.py --dir csv_reports_v3 # 指定其他目錄
    python analyze_results.py --labels labels.csv  # 提供標記才能算 FPR

目錄結構假設（與現行輸出一致）:
    csv_reports/<模型名>/phishing_report_<時間戳>.csv   ← 同名多份時取最新
    欄位: url,is_phishing,cloaking     cloaking ∈ {True, False, N/A}

labels.csv（選填）:
    url,label        label ∈ {phishing, benign}
    沒有這個檔就算不出 FPR —— 腳本會明說「無標記」而不是靜靜跳過。

純標準庫，不依賴 scipy/numpy（本專案 .venv 沒裝）。
"""
import os
import re
import csv
import sys
import math
import glob
import argparse
import itertools
from collections import Counter, defaultdict

CLOAK_CLASSES = ("True", "False", "N/A")


# ── 統計工具（scipy 不在依賴內，這裡自己實作）─────────────────────
def _gser(a, x):
    """下不完全 gamma 的級數展開，適用 x < a+1"""
    ap, s, d = a, 1.0 / a, 1.0 / a
    for _ in range(500):
        ap += 1
        d *= x / ap
        s += d
        if abs(d) < abs(s) * 1e-12:
            break
    return s * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gcf(a, x):
    """上不完全 gamma 的連分數展開，適用 x >= a+1"""
    tiny = 1e-300
    b, c, d = x + 1.0 - a, 1.0 / tiny, 1.0 / (x + 1.0 - a)
    h = d
    for i in range(1, 500):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-12:
            break
    return h * math.exp(-x + a * math.log(x) - math.lgamma(a))


def chi2_sf(x, df):
    """卡方分布的上尾機率 P(X > x)；即 p-value"""
    if x <= 0:
        return 1.0
    a, xx = df / 2.0, x / 2.0
    return 1.0 - _gser(a, xx) if xx < a + 1.0 else _gcf(a, xx)


def wilson(k, n, z=1.96):
    """Wilson 分數信賴區間；比例接近 0 或 1 時覆蓋率優於 Wald"""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, centre - half), min(1.0, centre + half))


def cohen_kappa(a_vals, b_vals, classes):
    """兩位評分者之 Cohen's κ（支援多類別）"""
    n = len(a_vals)
    if n == 0:
        return float("nan")
    po = sum(1 for x, y in zip(a_vals, b_vals) if x == y) / n
    ca, cb = Counter(a_vals), Counter(b_vals)
    pe = sum((ca[c] / n) * (cb[c] / n) for c in classes)
    return float("nan") if abs(1 - pe) < 1e-12 else (po - pe) / (1 - pe)


def fleiss_kappa(rows, classes):
    """rows: 每個項目一列，內容為各評分者之類別；回傳 Fleiss' κ"""
    n_items = len(rows)
    if n_items == 0:
        return float("nan")
    k = len(rows[0])
    if k < 2:
        return float("nan")
    p_bar = 0.0
    cat_total = Counter()
    for r in rows:
        c = Counter(r)
        cat_total.update(c)
        p_bar += (sum(v * v for v in c.values()) - k) / (k * (k - 1))
    p_bar /= n_items
    pe = sum((cat_total[c] / (n_items * k)) ** 2 for c in classes)
    return float("nan") if abs(1 - pe) < 1e-12 else (p_bar - pe) / (1 - pe)


def kappa_label(k):
    """Landis & Koch (1977) 之慣用解讀"""
    if k != k:
        return "—"
    for thr, lab in ((0.0, "poor"), (0.20, "slight"), (0.40, "fair"),
                     (0.60, "moderate"), (0.80, "substantial")):
        if k <= thr:
            return lab
    return "near-perfect"


# ── 讀檔 ──────────────────────────────────────────────────────
def load_reports(base):
    """回傳 {模型名: {url: (is_phishing, cloaking)}}"""
    data = {}
    if not os.path.isdir(base):
        sys.exit(f"[!] 找不到目錄: {base}")
    for name in sorted(os.listdir(base)):
        d = os.path.join(base, name)
        if not os.path.isdir(d):
            continue
        files = sorted(glob.glob(os.path.join(d, "phishing_report_*.csv")))
        if not files:
            print(f"    [略過] {name}: 無 phishing_report_*.csv")
            continue
        latest = files[-1]          # 檔名含時間戳，字典序即時間序
        rows = {}
        with open(latest, encoding="utf-8-sig", newline="") as fh:
            for r in csv.DictReader(fh):
                u = (r.get("url") or "").strip()
                if not u:
                    continue
                cloak = (r.get("cloaking") or "").strip()
                if cloak not in CLOAK_CLASSES:
                    print(f"    [警告] {name}: 未預期的 cloaking 值 {cloak!r}（url={u[:40]}）")
                rows[u] = ((r.get("is_phishing") or "").strip(), cloak)
        data[name] = rows
        if len(files) > 1:
            print(f"    [note] {name}: 有 {len(files)} 份報告，採用最新的 {os.path.basename(latest)}")
    if not data:
        sys.exit(f"[!] {base} 下沒有可用的報告")
    return data


def load_labels(path):
    """回傳 {url: 'phishing'|'benign'}；沒有檔案則回傳 None"""
    if not path:
        return None
    if not os.path.isfile(path):
        sys.exit(f"[!] 找不到標記檔: {path}")
    lab = {}
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            u = (r.get("url") or "").strip()
            v = (r.get("label") or "").strip().lower()
            if u and v:
                lab[u] = v
    return lab


# ── 各表 ──────────────────────────────────────────────────────
def table_ix(data, common, labels):
    print("\n表 IX　各語言模型後端之主要結果"
          f"（N = {len(common)}，各模型使用相同 URL 集合）")
    print("-" * 136)
    print("%-16s %6s %8s %8s %-18s %8s %-18s %9s %-18s %8s %8s"
          % ("模型", "|Ph_k|", "PDR_k", "CVR_k", "95% CI",
             "CVR*_k", "95% CI", "CVR^U_k", "95% CI", "NAR_k", "BR_k"))
    print("-" * 136)
    n_all = len(common)
    out = {}
    for m, rows in data.items():
        ph = [u for u in common if rows[u][0] == "True"]
        n_ph = len(ph)
        c = Counter(rows[u][1] for u in ph)
        t, f, na = c.get("True", 0), c.get("False", 0), c.get("N/A", 0)
        meas = t + f                       # CVR* 的分母：排除未測量
        cvr = t / n_ph if n_ph else float("nan")
        cvrs = t / meas if meas else float("nan")
        nar = na / n_ph if n_ph else float("nan")
        lo1, hi1 = wilson(t, n_ph)
        lo2, hi2 = wilson(t, meas)

        # CVR^U：分母為全體評估集 |U|，完全不經由 ŷ_k。
        # CVR / CVR* / NAR 的分母都是 Ph_k，而 Ph_k 由 ŷ_k 定義，ŷ_k 在
        # Layer 1 未觸發時含 LLM 貢獻 —— 所以那三個指標的跨模型差異，
        # 可能來自 cloak(u) 變動，也可能只是 Ph_k 成員資格變動，χ² 分不出來。
        # CVR^U 不經過那條路徑，才是 H1 的直接檢驗量（論文 §V-E）。
        t_all = sum(1 for u in common if rows[u][1] == "True")
        cvr_u = t_all / n_all if n_all else float("nan")
        lo3, hi3 = wilson(t_all, n_all)

        if labels:
            legit = [u for u in common if labels.get(u) == "benign"]
            # BR_k：合法組的 cloaking 盛行率。這「不是」錯誤率 —— cloaking 是
            # 中性技術，合法網站本就會因 WAF 擋爬蟲 / 地理導向 / A-B test /
            # 付費牆做差異化遞送，偵測到即為正確觀測（論文表 VIII）。
            br = (sum(1 for u in legit if rows[u][1] == "True") / len(legit)
                  if legit else float("nan"))
            br_s = "%.1f%%" % (100 * br)
        else:
            br, br_s = None, "無標記"

        print("%-16s %6d %7.1f%% %7.1f%% [%5.1f–%5.1f%%] %7.1f%% [%5.1f–%5.1f%%] %8.1f%% [%5.1f–%5.1f%%] %7.1f%% %8s"
              % (m, n_ph, 100 * len(ph) / len(common), 100 * cvr,
                 100 * lo1, 100 * hi1, 100 * cvrs, 100 * lo2, 100 * hi2,
                 100 * cvr_u, 100 * lo3, 100 * hi3,
                 100 * nar, br_s))
        out[m] = dict(n_ph=n_ph, n_all=n_all, true=t, false=f, na=na,
                      true_all=t_all,
                      pdr=len(ph) / len(common), cvr=cvr, cvr_star=cvrs,
                      cvr_u=cvr_u, nar=nar, br=br)
    print("-" * 136)
    print("CVR_k   = True / |Ph_k|（N/A 計入分母，保守估計）")
    print("CVR*_k  = True / (True + False)（僅計已可信測量者）")
    print("CVR^U_k = True / |U|（分母為全體評估集，不經由 ŷ_k → H1 之直接檢驗量）")
    print("NAR_k   = N/A  / |Ph_k|（驗證曾嘗試但不可信之比例）")
    print("BR_k    = 合法組 cloaking 盛行率（描述性統計，不是錯誤率 —— 見論文表 VIII）")
    if not labels:
        print("BR_k   需要 ground-truth 標記；請以 --labels labels.csv 提供"
              "（欄位 url,label；label ∈ phishing/benign）")
    return out


def chi2_h1(stats, mode):
    """
    卡方齊一性檢定。三種分母各測一次：

      mode='unconditional' → CVR^U，分母 |U|，不經由 ŷ_k。這是 H1 的直接檢驗：
                             差異只可能來自 cloak(u) 本身。
      mode='all'           → CVR，分母 |Ph_k|
      mode='measured'      → CVR*，分母排除 N/A

    後兩者的分母都由 ŷ_k 定義，故其跨模型差異混合了兩個來源（cloak(u) 變動、
    Ph_k 成員資格變動），只能當描述性指標讀，不能單獨用來裁決 H1。
    """
    ks = list(stats)
    if len(ks) < 2:
        print("  只有 1 個模型，無法做齊一性檢定 —— H1 的檢驗需要至少 2 個 LLM 後端。")
        return
    if mode == "unconditional":
        o1 = [stats[m]["true_all"] for m in ks]
        tot = [stats[m]["n_all"] for m in ks]
        desc = "CVR^U（分母 |U|，不經由 ŷ_k）★ H1 之直接檢驗"
    elif mode == "all":
        o1 = [stats[m]["true"] for m in ks]
        tot = [stats[m]["n_ph"] for m in ks]
        desc = "CVR（分母 |Ph_k|，含 N/A）— 描述性，分母經由 ŷ_k"
    else:
        o1 = [stats[m]["true"] for m in ks]
        tot = [stats[m]["true"] + stats[m]["false"] for m in ks]
        desc = "CVR*（分母排除 N/A）— 描述性，分母經由 ŷ_k"
    o0 = [t - a for t, a in zip(tot, o1)]
    s1, s0, sn = sum(o1), sum(o0), sum(tot)
    if sn == 0 or s1 == 0 or s0 == 0:
        print(f"  {desc}: 無法檢定（某一格總數為 0）")
        return
    chi = 0.0
    for i in range(len(ks)):
        for obs, s in ((o1[i], s1), (o0[i], s0)):
            e = tot[i] * s / sn
            if e > 0:
                chi += (obs - e) ** 2 / e
    df = len(ks) - 1
    p = chi2_sf(chi, df)
    verdict = ("不拒絕 H0 → 支持 LLM 不變性" if p >= 0.05
               else "拒絕 H0 → 各模型間存在顯著差異，需檢查離群模型")
    print(f"  {desc}")
    print(f"    χ² = {chi:.3f},  df = {df},  p = {p:.4f}  →  {verdict}")


def table_x(data, common):
    ms = list(data)
    print("\n表 X　逐對 Cohen's κ（上三角：釣魚判定，二類；下三角：偽裝判定，三類）")
    print("-" * (18 + 17 * len(ms)))
    print("%-17s" % "", end="")
    for m in ms:
        print("%16s " % m[:16], end="")
    print()
    kap = {}
    for a, b in itertools.combinations(ms, 2):
        kap[(a, b)] = cohen_kappa([data[a][u][0] for u in common],
                                  [data[b][u][0] for u in common],
                                  ("True", "False"))
        kap[(b, a)] = cohen_kappa([data[a][u][1] for u in common],
                                  [data[b][u][1] for u in common],
                                  CLOAK_CLASSES)
    for ra in ms:
        print("%-17s" % ra[:17], end="")
        for rb in ms:
            print("%16s " % ("1.000" if ra == rb else "%.3f" % kap[(ra, rb)]), end="")
        print()
    print("-" * (18 + 17 * len(ms)))
    print("偽裝判定務必以三類計算：把 N/A 併入 False 再算二類，"
          "正好抹除本文所強調之「未測量 vs 測得為否」的區分。")

    if len(ms) < 2:
        print("\n只有 1 個模型，無法計算一致性統計量。")
        return

    ph_rows = [[data[m][u][0] for m in ms] for u in common]
    ck_rows = [[data[m][u][1] for m in ms] for u in common]
    fk_ph = fleiss_kappa(ph_rows, ("True", "False"))
    fk_ck = fleiss_kappa(ck_rows, CLOAK_CLASSES)
    print("\n整體一致性（Fleiss' κ，%d 位評分者）" % len(ms))
    print("  釣魚判定  κ = %.3f  (%s)" % (fk_ph, kappa_label(fk_ph)))
    print("  偽裝判定  κ = %.3f  (%s)" % (fk_ck, kappa_label(fk_ck)))
    full = sum(1 for r in ck_rows if len(set(r)) == 1)
    print("  四模型偽裝結論完全一致: %d / %d = %.1f%%"
          % (full, len(common), 100 * full / len(common)))


def crosstab(data, common):
    """
    is_phishing × cloaking 2×2（實際 2×3）交叉表 —— 本研究的核心視圖。

    兩個屬性彼此獨立，四格都是有效的量測結果，不存在「哪一格是錯的」：

      釣魚 ∧ cloaking   ← 研究標的：對爬蟲隱藏自己的釣魚站
      釣魚 ∧ 無 cloaking ← 是釣魚但沒藏，傳統爬蟲即可偵測
      非釣魚 ∧ cloaking  ← 合法網站的差異化遞送（WAF 擋爬蟲、地理導向、
                          A/B test、付費牆）。cloaking 是中性技術，
                          這格是「真的有 cloaking 但不是釣魚」，並非偽陽性
      非釣魚 ∧ 無 cloaking ← 一般網站

    因此第三格的比例應解讀為「合法網站的 cloaking 盛行率」（描述性統計），
    不是錯誤率。真正的偽陽性需要 cloaking 的 ground-truth 標記才能談，
    而現有公開資料集並不提供（見論文 §V-B）。
    """
    print("\nis_phishing × cloaking 交叉表（兩個獨立屬性，四格皆為有效觀測）")
    print("-" * 74)
    print("%-16s %-10s %8s %8s %8s %10s" % ("模型", "is_phishing", "True", "False", "N/A", "小計"))
    print("-" * 74)
    for m, rows in data.items():
        for flag in ("True", "False"):
            sub = [u for u in common if rows[u][0] == flag]
            c = Counter(rows[u][1] for u in sub)
            print("%-16s %-10s %8d %8d %8d %10d"
                  % (m if flag == "True" else "", flag,
                     c.get("True", 0), c.get("False", 0), c.get("N/A", 0), len(sub)))
    print("-" * 74)
    # 盛行率一律排除 N/A —— 與 CVR* 同一原則：未測量不能當成「沒有」
    def cnt(ph, ck):
        return sum(1 for m in data for u in common
                   if data[m][u][0] == ph and data[m][u][1] == ck)
    a, b = cnt("True", "True"),  cnt("True", "False")     # 釣魚組：有/無 cloaking
    c, d = cnt("False", "True"), cnt("False", "False")    # 非釣魚組：有/無 cloaking
    print("cloaking 盛行率（分母排除 N/A，與 CVR* 同一原則）")
    print("  釣魚組    : %d / %d = %.1f%%   ← 研究標的所在" % (a, a + b, 100 * a / (a + b) if a + b else 0))
    print("  非釣魚組  : %d / %d = %.1f%%   ← 合法網站的 cloaking 盛行率，非錯誤率"
          % (c, c + d, 100 * c / (c + d) if c + d else 0))
    print("  cloaking 為中性技術（WAF 擋爬蟲、地理導向、A/B test、付費牆），")
    print("  合法網站本就會做差異化遞送，故此列不應解讀為偽陽性。")
    if a and b and c and d:
        orr = (a / b) / (c / d)
        print("  → 勝算比 OR = %.2f" % orr)
        print("  OR 才是「cloaking 對釣魚是否具鑑別力」的證據，建議於 §V-D 一併報告。")
        print("  OR 接近 1 代表兩組盛行率相當，cloaking 單獨作為釣魚指標的鑑別力有限；")
        print("  此時本系統的價值在於「兩個屬性各自獨立且誠實地量測並聯合報告」，")
        print("  而非把 cloaking 當成釣魚的代理指標 —— 這也正是管線不設條件路由的理由。")


def disagreements(data, common, limit=15):
    ms = list(data)
    rows = [(u, [data[m][u][1] for m in ms]) for u in common]
    bad = [(u, v) for u, v in rows if len(set(v)) > 1]
    if not bad:
        print("\n所有模型之偽裝結論完全一致，無分歧案例。")
        return
    print(f"\n偽裝結論分歧之 URL（共 {len(bad)} 筆，列出前 {min(limit, len(bad))} 筆）")
    print("  這些是 H1 的反例候選，值得個別檢視 evidence 欄位")
    print("  %-52s %s" % ("URL", " / ".join(m[:12] for m in ms)))
    for u, v in bad[:limit]:
        print("  %-52s %s" % (u[:52], " / ".join("%-12s" % x for x in v)))


def main():
    ap = argparse.ArgumentParser(description="計算論文 §V 的表 IX、表 X、χ²、Cohen's κ")
    ap.add_argument("--dir", default="csv_reports", help="報告根目錄（預設 csv_reports）")
    ap.add_argument("--labels", default=None, help="ground-truth 標記 CSV（算 BR_k 用）")
    args = ap.parse_args()

    print("=" * 108)
    print("PhishCloak Detector — §V 實驗結果分析")
    print("=" * 108)
    print("讀取:", os.path.abspath(args.dir))
    data = load_reports(args.dir)
    labels = load_labels(args.labels)

    sets = [set(v) for v in data.values()]
    common = sorted(set.intersection(*sets))
    sizes = {m: len(v) for m, v in data.items()}
    print("模型數: %d  %s" % (len(data), list(data)))
    print("各模型 URL 數: %s | 交集: %d" % (sizes, len(common)))
    if len(set(sizes.values())) > 1 or any(len(s) != len(common) for s in sets):
        print("[!] 各模型的 URL 集合不一致 —— 以下所有比較僅使用交集，"
              "跨模型數值才可直接對照")
    if labels:
        miss = [u for u in common if u not in labels]
        print("標記檔: %d 筆；交集中無標記者: %d" % (len(labels), len(miss)))

    stats = table_ix(data, common, labels)

    print("\n" + "=" * 108)
    print("H1 檢驗：偽裝結論是否與語言模型後端無關（卡方齊一性檢定，α = 0.05）")
    print("=" * 108)
    chi2_h1(stats, "unconditional")
    chi2_h1(stats, "all")
    chi2_h1(stats, "measured")
    print("  註 1：以 CVR^U 為準。CVR 與 CVR* 的分母 |Ph_k| 由 ŷ_k 定義，"
          "其跨模型差異無法區辨")
    print("        「cloak(u) 變動」與「Ph_k 成員資格變動」兩個來源，僅供描述。")
    print("  註 2：決定性規則層（D1–D7、C1–C5）本就不呼叫 LLM，"
          "故本檢定是對該結構性質的驗證，而非 H1 的唯一依據。")

    table_x(data, common)
    crosstab(data, common)
    disagreements(data, common)

    print("\n" + "=" * 108)
    print("完成。表 IX / 表 X 可直接填入論文 §V-D 與 §V-E。")
    if not labels:
        print("提醒：未提供 --labels，BR_k 一欄仍為空；"
              "§V-C 的表 VIII 有列出該指標，投稿前需補齊。")
    print("=" * 108)


if __name__ == "__main__":
    main()
