#!/usr/bin/env python3
"""
addr-screen — Tron (TRC20) 地址收款前風險查核。

設計參考 SlowMist 的 misttrack-skills/transfer_security_check.py 的決策樹骨架，
但不依賴任何 vendor API（不送資料給單一服務商、不需要任何 API key）。

三個獨立來源 cross-check：
  1. OFAC SDN 制裁名單（離線比對，完全不洩漏）
  2. TRONSCAN Security Service 公開 API（含 Tether 黑名單 freeze 狀態）
  3. GoPlus Security 公開 API（16 種 risk vector）

聚合規則：
  - 任何一個 source 回 BLOCK → BLOCK
  - 沒人 BLOCK，但有 WARN → WARN
  - 全部 ALLOW → ALLOW
  - 有 ERROR 但其他都 ALLOW → WARN（缺資訊不應視為安全）

Exit code:
  0  ALLOW   低風險，可收款
  1  WARN    有疑慮，人工二次確認
  2  BLOCK   嚴重風險，建議拒收
  3  ERROR   全部 source 都掛了，無法判斷

用法：
  python check.py --address TTxsEJ1AdiVeWjyEW7ADEZURaVQArAdCXj
  python check.py -a TTxs... --json
"""

import argparse
import json
import sys

# Windows console UTF-8 — 中文不亂碼。放在最前面，import 其他東西前就 reconfigure。
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass

from sources import goplus, tronscan, ofac

SOURCES = [
    ("OFAC SDN", ofac),
    ("TRONSCAN Security", tronscan),
    ("GoPlus", goplus),
]

EXIT_CODE = {"ALLOW": 0, "WARN": 1, "BLOCK": 2, "ERROR": 3}

# ANSI 色，可用 --no-color 關掉
COLOUR = {
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def aggregate(results: list[dict]) -> str:
    """
    SKIP 表示 source 沒啟用（如 opt-in 升級源沒設 env），完全不算缺資訊。
    ERROR 表示 source 啟用了但掛了,要當「應該有資訊但拿不到」處理。
    """
    decisions = [r["decision"] for r in results if r["decision"] != "SKIP"]
    if not decisions:
        return "ERROR"  # 一個 active source 都沒有
    if "BLOCK" in decisions:
        return "BLOCK"
    if "WARN" in decisions:
        return "WARN"
    if all(d == "ALLOW" for d in decisions):
        return "ALLOW"
    if "ERROR" in decisions:
        non_error = [d for d in decisions if d != "ERROR"]
        if non_error and all(d == "ALLOW" for d in non_error):
            return "WARN"  # 缺資訊不算安全
        return "ERROR"
    return "WARN"


def is_valid_tron_address(addr: str) -> bool:
    # Tron base58 地址 T 開頭 + 34 chars（含 T）
    # 簡單檢查，不做 base58 解碼
    return isinstance(addr, str) and addr.startswith("T") and len(addr) == 34


def render_human(address: str, results: list[dict], final: str, use_color: bool) -> None:
    c = COLOUR if use_color else {k: "" for k in COLOUR}

    icon = {"ALLOW": "✓", "WARN": "!", "BLOCK": "✗", "ERROR": "?"}.get(final, "?")
    colour = {
        "ALLOW": c["green"],
        "WARN": c["yellow"],
        "BLOCK": c["red"],
        "ERROR": c["yellow"],
    }.get(final, "")

    print(f"\n{c['bold']}地址風險查核{c['reset']}")
    print(f"地址：  {address}")
    print(f"鏈：    Tron / TRC20")
    print("─" * 60)

    for r in results:
        name = r["source"]
        d = r["decision"]
        line_colour = {
            "ALLOW": c["green"],
            "WARN": c["yellow"],
            "BLOCK": c["red"],
            "ERROR": c["dim"],
            "SKIP": c["dim"],
        }.get(d, "")
        flags = "，".join(r["flags"]) if r["flags"] else ""
        err = r.get("error")
        suffix = ""
        if flags:
            suffix = f"  [{flags}]"
        elif err:
            suffix = f"  ({c['dim']}{err}{c['reset']})"
        print(f"  {line_colour}{d:<6}{c['reset']}  {name}{suffix}")

    print("─" * 60)
    print(f"{colour}{c['bold']}最終判定：{icon} {final}{c['reset']}")

    if final == "ALLOW":
        n_active = sum(1 for r in results if r["decision"] != "SKIP")
        print(f"{c['green']}{n_active} 個啟用的查核來源都沒查到負面標記，可以收款。{c['reset']}")
        print(f"{c['dim']}提醒：「沒查到」不等於「100% 安全」。大額建議先 1 USDT 測試。{c['reset']}")
    elif final == "WARN":
        print(f"{c['yellow']}查到中等風險或部分來源失敗，建議人工二次確認後再決定。{c['reset']}")
    elif final == "BLOCK":
        print(f"{c['red']}查到嚴重風險，建議拒絕收款。{c['reset']}")
    else:
        print(f"{c['yellow']}所有查核來源都失敗，無法判斷，請稍後重試或人工核對。{c['reset']}")
    print()


def render_json(address: str, results: list[dict], final: str) -> None:
    payload = {
        "address": address,
        "chain": "tron",
        "final": final,
        "sources": [
            {
                "source": r["source"],
                "decision": r["decision"],
                "flags": r["flags"],
                "error": r.get("error"),
            }
            for r in results
        ],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Tron (TRC20) 地址收款前 AML / 詐騙風險查核（多源免費）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit code: 0=ALLOW, 1=WARN, 2=BLOCK, 3=ERROR\n"
            "適合接到收款腳本前置檢查，或直接給人看。"
        ),
    )
    parser.add_argument("--address", "-a", required=True, help="Tron 地址（T 開頭 34 字元）")
    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="輸出 JSON，給機器/Agent 解析")
    parser.add_argument("--no-color", action="store_true", help="關閉 ANSI 顏色")
    args = parser.parse_args()

    address = args.address.strip()

    if not is_valid_tron_address(address):
        msg = f"地址格式不像 Tron：{address}（應為 T 開頭 34 字元）"
        if args.json_output:
            print(json.dumps({"final": "ERROR", "error": msg, "address": address},
                             ensure_ascii=False, indent=2))
        else:
            print(f"\n⚠ {msg}\n", file=sys.stderr)
        return EXIT_CODE["ERROR"]

    results = []
    for _, mod in SOURCES:
        try:
            results.append(mod.check(address))
        except Exception as e:  # 保底，不讓單一 source 炸毀全流程
            results.append({
                "source": mod.__name__.split(".")[-1],
                "decision": "ERROR",
                "flags": [],
                "error": f"未預期錯誤: {e}",
                "raw": None,
            })

    final = aggregate(results)

    if args.json_output:
        render_json(address, results, final)
    else:
        render_human(address, results, final, use_color=not args.no_color)

    return EXIT_CODE.get(final, EXIT_CODE["ERROR"])


if __name__ == "__main__":
    sys.exit(main())
