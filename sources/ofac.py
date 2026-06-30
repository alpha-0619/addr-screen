"""
OFAC SDN 制裁清單查核（離線比對，完全不洩漏查詢內容）。

來源：0xB10C/ofac-sanctioned-digital-currency-addresses (lists branch)
每天 0 UTC 由 GitHub Actions 從美國財政部 OFAC SDN.XML 重新產生。

本地 cache 在 cache/ofac_TRX.txt，TTL 7 天。
若 cache 不在或過期會自動下載；下載失敗則 fallback 用舊 cache。
"""

from pathlib import Path
import time
import urllib.request
import urllib.error

# 一行一個地址的純文字檔
LIST_URL = (
    "https://raw.githubusercontent.com/0xB10C/"
    "ofac-sanctioned-digital-currency-addresses/lists/"
    "sanctioned_addresses_TRX.txt"
)

CACHE_DIR = Path(__file__).resolve().parent.parent / "cache"
CACHE_FILE = CACHE_DIR / "ofac_TRX.txt"
TTL_SECONDS = 7 * 24 * 60 * 60  # 7 天


def _refresh_cache() -> tuple[bool, str | None]:
    """嘗試重新下載清單。回傳 (ok, error_msg)。"""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        req = urllib.request.Request(
            LIST_URL,
            headers={"User-Agent": "addr-screen/0.1"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
        # 寫到 tmp 再 rename，避免 partial write
        tmp = CACHE_FILE.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(CACHE_FILE)
        return True, None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        return False, f"OFAC 清單下載失敗: {e}"


def _load_addresses() -> tuple[set[str] | None, str | None]:
    """載入清單。需要時自動 refresh。回傳 (address_set, warning_msg)。"""
    fresh = False
    if CACHE_FILE.exists():
        age = time.time() - CACHE_FILE.stat().st_mtime
        if age < TTL_SECONDS:
            fresh = True

    warning = None
    if not fresh:
        ok, err = _refresh_cache()
        if not ok:
            if CACHE_FILE.exists():
                # 用舊 cache，但發 warning
                warning = f"使用過期 cache（{err}）"
            else:
                return None, err

    try:
        lines = CACHE_FILE.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        return None, f"無法讀 OFAC cache: {e}"

    # 過濾空行跟註解（OFAC 純列表沒註解，但保險）
    addrs = {ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")}
    return addrs, warning


def check(address: str) -> dict:
    addrs, warn = _load_addresses()
    if addrs is None:
        return {
            "source": "ofac",
            "decision": "ERROR",
            "flags": [],
            "error": warn,
            "raw": None,
        }

    hit = address in addrs
    result = {
        "source": "ofac",
        "decision": "BLOCK" if hit else "ALLOW",
        "flags": ["OFAC SDN 制裁名單"] if hit else [],
        "error": warn,  # 即使用了過期 cache 也標出來
        "raw": {"list_size": len(addrs), "hit": hit},
    }
    return result


if __name__ == "__main__":
    import json, sys
    addr = sys.argv[1] if len(sys.argv) > 1 else "TTxsEJ1AdiVeWjyEW7ADEZURaVQArAdCXj"
    print(json.dumps(check(addr), ensure_ascii=False, indent=2))
