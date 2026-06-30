"""
TRONSCAN Security Service API（需要免費 API key,2025-08-31 起強制）。

Endpoint: GET https://apilist.tronscanapi.com/api/security/account/data?address=<addr>
Header:   TRON-PRO-API-KEY: <key>

回傳關鍵欄位：
  is_black_list           — Tether/USDC 等穩定幣發行商的黑名單（被 freeze 了）
  has_fraud_transaction   — 該地址有詐騙交易紀錄
  fraud_token_creator     — 該地址是詐騙幣創建者
  send_ad_by_memo         — 該地址常用 memo 發廣告 spam

升級啟用：
  1. https://tronscan.org → 註冊 → My Account → API Keys → 申請免費 key
  2. 設環境變數: $env:TRONSCAN_API_KEY = "<your_key>"

沒 key 時這個 source 回 decision=SKIP,不影響主流程。
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request

ENDPOINT = "https://apilist.tronscanapi.com/api/security/account/data"
TIMEOUT = 15
ENV_KEY = "TRONSCAN_API_KEY"


def _fetch(address: str, api_key: str) -> tuple[dict | None, str | None]:
    url = f"{ENDPOINT}?{urllib.parse.urlencode({'address': address})}"
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "addr-screen/0.1",
                "TRON-PRO-API-KEY": api_key,
            },
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data, None
    except urllib.error.HTTPError as e:
        return None, f"TRONSCAN HTTP {e.code}"
    except urllib.error.URLError as e:
        return None, f"TRONSCAN 網路錯誤: {e.reason}"
    except (TimeoutError, json.JSONDecodeError) as e:
        return None, f"TRONSCAN 回應錯誤: {e}"


def check(address: str) -> dict:
    api_key = os.environ.get(ENV_KEY, "").strip()
    if not api_key:
        return {
            "source": "tronscan",
            "decision": "SKIP",
            "flags": [],
            "error": f"未設 {ENV_KEY}（opt-in 升級源,可略過）",
            "raw": None,
        }

    data, err = _fetch(address, api_key)
    if data is None:
        return {
            "source": "tronscan",
            "decision": "ERROR",
            "flags": [],
            "error": err,
            "raw": None,
        }

    # 收集 BLOCK 等級的標籤
    flags = []
    block = False
    warn = False

    if data.get("is_black_list"):
        flags.append("穩定幣黑名單（已被 freeze）")
        block = True
    if data.get("has_fraud_transaction"):
        flags.append("有詐騙交易紀錄")
        block = True
    if data.get("fraud_token_creator"):
        flags.append("詐騙幣創建者")
        block = True
    if data.get("send_ad_by_memo"):
        flags.append("memo 廣告 spam 地址")
        warn = True

    if block:
        decision = "BLOCK"
    elif warn:
        decision = "WARN"
    else:
        decision = "ALLOW"

    return {
        "source": "tronscan",
        "decision": decision,
        "flags": flags,
        "error": None,
        "raw": data,
    }


if __name__ == "__main__":
    import sys
    addr = sys.argv[1] if len(sys.argv) > 1 else "TTxsEJ1AdiVeWjyEW7ADEZURaVQArAdCXj"
    print(json.dumps(check(addr), ensure_ascii=False, indent=2))
