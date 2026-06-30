"""
GoPlus Security 公開 API（免 key）。

Endpoint: GET https://api.gopluslabs.io/api/v1/address_security/<addr>?chain_id=tron

回傳結構大致：
{
  "code": 1,
  "message": "OK",
  "result": {
    "money_laundering": "0",
    "sanctioned": "0",
    "phishing_activities": "0",
    "blacklist_doubt": "0",
    "stealing_attack": "0",
    "blackmail_activities": "0",
    "darkweb_transactions": "0",
    "cybercrime": "0",
    "financial_crime": "0",
    "honeypot_related_address": "0",
    "fake_kyc": "0",
    "malicious_mining_activities": "0",
    "mixer": "0",
    "fake_token": "0",
    "fake_standard_interface": "0",
    "gas_abuse": "0",
    "number_of_malicious_contracts_created": "0",
    "data_source": "..."
  }
}

每個 risk field 是字串 "0"（無）或 "1"（標記）。
"""

import json
import urllib.error
import urllib.parse
import urllib.request

ENDPOINT_TMPL = "https://api.gopluslabs.io/api/v1/address_security/{addr}"
TIMEOUT = 15

# BLOCK 等級的 risk fields（任一命中 = BLOCK）
BLOCK_FIELDS = {
    "money_laundering": "洗錢",
    "sanctioned": "受制裁",
    "financial_crime": "金融犯罪",
    "cybercrime": "網路犯罪",
    "blackmail_activities": "勒索",
    "stealing_attack": "盜竊攻擊",
    "blacklist_doubt": "可疑黑名單",
    "fake_kyc": "假 KYC",
    "darkweb_transactions": "暗網交易",
    "phishing_activities": "釣魚",
    "fake_token": "假幣",
    "honeypot_related_address": "蜜罐相關",
    "mixer": "混幣器",
    "malicious_mining_activities": "惡意挖礦",
    "fake_standard_interface": "偽造標準介面",
}

# WARN 等級的 risk fields（命中 = WARN，不到 BLOCK）
WARN_FIELDS = {
    "gas_abuse": "gas 濫用",
}


def _fetch(address: str) -> tuple[dict | None, str | None]:
    url = (
        ENDPOINT_TMPL.format(addr=urllib.parse.quote(address))
        + "?"
        + urllib.parse.urlencode({"chain_id": "tron"})
    )
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "addr-screen/0.1"}
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data, None
    except urllib.error.HTTPError as e:
        return None, f"GoPlus HTTP {e.code}"
    except urllib.error.URLError as e:
        return None, f"GoPlus 網路錯誤: {e.reason}"
    except (TimeoutError, json.JSONDecodeError) as e:
        return None, f"GoPlus 回應錯誤: {e}"


def check(address: str) -> dict:
    data, err = _fetch(address)
    if data is None:
        return {
            "source": "goplus",
            "decision": "ERROR",
            "flags": [],
            "error": err,
            "raw": None,
        }

    if data.get("code") != 1:
        return {
            "source": "goplus",
            "decision": "ERROR",
            "flags": [],
            "error": f"GoPlus API 失敗: {data.get('message')}",
            "raw": data,
        }

    result = data.get("result") or {}

    # GoPlus 對 Tron 地址有時把 risk 包在地址 key 下，有時直接平鋪
    # 偵測：如果 result 唯一一個 key 看起來像地址（T 開頭、長度 33-34），rebuild
    if len(result) == 1:
        only_key = next(iter(result))
        if isinstance(only_key, str) and only_key.startswith("T") and 30 < len(only_key) < 40:
            result = result[only_key]

    flags = []
    block = False
    warn = False

    for field, label in BLOCK_FIELDS.items():
        if str(result.get(field, "0")) == "1":
            flags.append(label)
            block = True

    for field, label in WARN_FIELDS.items():
        if str(result.get(field, "0")) == "1":
            flags.append(label)
            warn = True

    n_mal = result.get("number_of_malicious_contracts_created")
    if n_mal and str(n_mal) != "0":
        flags.append(f"建立過 {n_mal} 個惡意合約")
        block = True

    if block:
        decision = "BLOCK"
    elif warn:
        decision = "WARN"
    else:
        decision = "ALLOW"

    return {
        "source": "goplus",
        "decision": decision,
        "flags": flags,
        "error": None,
        "raw": result,
    }


if __name__ == "__main__":
    import sys
    addr = sys.argv[1] if len(sys.argv) > 1 else "TTxsEJ1AdiVeWjyEW7ADEZURaVQArAdCXj"
    print(json.dumps(check(addr), ensure_ascii=False, indent=2))
