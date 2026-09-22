# addr-screen

Risk-screen a Tron (TRC-20) address before you accept USDT from it — sanctions, blacklists, and on-chain fraud — cross-checked across three independent sources, with no vendor lock-in and no API key required for the default run.

Built for freelancers, donation recipients, and anyone taking TRC-20 USDT who wants to know a wallet is clean *before* they accept payment.

## Why not just use one checker

Most address checkers send your query to a single commercial API. That means one vendor sees every address you ever screen, and you're trusting one opinion. `addr-screen` cross-checks three independent sources, runs the sanctions list fully offline, and skips any source you haven't opted into. No single service sees all your activity, and a block from any one source blocks the result.

## What it checks

| Source | Checks for | Default | Privacy |
|---|---|---|---|
| **OFAC SDN** | U.S. Treasury sanctions list | on | fully offline (local match) |
| **GoPlus Security** | 16 risk vectors (laundering, phishing, mixers, darkweb…) | on | public API, no key, not tied to you |
| **TRONSCAN Security** | Tether blacklist (freeze) + fraud-token creator | opt-in | free key; provider sees your query |

The default two sources (OFAC + GoPlus) need no API key and cover the common case.

## Install

```bash
git clone https://github.com/alpha-0619/addr-screen
cd addr-screen
python check.py --address <TRON_ADDRESS>
```

Python 3.10+. Standard library only — no third-party packages.

## Usage

```bash
python check.py --address TXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
python check.py --address TXXXX... --json     # machine-readable
```

### Exit codes

| code | meaning | action |
|---|---|---|
| 0 | ALLOW | all sources clear |
| 1 | WARN | a concern, or a source failed — verify manually |
| 2 | BLOCK | serious risk — refuse the payment |
| 3 | ERROR | all sources down — retry later |

## Enabling the third source (TRONSCAN)

TRONSCAN requires a free API key since 2025-08-31:

1. Register at tronscan.org → My Account → API Keys
2. `export TRONSCAN_API_KEY=<your_key>` (or set it as a user environment variable)

If the key isn't set, this source is skipped automatically and the others still run.

## How the decision aggregates

Any source returns BLOCK → final **BLOCK**. All sources ALLOW → final **ALLOW**. Any WARN, or a source fails while others are clear → final **WARN** (missing information is never treated as safe).

## A note on limits

"Not found" is not "100% safe" — a brand-new scam address that none of the sources have reported yet will pass all three. For large payments, ask the sender for a 1 USDT test transfer first, confirm it screens clean, then accept the rest.

## License

MIT — see [LICENSE](LICENSE).
