# blackbar

[![CI](https://github.com/azgeekthe3rd/blackbar/actions/workflows/ci.yml/badge.svg)](https://github.com/azgeekthe3rd/blackbar/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**A PII scrubber that checks its work.** Zero dependencies, one command.

```console
$ echo "card 4111 1111 1111 1111, ref 4111 1111 1111 1112" | blackbar scrub -
card [CREDIT_CARD], ref 4111 1111 1111 1112
```

Those two numbers differ by one digit. The first passes the Luhn checksum, the
second doesn't — so the second is an order reference, not a card, and it stays.
Every regex-only scrubber redacts both.

---

## The problem

Redacting PII with regular expressions alone gives you a tool nobody keeps
using. `\d{16}` matches every order ID. `\d{3}-\d{2}-\d{4}` matches every date
range. `\d+\.\d+\.\d+\.\d+` eats `127.0.0.1` and the version string in your
build log. After the third time it mangles a file, people stop running it —
and a scrubber nobody runs protects nobody.

blackbar uses regexes to *find candidates* and then makes them prove it:

| Layer | Job | Example |
|---|---|---|
| **Regex** | Cast a wide net over plausible spans | `\d(?:[ -]?\d){12,18}` |
| **Validator** | Reject anything that fails a real check | Luhn, issuer prefix, length |
| **Resolver** | Settle detectors that claim the same span | IBAN beats the phone inside it |
| **Strategy** | Decide what replaces the span | `[EMAIL]`, `o**@acme.io`, `[EMAIL:3f9a1c4e]` |

The validators are the interesting part, and they're what the test suite spends
most of its time on.

## Install

```bash
pip install blackbar          # or: pipx install blackbar
```

Requires Python 3.10+. Installs nothing else.

## Use it from the shell

```bash
blackbar scrub app.log                     # clean a file to stdout
kubectl logs api-7f9 | blackbar scrub -    # clean a stream
blackbar scrub app.log -o clean.log        # write to a file

blackbar scan diary.txt                    # what's in there? (values hidden)
blackbar scan diary.txt --json             # machine-readable report

blackbar scrub app.log --only EMAIL,IPV4   # narrow the net
blackbar scrub app.log --exclude PHONE     # or widen it
blackbar scrub app.log --allow noreply@acme.io
```

`scan` exits **1** when it finds something and **0** when it doesn't, so it
drops straight into CI or a pre-commit hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/azgeekthe3rd/blackbar
    rev: v0.1.0
    hooks:
      - id: blackbar
```

## Use it from Python

```python
from blackbar import Scrubber, Entity, HashStrategy, scrub

scrub("email ops@acme.io from 8.8.8.8")
# 'email [EMAIL] from [IPV4]'

# Pseudonymise instead of erasing: same input -> same token, everywhere.
scrubber = Scrubber(strategy=HashStrategy(key="a-secret-you-keep"))
scrubber.scrub("ops@acme.io opened; ops@acme.io closed").text
# 'the same [EMAIL:1c2f...] token twice'

# Find without rewriting; offsets map back to the original string.
for match in Scrubber().scan(text):
    print(match.entity, match.span, match.note)
```

## Redaction strategies

| Strategy | Output | Use when |
|---|---|---|
| `label` *(default)* | `[EMAIL]` | You want the data gone. |
| `hash` | `[EMAIL:3f9a1c4e]` | You still need to count or join on it. |
| `mask` | `**** **** **** 1111` | A human needs to recognise the record. |
| `remove` | *(nothing)* | The span shouldn't exist at all. |

**On `hash`:** determinism is the feature — a scrubbed corpus stays *joinable*,
so you can still follow one user across services or group errors by customer.
It's also the risk. A plain digest of a phone number is trivially reversed;
there simply aren't that many phone numbers. blackbar uses a keyed HMAC, so
the key is what stands between the tokens and a brute-force lookup table:

```bash
export BLACKBAR_KEY="$(openssl rand -hex 32)"   # keep it secret, keep it stable
blackbar scrub app.log --strategy hash
```

Without a key, a random one is generated per run: tokens stay consistent within
a file and are unlinkable between runs.

## What it detects

| Entity | Validation beyond the regex |
|---|---|
| `CREDIT_CARD` | Luhn checksum + issuer prefix + per-brand length |
| `IBAN` | ISO 7064 mod-97-10 + per-country length (78 countries) |
| `CRYPTO_WALLET` | Base58Check double-SHA256 for Bitcoin; shape only for EVM |
| `US_SSN` | SSA structural rules; separators required |
| `UK_NINO` | Prefix/suffix allowlists, forbidden prefixes |
| `IPV4` / `IPV6` | Parsed by `ipaddress`; private and loopback ranges kept |
| `EMAIL` | Reserved domains (RFC 2606) excluded |
| `PHONE` | E.164 digit bounds; requires formatting to fire |
| `MAC` | Null and broadcast addresses excluded |
| `API_KEY` | AWS, GitHub, Slack, Stripe, Google, OpenAI, Anthropic, SendGrid |
| `JWT` | Three-segment structure with `eyJ` header |
| `PRIVATE_KEY` | Whole PEM block, across lines |
| `URL_CREDENTIALS` | Only the `user:pass` span, so the host stays readable |

## Design notes

**Private IPs are not redacted.** `10.0.0.7` and `127.0.0.1` identify nobody,
and stripping them destroys the reason someone opened the log. Pass
`--only IPV4` with your own allowlist if your threat model differs.

**Unpunctuated nine-digit runs are not SSNs.** `574382914` is equally a zip+4,
a product code or a timestamp fragment. Requiring separators trades a little
recall for a lot of precision.

**Phone numbers need a formatting signal** — a `+`, parentheses, or internal
separators. Ten bare digits are more often an order number.

**Priority decides overlaps, then length.** In
`postgres://app:hunter2@db.internal`, the email regex sees a longer span than
the credential regex does. Ranking by detector priority first is what stops the
longer, wronger match from winning.

**Ethereum checksums aren't verified.** EIP-55 needs Keccak-256, which is *not*
`hashlib.sha3_256` — different padding, different digest. Rather than ship a
validator that silently rejects every valid address, EVM addresses are matched
on shape and annotated as unverified.

## Limitations

Read these before pointing it at anything that matters.

- **No names, addresses or dates of birth.** Those need NER, which needs a
  model, which needs a dependency and a GPU-shaped hole in your CI. Out of
  scope by choice — pair blackbar with [Presidio](https://github.com/microsoft/presidio)
  if you need them.
- **English-centric formats.** Phone and government-ID patterns cover US and UK
  conventions. Other locales will under-match.
- **`--stream` disables multi-line detection.** Constant memory costs you PEM
  private key blocks, which span lines.
- **`mask` is not anonymisation.** The last four digits plus a timestamp are
  often enough to re-identify someone. It's for human recognition, not privacy.
- **This is not a compliance tool.** It reduces exposure; it does not make you
  GDPR-compliant, and no automated scrubber can.

## Development

```bash
git clone https://github.com/azgeekthe3rd/blackbar
cd blackbar
pip install -e ".[dev]"

pytest --cov=blackbar --cov-report=term-missing
ruff check src tests
mypy
```

Adding a detector is one class:

```python
from blackbar.detectors import RegexDetector, register
from blackbar.types import Entity

@register
class EmployeeIdDetector(RegexDetector):
    entity = Entity.CUSTOM          # add to the Entity enum first
    priority = 60
    pattern = re.compile(r"\bEMP-\d{6}\b")

    def validate(self, canonical: str, raw: str) -> bool:
        return int(canonical[-6:]) < 500_000
```

## License

MIT
