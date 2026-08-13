# Mappings, sessions, and audit history

[← README](../README.md)

Export a map when placeholders must remain stable across separate commands:

```bash
decon --export-map engagement.decon-map.json scan-1.txt > clean-1.txt
decon --import-map engagement.decon-map.json scan-2.txt > clean-2.txt

# Update the same map with newly discovered values
decon \
  --import-map engagement.decon-map.json \
  --export-map engagement.decon-map.json \
  scan-3.txt > clean-3.txt
```

Restore placeholders after local analysis:

```bash
echo "Investigate [IPV4_REDACTED_0001]:443" \
  | decon --unredact engagement.decon-map.json
```

> [!CAUTION]
> Maps, saved sessions, and the audit log all contain the original sensitive
> values. Maps and sessions are replaced atomically; every persisted file is
> forced to mode `0600`, and DECON's state directory is owner-only. This
> repository ignores `map.json` and `*.decon-map.json`. Never commit, upload, or
> share any of them.

Case-insensitive and canonicalized values—such as hostname case variants,
equivalent IPv6 spellings, and alternate MAC formats—share a placeholder. A
map retains the first-seen original spelling for reverse redaction.

## Sessions

A session is a map DECON names and stores for you, so a paste-into-a-chat round
trip is two short commands instead of a map path you have to keep track of:

```bash
decon --session -c scan.txt     # redact -> clipboard, mapping saved as "last"
# paste into the assistant, copy its reply
decon --restore -c              # placeholders -> real values, back to clipboard
```

Name sessions to keep engagements apart. Add a TTL for automatic expiration,
or consume the map after a successful restore for a one-shot round trip:

```bash
decon --session acme --session-ttl 24h -c scan.txt
decon --restore acme --consume -c
decon --list-sessions
decon --forget acme          # delete one reversible map
decon --forget-all           # delete them all
```

Sessions live in `~/.local/state/decon/sessions/` (or `$XDG_STATE_HOME`). Each
one is a reversible plaintext map. TTLs accept positive whole seconds, minutes,
hours, days, or weeks (`30m`, `24h`, `7d`). Expired sessions are removed when
listed or restored. `--consume` deletes only after output succeeds, allowing a
failed clipboard or file write to be retried.

If a restored placeholder has no mapping — a model reformatted it, or it came
from a different session — DECON says so rather than leaving it to look like
real output:

```text
Warning: 2 placeholder(s) had no mapping and were left as-is:
  [HOST_REDACTED_1], [IPV4_REDACTED_0099]
```

> [!TIP]
> `--session` and `--restore` take an *optional* name, so a bare
> `decon --session scan.txt` would read `scan.txt` as the session name. DECON
> detects that and tells you to write `decon --session -c scan.txt` or
> `decon --session=NAME scan.txt` instead.

## Audit log

Every substitution is appended to `~/.local/state/decon/audit.jsonl` as one JSON
record per run:

```json
{"ts":"2026-07-24T12:00:00+00:00","mode":"redact","status":"emitted","sources":["scan.txt"],
 "substitutions":[{"category":"hostname","original":"dc01.corp.local",
                   "placeholder":"[HOST_REDACTED_0001]"}]}
```

Runs that redact nothing write nothing. If the log cannot be written, DECON
warns and still produces your sanitized output — auditing never costs you the
redaction. Turn it off per run with `--no-audit`, or permanently:

```toml
[audit]
enabled = false
# path = "~/engagement-audit.jsonl"
```
