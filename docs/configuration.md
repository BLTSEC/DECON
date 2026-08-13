# Configuration

[← README](../README.md)

Create `~/.config/decon/decon.toml` with owner-only permissions:

```bash
decon --init-config
```

A compact configuration example:

```toml
default_profile = "standard"

[rules]
phone = false
credit_card = false

[custom]
values = ["Project Nighthawk"]
values_nocase = ["jsmith", "proddb"]
target_domains = ["corp.example"]
allowlist = ["scanme.nmap.org"]

# Typed engagement identifiers — keep their type in the output
hostnames = ["DC01", "prod-web-01"]
usernames = ["svc_backup"]
netbios = ["ACME"]
shares = ["SYSVOL", "HR-Data"]

[[custom.patterns]]
name = "ticket_ids"
pattern = 'CLIENT-[0-9]{4}'
replacement = "[CUSTOM_REDACTED_{n:04d}]"

[profiles.client-share]
hostname_internal = true
custom_values_extra = ["Internal Codename"]

[llm]
enabled = false
required = false
model = "qwen3.5:9b"
host = "http://localhost:11434"
```

Precedence is predictable:

```text
[rules] -> selected profile -> --enable / --disable
```

Set every built-in rule at once with `all`, then override individually. Within a
layer `all` is applied first, so per-rule keys win:

```toml
[profiles.ctf]
all = false          # lab infrastructure is public — redact nothing built-in

[profiles.network-only]
all = false
ipv4 = true          # ...except addresses
ipv6 = true
```

Prefer this over listing every rule name to disable: a deny-list silently stops
covering rules added in later releases, while `all` states the intent once.

`all` applies to built-in rules only. Values you declare under `[custom]` are
explicit instructions and keep redacting regardless, so `all = false` never
stops protecting your own identifiers.

```bash
decon --profile client-share report.txt
DECON_PROFILE=client-share decon report.txt
```

Invalid tables, rule names, value types, regular expressions, and placeholder
templates fail with a concise configuration error. See
[`config.example.toml`](../config.example.toml) for the complete example.

## Typed engagement identifiers

Regex catches common formats, but every engagement has its own naming
conventions — a host called `prod-web-01` slips past the generic hostname rules,
and a bare `DC01` or `SYSVOL` mentioned in prose has nothing to key on.

Declaring these under `[custom]` closes the gap **without losing type**. Unlike
`values` and `values_nocase`, which collapse everything into
`[CUSTOM_REDACTED_nnnn]`, each typed array keeps its own placeholder namespace:

| Key | Placeholder |
|---|---|
| `hostnames` | `[HOST_SHORT_REDACTED_nnnn]` |
| `usernames` | `DOMAIN_USER_nn` |
| `netbios` | `[DOMAIN_REDACTED_nnnn]` |
| `shares` | `[SHARE_REDACTED_nnnn]` |

All four match case-insensitively. A bare hostname reuses the placeholder
already assigned to its FQDN, so `DC01` and `DC01.corp.example.com` stay one
machine rather than becoming two.

> [!TIP]
> These match anywhere the bare token appears, so avoid declaring a value that
> is also an ordinary word in text you want to keep — listing `ACME` as
> `netbios` will also redact it inside a project codename like
> `Operation ACME`. Drop the entry, or narrow it with a `[[custom.patterns]]`
> rule instead.
