---
title: Operation Emberglass Web Testing
synthetic: true
classification: demo
tags: [engagement, web, jwt, upload, emberglass]
---

# Operation Emberglass Web Testing

> The application, token, and credentials below are fictional.

## Content discovery

The portal at `10.77.24.20` exposed `/api/session`, `/api/profile`, and
`/api/upload`. The administrative route returned 403 to the initial user.

```bash
ffuf \
  -u 'https://portal.emberglass.internal/FUZZ' \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,204,301,302,401,403 \
  -ac
```

## Session handling

The synthetic response contained:

```text
token=demo_token_6f2c9a84_not_valid
owner=analyst.demo@emberglass.internal
```

Changing the role claim without a valid signature was rejected. Expired tokens
were also rejected, so no JWT verification bypass was found.

## Upload behavior

A text marker uploaded successfully to
`https://portal.emberglass.internal/uploads/proof.txt`. Executable extensions
were rejected and retrieved content was served as plain text. This was recorded
as an informational hardening observation, not code execution.

