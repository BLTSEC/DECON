---
title: Operation Emberglass Recon Log
synthetic: true
classification: demo
tags: [engagement, recon, nmap, emberglass]
---

# Operation Emberglass Recon Log

> All infrastructure and identifiers in this note are synthetic.

## 2026-06-15 09:10 — Discovery

The supplied range was `10.77.24.0/24`. Three hosts responded:

| Address | Host | Role |
|---|---|---|
| `10.77.24.10` | `dc01.emberglass.internal` | Domain controller |
| `10.77.24.20` | `portal.emberglass.internal` | Web application |
| `10.77.24.30` | `files01.emberglass.internal` | File server |

The file server advertised MAC address `02:42:ac:11:00:30`.

```bash
nmap -Pn -sC -sV -p 53,80,88,389,443,445 \
  -oA evidence/emberglass-services \
  10.77.24.10 10.77.24.20 10.77.24.30
```

## 2026-06-15 10:05 — Observations

SMB signing was required on `10.77.24.10` but optional on `10.77.24.30`.
The portal redirected to `https://portal.emberglass.internal/login`.
These results informed [[02 - AD Enumeration]] and [[03 - Web Testing]].

