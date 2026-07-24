---
title: Operation Emberglass Attack Path
synthetic: true
classification: demo
tags: [engagement, attack-path, dcsync, emberglass]
---

# Operation Emberglass Attack Path

> This attack path is a fictional training sequence.

## Path summary

1. Authenticate as `EMBERGLASS\analyst.demo`.
2. Request the ticket for `svc_archive`.
3. Validate controlled write access over the service account.
4. Confirm `Archive Operators` has replication permissions.
5. Request one synthetic account through DCSync.
6. Restore the changed attribute and remove collected files.

## Rights check

The replication ACE applied to
`S-1-5-21-4242424242-3131313131-2020202020-2105`. The operator confirmed both
required replication rights before proceeding.

## Controlled DCSync

```bash
impacket-secretsdump \
  -just-dc-user audit.reader \
  -dc-ip 10.77.24.10 \
  'emberglass.internal/svc_archive:Archive-Meteor-82!@dc01.emberglass.internal'
```

Only `audit.reader` was requested. A full `-just-dc` dump was explicitly out of
scope.

## Cleanup

The temporary SPN was restored, the TUN route was removed, and the evidence
directory was sealed read-only. See [[06 - Final Recap]] for the concise
assessment narrative.

