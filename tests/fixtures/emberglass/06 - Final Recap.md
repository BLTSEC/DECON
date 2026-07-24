---
title: Operation Emberglass Final Recap
synthetic: true
classification: demo
tags: [engagement, recap, findings, emberglass]
---

# Operation Emberglass Final Recap

> This recap describes a wholly fictional assessment.

## Executive path

A standard analyst account exposed a service-account ticket whose deliberately
weak lab password could be recovered offline. Delegated control over that
service account led to membership in a group with directory replication
permissions. The team demonstrated impact by requesting one synthetic account
and then restored the modified state.

## What mattered

- The web portal did not produce an authentication bypass.
- Optional SMB signing on the file server increased relay exposure, but relay
  was not needed for the validated path.
- The decisive weakness was the combination of service-account password
  quality and excessive directory delegation.
- Limiting DCSync to one account proved impact without collecting the directory.

## Recommendations

1. Rotate service-account credentials and prefer managed identities.
2. Remove replication rights from operational groups.
3. Alert on replication requests from non-domain-controller systems.
4. Require SMB signing consistently.
5. Review delegated object control quarterly.

## Demo retrieval targets

Semantic searches about reaching the objective should land here or in
[[05 - Attack Path]]. Command searches should lead to [[NetExec SMB]],
[[Ligolo Routing]], or [[DCSync from Linux]].

