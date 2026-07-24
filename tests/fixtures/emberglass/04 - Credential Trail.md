---
title: Operation Emberglass Credential Trail
synthetic: true
classification: demo
tags: [engagement, credentials, evidence, emberglass]
---

# Operation Emberglass Credential Trail

> Every credential, hash, path, and identity in this note is synthetic.

## Controlled test material

The service-account exercise used:

```text
EMBERGLASS\svc_archive:500:aad3b435b51404eeaad3b435b51404ee:11223344556677889900aabbccddeeff:::
svc_archive::EMBERGLASS:1122334455667788:aabbccddeeff0011:0101000000000000
password=Archive-Meteor-82!
```

The value was observed in a lab-only configuration backup at
`\\files01.emberglass.internal\Engineering\archive-service.ini` and in
`C:\Users\svc_archive\Documents\migration.txt`.

## Handling

The operator stored temporary evidence under
`/home/ember-operator/engagements/emberglass/evidence` and recorded SHA-256
digests before analysis. Only the single synthetic service account was tested.

## Relationship

The recovered identity explained the `Archive Operators` membership shown in
[[02 - AD Enumeration]]. It was not used for persistence or unrelated access.

