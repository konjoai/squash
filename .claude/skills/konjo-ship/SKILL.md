---
name: konjo-ship
description: Konjo sprint completion checklist for squash.
user-invocable: true
---
# Konjo Ship — squash

## Sprint Completion Checklist
```
[ ] All tests pass — `python -m pytest` green
[ ] `ruff check` and `ruff format --check` clean
[ ] Attestation reproducibility verified (byte-identical for same inputs)
[ ] CHANGELOG.md updated
[ ] SQUASH_MASTER_PLAN.md updated
[ ] README.md reflects current state
[ ] EU AI Act deadline sprint deliverables checked
[ ] git add && git commit -m "type(scope): description" && git push
```

## Session Handoff Template
```
SHIPPED      [what was completed]
TESTS        [passing / failing / count]
PUSHED       [commit hash]
NEXT SESSION [exact next task]
DISCOVERIES  [regulatory updates, tools found]
HEALTH       [Green / Yellow / Red]
```
