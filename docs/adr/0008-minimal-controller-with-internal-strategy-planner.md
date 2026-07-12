---
status: accepted
decision_date: 2026-07-13
---

# Keep the Controller minimal and the strategy planner internal

Flux's core Controller Interface will submit intentions, return coherent snapshots, and stream status revisions. Common `enable`/`disable`/`reload` verbs live in a thin client Adapter, while candidate Backend Plans, semantic capability composition, and typed facility ports remain behind an internal Seam; this preserves caller leverage without committing the first rewrite to a public plugin/solver model.
