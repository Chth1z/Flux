---
status: accepted
decision_date: 2026-07-13
---

# Respect Android VPN policy by default

Flux will audit the live Android routing-policy lattice and preserve secure VPN, lockdown, per-UID, explicit-network, and default-network behavior unless the user explicitly selects a documented override. The current fixed priority `2025` precedes netd's normal policy ranges and therefore cannot be retained as an unquestioned default.
