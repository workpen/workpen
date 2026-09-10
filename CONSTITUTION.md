# Constitution

Immutable until a human-labeled PR amends this file.

1. Independent org `workpen/workpen`. Not `blineai/`. Not `patchloom/`.
2. License is MIT OR Apache-2.0.
3. Crate and CLI name is `workpen`. Do not name the CLI `wt`.
4. Pin nono for kernel wrap. Do not reimplement Landlock or Seatbelt.
5. Do not dest-parent-copy Bline or patchloom sources. Port via corpus tests first.
6. Do not depend on landstrip (LGPL) or ai-jail (GPL). Do not fork `.sb` files.
7. Do not fold this crate into canact or craftbag.
8. Default crate is dest-deny plus PathGuard. Feature-gate `gc` and `nono`.
9. Keep dest-deny and PathGuard as separate types.
10. Stealth-public until a human says launch: empty About, no topics, README is "Not ready."
