# Changelog

## [0.2.0](https://github.com/workpen/workpen/compare/v0.1.0...v0.2.0) (2026-09-12)


### Features

* cheap DenyPolicy clone and dest display helper ([#34](https://github.com/workpen/workpen/issues/34)) ([228a09d](https://github.com/workpen/workpen/commit/228a09d9c9d8603e44858f283a874f7017ab9a4c)), closes [#21](https://github.com/workpen/workpen/issues/21) [#23](https://github.com/workpen/workpen/issues/23)
* child pre_exec jail apply and extra system grants ([#9](https://github.com/workpen/workpen/issues/9)) ([6eb05d7](https://github.com/workpen/workpen/commit/6eb05d74b144f900020de65d7ae533b45b08900d)), closes [#8](https://github.com/workpen/workpen/issues/8)
* DenyPolicy::from_arc for session glob slots ([#41](https://github.com/workpen/workpen/issues/41)) ([fd0dc8a](https://github.com/workpen/workpen/commit/fd0dc8ae3c463404d4e59a116aa4786145bd8a23)), closes [#40](https://github.com/workpen/workpen/issues/40)
* dest-deny check_dest and verify_post_open ([#11](https://github.com/workpen/workpen/issues/11)) ([e0e27e7](https://github.com/workpen/workpen/commit/e0e27e72990558685b0c5497f40e9b447205d450)), closes [#10](https://github.com/workpen/workpen/issues/10)
* leftover GC leftover_dir, saved refs, and run_gc ([#13](https://github.com/workpen/workpen/issues/13)) ([b8dbafe](https://github.com/workpen/workpen/commit/b8dbafefe3867f6feec6b5ac61ee00012ac76b43)), closes [#12](https://github.com/workpen/workpen/issues/12)
* PathGuard policy, check_path_entry, and resolve_extra_root ([#16](https://github.com/workpen/workpen/issues/16)) ([6b4c145](https://github.com/workpen/workpen/commit/6b4c145aeabc8a9938890a84daf5145f9edd357f))
* public remove_explicit and worktree_last_used ([#33](https://github.com/workpen/workpen/issues/33)) ([8fdc649](https://github.com/workpen/workpen/commit/8fdc6498b63b9090f3283b07ba61bde86226df6d)), closes [#20](https://github.com/workpen/workpen/issues/20)


### Bug Fixes

* argv dest-deny uses classify for hardlink tokens ([#30](https://github.com/workpen/workpen/issues/30)) ([a56b3bc](https://github.com/workpen/workpen/commit/a56b3bc395f06b09ca6d5efad02bbf230d57ba48)), closes [#18](https://github.com/workpen/workpen/issues/18)
* **cli:** canonicalize why --root like run ([#73](https://github.com/workpen/workpen/issues/73)) ([ff5753b](https://github.com/workpen/workpen/commit/ff5753b451b44eacd0e958fb4d0f9df728e61c17))
* dest-deny fixtures, check_dest NUL/special, junction test ([#46](https://github.com/workpen/workpen/issues/46)) ([cf8c425](https://github.com/workpen/workpen/commit/cf8c425253312cd72b47de231168c10a8e804ac1)), closes [#42](https://github.com/workpen/workpen/issues/42) [#43](https://github.com/workpen/workpen/issues/43) [#44](https://github.com/workpen/workpen/issues/44)
* dest-deny hardlink when canonicalize fails ([#28](https://github.com/workpen/workpen/issues/28)) ([5851838](https://github.com/workpen/workpen/commit/5851838a5aec6e833e0e3bb077fa9792a6ba687d)), closes [#17](https://github.com/workpen/workpen/issues/17) [#24](https://github.com/workpen/workpen/issues/24)
* **dest-deny:** fail-closed argv, cache walks, and leftover GC ([#69](https://github.com/workpen/workpen/issues/69)) ([1807cdf](https://github.com/workpen/workpen/commit/1807cdf2c9bf24b0e64c1b6e2e0b468f8120f5dd))
* **dest-deny:** fail-closed CLI dest-deny and leftover GC ([#54](https://github.com/workpen/workpen/issues/54)) ([0060e04](https://github.com/workpen/workpen/commit/0060e04cd6fb907dafded94840b7840138867fb6))
* **dest-deny:** name matching glob or hardlink sibling ([#70](https://github.com/workpen/workpen/issues/70)) ([421d7fb](https://github.com/workpen/workpen/commit/421d7fbeb6191d24d211fed5cf468932c2319c91)), closes [#68](https://github.com/workpen/workpen/issues/68)
* **dest-deny:** refuse directory reads and lock device fixture ([#53](https://github.com/workpen/workpen/issues/53)) ([fc0ae97](https://github.com/workpen/workpen/commit/fc0ae97329b4d854172c1b1a9f3a912620499879)), closes [#51](https://github.com/workpen/workpen/issues/51) [#52](https://github.com/workpen/workpen/issues/52)
* do not dest-deny Unix directories as hardlink siblings ([#27](https://github.com/workpen/workpen/issues/27)) ([cc11dac](https://github.com/workpen/workpen/commit/cc11dac8c841945927778476504391a929bc9d56)), closes [#22](https://github.com/workpen/workpen/issues/22)
* extra dest-deny globs can match env templates ([#29](https://github.com/workpen/workpen/issues/29)) ([6363fa7](https://github.com/workpen/workpen/commit/6363fa7854e72ee30fa4bad937f50f703c309968)), closes [#19](https://github.com/workpen/workpen/issues/19)
* **gc:** discover common dir, honor force, scrub GIT_* ([#45](https://github.com/workpen/workpen/issues/45)) ([2fe4906](https://github.com/workpen/workpen/commit/2fe490685f5c06fc984b450d391567b27e150cfe)), closes [#37](https://github.com/workpen/workpen/issues/37) [#38](https://github.com/workpen/workpen/issues/38) [#39](https://github.com/workpen/workpen/issues/39)
* **gc:** honest leftover unique-work and CLI flag parse ([#58](https://github.com/workpen/workpen/issues/58)) ([af69c34](https://github.com/workpen/workpen/commit/af69c34727a09026d75fc7e92d49a7c03d67a406))
* **gc:** keep cache-dir secrets, live-cwd rm, and explain dest-deny ([#59](https://github.com/workpen/workpen/issues/59)) ([bd9609b](https://github.com/workpen/workpen/commit/bd9609bc032f094533565521dd32062b494bb616))
* leftover without .git is NotAGitDir ([#32](https://github.com/workpen/workpen/issues/32)) ([aa0078c](https://github.com/workpen/workpen/commit/aa0078cacadccd370ba4945751a2dd8f45f0f368)), closes [#25](https://github.com/workpen/workpen/issues/25)
* **path-guard:** deny broken out-of-tree symlinks and grant presented extra-roots ([#72](https://github.com/workpen/workpen/issues/72)) ([8d74531](https://github.com/workpen/workpen/commit/8d745319ab453f7c61a5de7fcaa358dc8cd8e375))

## [0.1.0](https://github.com/workpen/workpen/compare/v0.0.1...v0.1.0) (2026-09-10)


### Features

* implement dest-deny predicate ([#2](https://github.com/workpen/workpen/issues/2)) ([40cf40d](https://github.com/workpen/workpen/commit/40cf40dbeedd0b2412deb7767c9567b8d0c7e3de))
* PathGuard, leftover GC, and workpen CLI ([#4](https://github.com/workpen/workpen/issues/4)) ([36c15fa](https://github.com/workpen/workpen/commit/36c15fa6c89e46f5267244704d7dd0a9438232e3))
* pin nono 0.76 and raise MSRV to 1.95 ([#7](https://github.com/workpen/workpen/issues/7)) ([0f1a974](https://github.com/workpen/workpen/commit/0f1a97474bdab36f003bc62a97c6f3a2f6b6c24d))
