# Changelog

## [0.4.0](https://github.com/workpen/workpen/compare/v0.3.0...v0.4.0) (2026-09-14)


### Features

* **cli:** bound workpen run with --timeout ([#121](https://github.com/workpen/workpen/issues/121)) ([1a86223](https://github.com/workpen/workpen/commit/1a86223a22aa7e07846b38c0a9ea3c036360c7da))
* **deny:** dest-deny PowerShell EncodedCommand bodies ([#111](https://github.com/workpen/workpen/issues/111)) ([7cde051](https://github.com/workpen/workpen/commit/7cde0513ec8969d780e194a23e32a99a35949b39)), closes [#109](https://github.com/workpen/workpen/issues/109)
* **wrap:** add run_child_timeout ([#115](https://github.com/workpen/workpen/issues/115)) ([ddb60d3](https://github.com/workpen/workpen/commit/ddb60d394339b91d75361045ad71b43e289e7051)), closes [#110](https://github.com/workpen/workpen/issues/110)
* **wrap:** deny Windows run_child sockets via helper and AppContainer ([#117](https://github.com/workpen/workpen/issues/117)) ([813f25c](https://github.com/workpen/workpen/commit/813f25cb1686ab671ff00af30efbae4429f7330f))
* **wrap:** inherit or grant Windows run_child stdio ([#116](https://github.com/workpen/workpen/issues/116)) ([d76a756](https://github.com/workpen/workpen/commit/d76a756e813d1f7a8c9fd8ee14b5088cd7c9ba5d))
* **wrap:** merge agent.lock into process_jail dest-deny ([#114](https://github.com/workpen/workpen/issues/114)) ([4b90657](https://github.com/workpen/workpen/commit/4b90657d9dd05ab3614054da5f8bd13fa38affd6)), closes [#108](https://github.com/workpen/workpen/issues/108)


### Bug Fixes

* **deny:** peel cmd/pwsh flags and keep Windows dest-deny ACEs ([#118](https://github.com/workpen/workpen/issues/118)) ([2a9b7f9](https://github.com/workpen/workpen/commit/2a9b7f993947e076545cdee6ca9d36849b0d69e8))
* **deny:** peel pwsh -en, -File, --switch, -cwa, and EncodedArguments ([#119](https://github.com/workpen/workpen/issues/119)) ([26822b2](https://github.com/workpen/workpen/commit/26822b205e3ce23abb11fd999f86edb5bbdefa1c))
* **gc:** do not let dry-run refresh last-used ([#120](https://github.com/workpen/workpen/issues/120)) ([c59241f](https://github.com/workpen/workpen/commit/c59241f5d428a56957b973c6b41200e0104e5f8d))

## [0.3.0](https://github.com/workpen/workpen/compare/v0.2.0...v0.3.0) (2026-09-14)


### Features

* **deny:** dest-deny cmd/powershell bodies after wrappers ([#106](https://github.com/workpen/workpen/issues/106)) ([2ef2e4f](https://github.com/workpen/workpen/commit/2ef2e4f3e2640588d2e9504321ca9c5ed839f826))
* **guard:** refuse HOME extra-root and dest-deny nested env ([#105](https://github.com/workpen/workpen/issues/105)) ([215daa7](https://github.com/workpen/workpen/commit/215daa711a6908886e1a96b186cc9c4993e1fda6))
* optional agent.lock extra dest-deny names ([#101](https://github.com/workpen/workpen/issues/101)) ([e61dd68](https://github.com/workpen/workpen/commit/e61dd6832abe8a7b334dc8761a9b4b46e28db531)), closes [#96](https://github.com/workpen/workpen/issues/96)
* **wrap:** dest-deny .env created after jail start ([#104](https://github.com/workpen/workpen/issues/104)) ([8bc48a5](https://github.com/workpen/workpen/commit/8bc48a5562817c76a2b71da5889d6c5cf908314c))
* **wrap:** fail-closed run_child, refuse HOME, prove net ([#98](https://github.com/workpen/workpen/issues/98)) ([9856a97](https://github.com/workpen/workpen/commit/9856a9750ac92b4d38b3e9fc4f18c0a05c96bed6))
* **wrap:** KernelPolicy dest-deny list for in-tree secrets ([#99](https://github.com/workpen/workpen/issues/99)) ([258685b](https://github.com/workpen/workpen/commit/258685b4e5f7b0f38d05864ef93a75e0cacff111)), closes [#91](https://github.com/workpen/workpen/issues/91)
* **wrap:** Linux remount dest-deny of workspace secrets ([#102](https://github.com/workpen/workpen/issues/102)) ([2b140d0](https://github.com/workpen/workpen/commit/2b140d08c4cb6bdb54b441c7f9b2f535bf062d3b))
* **wrap:** macOS Seatbelt dest-deny of workspace secrets ([#100](https://github.com/workpen/workpen/issues/100)) ([c4ebb1c](https://github.com/workpen/workpen/commit/c4ebb1ca57f48ae045cd9b93707ae6efbb7acc31)), closes [#93](https://github.com/workpen/workpen/issues/93)
* **wrap:** Windows read dest-deny of workspace secrets ([#103](https://github.com/workpen/workpen/issues/103)) ([b13bfc4](https://github.com/workpen/workpen/commit/b13bfc453438c46cf738e3ff2b95f96d7ec77bee))


### Bug Fixes

* **cli:** resolve extra-root from cwd and dest-deny env leftovers ([#85](https://github.com/workpen/workpen/issues/85)) ([8f3007c](https://github.com/workpen/workpen/commit/8f3007ca7699dc6408aa2710c1bd6bc6f03573ca))
* **wrap:** noprofile and dest-deny env after timeout and inside -c ([#87](https://github.com/workpen/workpen/issues/87)) ([36b29cf](https://github.com/workpen/workpen/commit/36b29cfd3b3d7b52894a467a34c1d3686a6fd389))

## [0.2.0](https://github.com/workpen/workpen/compare/v0.1.0...v0.2.0) (2026-09-13)


### Features

* cheap DenyPolicy clone and dest display helper ([#34](https://github.com/workpen/workpen/issues/34)) ([228a09d](https://github.com/workpen/workpen/commit/228a09d9c9d8603e44858f283a874f7017ab9a4c)), closes [#21](https://github.com/workpen/workpen/issues/21) [#23](https://github.com/workpen/workpen/issues/23)
* child pre_exec jail apply and extra system grants ([#9](https://github.com/workpen/workpen/issues/9)) ([6eb05d7](https://github.com/workpen/workpen/commit/6eb05d74b144f900020de65d7ae533b45b08900d)), closes [#8](https://github.com/workpen/workpen/issues/8)
* DenyPolicy::from_arc for session glob slots ([#41](https://github.com/workpen/workpen/issues/41)) ([fd0dc8a](https://github.com/workpen/workpen/commit/fd0dc8ae3c463404d4e59a116aa4786145bd8a23)), closes [#40](https://github.com/workpen/workpen/issues/40)
* dest-deny check_dest and verify_post_open ([#11](https://github.com/workpen/workpen/issues/11)) ([e0e27e7](https://github.com/workpen/workpen/commit/e0e27e72990558685b0c5497f40e9b447205d450)), closes [#10](https://github.com/workpen/workpen/issues/10)
* leftover GC leftover_dir, saved refs, and run_gc ([#13](https://github.com/workpen/workpen/issues/13)) ([b8dbafe](https://github.com/workpen/workpen/commit/b8dbafefe3867f6feec6b5ac61ee00012ac76b43)), closes [#12](https://github.com/workpen/workpen/issues/12)
* PathGuard policy, check_path_entry, and resolve_extra_root ([#16](https://github.com/workpen/workpen/issues/16)) ([6b4c145](https://github.com/workpen/workpen/commit/6b4c145aeabc8a9938890a84daf5145f9edd357f))
* public remove_explicit and worktree_last_used ([#33](https://github.com/workpen/workpen/issues/33)) ([8fdc649](https://github.com/workpen/workpen/commit/8fdc6498b63b9090f3283b07ba61bde86226df6d)), closes [#20](https://github.com/workpen/workpen/issues/20)
* **wrap:** harden run_child bash flags, env scrub, and fail-closed tests ([#80](https://github.com/workpen/workpen/issues/80)) ([696898d](https://github.com/workpen/workpen/commit/696898dadc65a0af1d8d1f3d11cea68990ff609f))
* **wrap:** jail Windows workpen run with a write-restricted token ([#76](https://github.com/workpen/workpen/issues/76)) ([7324543](https://github.com/workpen/workpen/commit/7324543b49c8d88c9ac2d75949a96c719b5658f8)), closes [#75](https://github.com/workpen/workpen/issues/75)


### Bug Fixes

* argv dest-deny uses classify for hardlink tokens ([#30](https://github.com/workpen/workpen/issues/30)) ([a56b3bc](https://github.com/workpen/workpen/commit/a56b3bc395f06b09ca6d5efad02bbf230d57ba48)), closes [#18](https://github.com/workpen/workpen/issues/18)
* **cli:** canonicalize why --root like run ([#73](https://github.com/workpen/workpen/issues/73)) ([ff5753b](https://github.com/workpen/workpen/commit/ff5753b451b44eacd0e958fb4d0f9df728e61c17))
* **deny:** dest-deny -uc clusters and infix redirects ([#83](https://github.com/workpen/workpen/issues/83)) ([0d48b2f](https://github.com/workpen/workpen/commit/0d48b2ff26e4ad1cb3b1f6f74950426de81dd539))
* **deny:** dest-deny attached -lc script bodies ([#84](https://github.com/workpen/workpen/issues/84)) ([b4e2276](https://github.com/workpen/workpen/commit/b4e22765c86849db3ef29e2185fb07de9395543b))
* **deny:** dest-deny clustered shell -c and why extra paths ([#81](https://github.com/workpen/workpen/issues/81)) ([c7a09ff](https://github.com/workpen/workpen/commit/c7a09ff500764ec6101066a12d79d9a8196ca6a0))
* **deny:** fail-closed Windows hardlink when names &lt; nlink ([#74](https://github.com/workpen/workpen/issues/74)) ([83a83fa](https://github.com/workpen/workpen/commit/83a83fa3cd08c3a184f699585b4f5f876698e13a))
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
