#!/usr/bin/env python3
"""Lock Recipe A and the cheap release-please split."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _on_block(text: str) -> str:
    start = text.index("\non:")
    rest = text[start + 1 :]
    end = rest.index("\njobs:")
    block = rest[:end]
    lines = []
    for line in block.splitlines():
        stripped = line.split("#", 1)[0].rstrip()
        if stripped:
            lines.append(stripped)
    return "\n".join(lines)


class WorkflowTriggerTests(unittest.TestCase):
    def test_ci_has_no_push_compile(self) -> None:
        on_block = _on_block((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))
        self.assertIn("pull_request:", on_block)
        self.assertIn("workflow_dispatch:", on_block)
        self.assertNotIn("push:", on_block)
        self.assertNotIn("tags:", on_block)

    def test_actionlint_is_not_an_install_action_tool(self) -> None:
        # actionlint is a Go binary, not a crates.io crate. install-action
        # falls back to cargo-binstall and fails with "actionlint is not found".
        text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("tool: actionlint@", text)
        self.assertIn("rhysd/actionlint@", text)

    def test_gitleaks_is_not_an_install_action_tool(self) -> None:
        # Same class as actionlint: gitleaks is Go, not crates.io.
        text = (WORKFLOWS / "security.yml").read_text(encoding="utf-8")
        self.assertNotIn("tool: gitleaks@", text)
        self.assertIn("gitleaks/gitleaks/releases/download/", text)

    def test_release_please_uses_simple_for_virtual_workspace(self) -> None:
        text = (ROOT / "release-please-config.json").read_text(encoding="utf-8")
        self.assertIn('"release-type": "simple"', text)
        self.assertNotIn('"release-type": "rust"', text)
        self.assertIn("crates/workpen/Cargo.toml", text)
        self.assertIn("crates/workpen-cli/Cargo.toml", text)

    def test_release_please_is_main_only(self) -> None:
        text = (WORKFLOWS / "release-please.yml").read_text(encoding="utf-8")
        on_block = _on_block(text)
        self.assertIn("push:", on_block)
        self.assertIn("branches: [main]", on_block)
        self.assertIn("workflow_dispatch:", on_block)
        self.assertNotIn("pull_request:", on_block)
        self.assertNotRegex(text, r"cargo (test|nextest|clippy|fuzz)")

    def test_release_please_syncs_cargo_lock(self) -> None:
        text = (WORKFLOWS / "release-please.yml").read_text(encoding="utf-8")
        self.assertIn("sync-release-pr-versions:", text)
        self.assertIn("scripts/sync-cargo-lock-workspace-versions.sh", text)
        self.assertNotIn("cargo generate-lockfile", text)
        script = (ROOT / "scripts" / "sync-cargo-lock-workspace-versions.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("cargo check -p workpen", script)
        self.assertIn("cargo metadata --locked", script)
        self.assertNotIn("generate-lockfile", script)

    def test_auto_merge_skips_release_please_head(self) -> None:
        text = (WORKFLOWS / "auto-approve.yml").read_text(encoding="utf-8")
        self.assertIn("!startsWith(github.head_ref, 'release-please')", text)
        self.assertIn("autorelease: pending", text)

    def test_auto_approve_skips_hmarr_on_release_please(self) -> None:
        text = (WORKFLOWS / "auto-approve.yml").read_text(encoding="utf-8")
        self.assertIn("Skip self-approve on release-please", text)
        self.assertIn("bot cannot approve its own PR", text)
        approve_idx = text.index("name: Auto-approve PR")
        skip_idx = text.index("name: Skip self-approve on release-please")
        self.assertLess(approve_idx, skip_idx)
        approve_block = text[approve_idx:skip_idx]
        self.assertIn("!startsWith(github.head_ref, 'release-please')", approve_block)
        self.assertIn("hmarr/auto-approve-action@", approve_block)

    def test_cheap_pr_status_checks_do_not_cancel(self) -> None:
        for name in ("pr-title.yml", "dco.yml"):
            text = (WORKFLOWS / name).read_text(encoding="utf-8")
            self.assertIn("cancel-in-progress: false", text, name)

    def test_publish_crates_is_tag_or_dispatch(self) -> None:
        text = (WORKFLOWS / "publish-crates.yml").read_text(encoding="utf-8")
        on_block = _on_block(text)
        self.assertIn("workflow_dispatch:", on_block)
        self.assertIn("tags:", on_block)
        self.assertNotIn("pull_request:", on_block)
        self.assertNotIn("branches:", on_block)
        self.assertIn("id-token: write", text)
        self.assertIn("crates-io-auth-action", text)
        self.assertNotIn("CARGO_REGISTRY_TOKEN: ${{ secrets.", text)

    def test_msrv_is_1_95(self) -> None:
        toolchain = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
        self.assertIn('channel = "1.95"', toolchain)
        ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('toolchain: "1.95"', ci)
        self.assertNotIn('toolchain: "1.85"', ci)
        publish = (WORKFLOWS / "publish-crates.yml").read_text(encoding="utf-8")
        self.assertIn('toolchain: "1.95"', publish)
        cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('rust-version = "1.95"', cargo)

    def test_ci_enables_gc_and_nono_features(self) -> None:
        ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("--features gc,nono", ci)
        self.assertNotIn("--features gc --", ci)
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("--features gc,nono", makefile)


if __name__ == "__main__":
    unittest.main()
