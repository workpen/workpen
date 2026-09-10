.PHONY: help check stealth

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

check: ## fmt, clippy, test, deny, stealth, trigger lock
	cargo fmt --check
	RUSTFLAGS="-D warnings" cargo clippy --locked --workspace --all-targets -- -D warnings
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --workspace
	RUSTFLAGS="-D warnings" cargo test --locked --workspace
	cargo deny check
	python3 scripts/test_workflow_triggers.py
	bash scripts/assert-stealth.sh workpen/workpen

stealth: ## Check launch surfaces stay empty
	bash scripts/assert-stealth.sh workpen/workpen
