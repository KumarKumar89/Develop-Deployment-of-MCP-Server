.PHONY: fmt check test build release docker smoke clean

fmt:
	cargo fmt --all

check:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features --locked -- -D warnings

test:
	cargo test --all-targets --locked

build:
	cargo build --locked

release:
	cargo build --release --locked

docker:
	docker build -t cybersecurity-mcp-server:local .

smoke:
	./scripts/smoke_test.sh

clean:
	cargo clean
