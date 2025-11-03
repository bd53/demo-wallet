binary := "demo-wallet"
target := "release"

all: clean update check test build generate

clean:
  @echo "Cleaning..."
  cargo clean

update:
  @echo "Updating dependencies..."
  cargo update

check:
  @echo "Checking..."
  cargo clippy -- -D warnings

test:
  @echo "Testing..."
  cargo test

build:
  @echo "Building ({{target}})..."
  cargo build --release

generate:
  @echo "Generating documentation..."
  cargo run --release --bin docs
