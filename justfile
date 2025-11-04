binary := "cws"
target := "release"

all: clean update check test build

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

run *ARGS:
  @echo "Running {{binary}} (dev)..."
  cargo run -- {{ARGS}}

run-release *ARGS:
  @echo "Running {{binary}} (release)..."
  cargo run --release -- {{ARGS}}

exec *ARGS:
  @echo "Executing {{binary}}..."
  ./target/release/{{binary}} {{ARGS}}

build-run *ARGS: build
  @echo "Running {{binary}}..."
  ./target/release/{{binary}} {{ARGS}}

dev *ARGS: check test
  cargo run -- {{ARGS}}

full *ARGS: all
  ./target/release/{{binary}} {{ARGS}}
