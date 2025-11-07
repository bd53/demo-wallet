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

docs:
  @echo "Generating documentation..."
  cargo doc --no-deps --open
