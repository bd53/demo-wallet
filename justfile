binary := "demo-wallet"
target := "release"

all: clean update build generate

clean:
  @echo "Cleaning..."
  cargo clean

update:
  @echo "Updating dependencies..."
  cargo update

build:
  @echo "Building ({{target}})..."
  cargo build --release

generate:
  @echo "Generating documentation..."
  cargo run --release --bin docs