BINARY := demo-wallet
TARGET := release
BUILD_DIR := target/$(TARGET)

.PHONY: all clean update build generate

all: clean update build generate

clean:
	@echo "Cleaning..."
	cargo clean

update:
	@echo "Updating dependencies..."
	cargo update

build:
	@echo "Building ($(TARGET))..."
	cargo build --release

generate:
	@echo "Generating documentation..."
	cargo run --release --bin docs
