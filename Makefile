.PHONY: build clean run install test run-full run-quick

# Build the binary
build:
	go build -o triagectl ./cmd/triagectl

# Build optimized release binary
release:
	go build -ldflags="-s -w" -o triagectl ./cmd/triagectl
	strip triagectl

# Clean build artifacts
clean:
	rm -f triagectl
	rm -rf triagectl-output/

# Run the tool
run: build
	./triagectl

# Run with all output formats
run-full: build
	./triagectl --html --csv --timeline

# Run with a small collector subset for quick testing
run-quick: build
	./triagectl --collectors system_info,gatekeeper,firewall,filevault,environment --html

# Install dependencies
install:
	go mod download

# Test (placeholder for when tests are added)
test:
	go test ./...

# List collectors
list: build
	./triagectl -list

# Show help
help:
	@echo "triagectl Build System"
	@echo "========================"
	@echo "make build     - Build debug binary"
	@echo "make release   - Build optimized binary"
	@echo "make run       - Build and run"
	@echo "make run-full  - Build and run with --html --csv --timeline"
	@echo "make run-quick - Build and run with small collector subset + HTML"
	@echo "make clean     - Clean artifacts"
	@echo "make install   - Download dependencies"
	@echo "make list      - List available collectors"
