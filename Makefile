# Workspace tooling for `poprf-ristretto`.
#
# Meta / lint:
#   make headers          regenerate the FFI C header.
#   make check-headers    fail if the checked-in header is stale (CI gate).
#   make test             run the workspace test suite with all features.
#   make clippy           run clippy across the workspace with `-D warnings`.
#   make fmt              apply rustfmt to the workspace.
#   make check-fmt        fail if rustfmt would modify any file.
#
# Build:
#   make ffi-release      build the FFI cdylib (libpoprf_ristretto_ffi.so).
#   make wasm             build the wasm package (target=web, release).
#   make wasm-nodejs      build the wasm package for Node.js consumers.
#   make wasm-tarball     run `npm pack` on pkg/ for the publishable .tgz.
#   make wasm-docker      run wasm builds inside the pinned container.
#                         Set WASM_DOCKER_TARGETS to override the inner
#                         make targets (default: wasm).
#
# Publish:
#   make publish-dry-run  cargo publish --dry-run for all three crates
#                         (verifies packaging, tarball contents, deps).
#
# Housekeeping:
#   make clean            `cargo clean` plus wipe pkg/, pkg-node/, target-docker/.
#
# Real publishes (crates.io and npm) are intentionally not exposed as
# Makefile targets. The commands are:
#
#   # crates.io, in dependency order, sleeping ~45s between to let the
#   # sparse index catch up:
#   cargo publish -p poprf-ristretto
#   cargo publish -p poprf-ristretto-ffi
#   cargo publish -p poprf-ristretto-wasm
#
#   # npm: build the .tgz in the pinned container, then publish:
#   make wasm-docker WASM_DOCKER_TARGETS=wasm-tarball
#   (cd poprf-ristretto-wasm/pkg && npm publish --access public *.tgz)
#
# `cargo`, `cbindgen`, and `wasm-pack` are invoked through the
# env-overridable variables below so CI can pin tool versions.

FFI_DIR        := poprf-ristretto-ffi
FFI_HEADER     := $(FFI_DIR)/include/poprf_ristretto_ffi.h
FFI_CBINDGEN   := $(FFI_DIR)/cbindgen.toml
WASM_DIR       := poprf-ristretto-wasm

CBINDGEN  ?= cbindgen
CARGO     ?= cargo
WASM_PACK ?= wasm-pack
WASM_PACK_VERSION ?= 0.15.0
DOCKER    ?= docker
DOCKER_IMAGE_TAG ?= poprf-ristretto-build:local

.PHONY: all headers check-headers test clippy fmt check-fmt \
        ffi-release wasm wasm-nodejs wasm-test wasm-tarball \
        publish-dry-run clean wasm-pack-install wasm-docker

all: headers test clippy

headers:
	@mkdir -p $(FFI_DIR)/include
	$(CBINDGEN) --config $(FFI_CBINDGEN) --crate poprf-ristretto-ffi --output $(FFI_HEADER) 2>/dev/null

# CI drift check. Regenerates into a temp file and diffs against the
# checked-in header; any divergence (function added/renamed, signature
# changed, doc comment edited) fails the build.
check-headers:
	@tmp=$$(mktemp); \
	$(CBINDGEN) --config $(FFI_CBINDGEN) --crate poprf-ristretto-ffi --output $$tmp 2>/dev/null; \
	if ! diff -u $(FFI_HEADER) $$tmp; then \
		echo ""; \
		echo "error: $(FFI_HEADER) is stale; run 'make headers' and commit the result." >&2; \
		rm -f $$tmp; \
		exit 1; \
	fi; \
	rm -f $$tmp

test:
	$(CARGO) test --workspace --all-features

clippy:
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

fmt:
	$(CARGO) fmt --all

check-fmt:
	$(CARGO) fmt --all -- --check

# Build the FFI cdylib in release mode. Output:
#   target/release/libpoprf_ristretto_ffi.so   (Linux)
#   target/release/libpoprf_ristretto_ffi.dylib (macOS)
# Workspace `[profile.release]` sets `panic = "abort"` to keep unwinding
# from crossing the `extern "C"` boundary.
ffi-release:
	$(CARGO) build -p poprf-ristretto-ffi --release

# Build the wasm package for browser consumers.
#   make wasm  → $(WASM_DIR)/pkg/  (ESM with `initSync` / `init()`)
#
# `wasm-pack` drives `cargo build --target wasm32-unknown-unknown` under
# the `release-wasm` profile (see workspace Cargo.toml). `--target web`
# emits glue directly callable from a browser `<script type="module">` or
# from any runtime supporting raw `WebAssembly.instantiate`.
#
# `WASM_BUILD_ENV` makes the `.wasm` byte-reproducible by remapping the
# three absolute paths that leak into the binary via `file!()` and panic
# strings: workspace dir, CARGO_HOME (crates.io dependency sources), and
# the rustc sysroot (rust-src component). The env var replaces
# `.cargo/config.toml`'s wasm32 rustflags, so `+reference-types` is
# re-applied here.
#
# PATH prepend ensures a wasm-pack just installed by `wasm-pack-install`
# is found by the recipe shell.
WASM_BUILD_ENV = PATH="$${CARGO_HOME:-$$HOME/.cargo}/bin:$$PATH" \
	CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS=" \
	-C target-feature=+reference-types \
	--remap-path-prefix $(CURDIR)=/build/src \
	--remap-path-prefix $${CARGO_HOME:-$$HOME/.cargo}=/build/cargo \
	--remap-path-prefix $$(rustc --print sysroot)=/build/rust"

# Install the pinned wasm-pack if missing.
wasm-pack-install:
	@command -v $(WASM_PACK) >/dev/null 2>&1 || \
		test -x "$${CARGO_HOME:-$$HOME/.cargo}/bin/$(WASM_PACK)" || \
		$(CARGO) install $(WASM_PACK) --version $(WASM_PACK_VERSION) --locked

# wasm-pack 0.15.0 generates package.json's `files` array from
# `read_dir(pkg/)` before copying LICENSE files in. Clean pkg/ first to
# avoid leftovers leaking in, then append the LICENSEs via jq in a fixed
# order so the manifest is filesystem-independent.
wasm: wasm-pack-install
	rm -rf $(WASM_DIR)/pkg
	cd $(WASM_DIR) && $(WASM_BUILD_ENV) $(WASM_PACK) build --target web --profile release-wasm --scope brave-intl
	@jq '.files += ["LICENSE-APACHE", "LICENSE-MIT"]' \
		$(WASM_DIR)/pkg/package.json > $(WASM_DIR)/pkg/package.json.tmp \
		&& mv $(WASM_DIR)/pkg/package.json.tmp $(WASM_DIR)/pkg/package.json

wasm-nodejs: wasm-pack-install
	rm -rf $(WASM_DIR)/pkg-node
	cd $(WASM_DIR) && $(WASM_BUILD_ENV) $(WASM_PACK) build --target nodejs --profile release-wasm --out-dir pkg-node

# `npm pack` the built pkg/. Pair with `wasm-docker` for a reproducible .tgz.
wasm-tarball: wasm
	cd $(WASM_DIR)/pkg && npm pack

# Run targets inside the pinned container (see Dockerfile).
WASM_DOCKER_TARGETS ?= wasm

wasm-docker:
	$(DOCKER) build -t $(DOCKER_IMAGE_TAG) .
	$(DOCKER) run --rm \
		--user $$(id -u):$$(id -g) \
		-v $(CURDIR):/work \
		-e HOME=/tmp \
		-e CARGO_TARGET_DIR=/work/target-docker \
		$(DOCKER_IMAGE_TAG) \
		make $(WASM_DOCKER_TARGETS)

# Round-trip smoke test across the JS↔Rust boundary, run under Node.
# Catches regressions in the `js_sys::Array` / `Uint8Array` / `JsValue`
# glue that a native `cargo test` cannot exercise.
wasm-test: wasm-pack-install
	PATH="$${CARGO_HOME:-$$HOME/.cargo}/bin:$$PATH" $(WASM_PACK) test --node $(WASM_DIR)

# Verify each crate is packageable before tagging a release. Catches
# dirty git state, missing tracked files, .gitignore over-restriction
# (e.g. a fixture excluded by accident), missing metadata, and
# cross-crate version pin mismatches.
#
# The core crate has no path dependencies and gets a full
# `cargo publish --dry-run` (compiles against a stripped manifest and
# verifies against the registry index).
#
# The binding crates path-depend on the core crate. If `poprf-ristretto`
# is not resolvable from the registry, `cargo publish --dry-run` for the
# bindings fails before any packaging checks run. The bindings therefore
# use `cargo package --list`, which emits the would-be tarball file
# listing — enough to verify packaging correctness without contacting
# the registry.
publish-dry-run:
	$(CARGO) publish --dry-run --allow-dirty -p poprf-ristretto
	@echo ""
	@echo "==> poprf-ristretto-ffi tarball contents:"
	$(CARGO) package --allow-dirty --list -p poprf-ristretto-ffi
	@echo ""
	@echo "==> poprf-ristretto-wasm tarball contents:"
	$(CARGO) package --allow-dirty --list -p poprf-ristretto-wasm

clean:
	$(CARGO) clean
	rm -rf $(WASM_DIR)/pkg $(WASM_DIR)/pkg-node target-docker
