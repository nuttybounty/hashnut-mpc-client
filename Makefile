VERSION    := $(shell git describe --tags --always 2>/dev/null || echo "dev")
ENTRY      := ./cmd/gui
OUTDIR     := bin
APP_NAME   := hashnut-mpc

OSES       := darwin windows
ARCHES     := amd64 arm64
ENVS       := local testnet mainnet

# Windows 交叉编译需要 mingw-w64: brew install mingw-w64
CC_windows_amd64 := x86_64-w64-mingw32-gcc
CC_windows_arm64 := aarch64-w64-mingw32-gcc

# 文件扩展名
EXT_darwin  :=
EXT_windows := .exe

# 打包格式
PKG_darwin  := tar.gz
PKG_windows := zip

.PHONY: all clean tidy local testnet mainnet

# ── 快捷目标 ──────────────────────────────────────────────

all: tidy
	@for env in $(ENVS); do \
		for os in $(OSES); do \
			for arch in $(ARCHES); do \
				$(MAKE) --no-print-directory _build_one OS=$$os ARCH=$$arch ENV=$$env; \
			done; \
		done; \
	done
	@echo "\nAll builds complete. Output: $(OUTDIR)/"

local:
	@for os in $(OSES); do \
		for arch in $(ARCHES); do \
			$(MAKE) --no-print-directory _build_one OS=$$os ARCH=$$arch ENV=local; \
		done; \
	done

testnet:
	@for os in $(OSES); do \
		for arch in $(ARCHES); do \
			$(MAKE) --no-print-directory _build_one OS=$$os ARCH=$$arch ENV=testnet; \
		done; \
	done

mainnet:
	@for os in $(OSES); do \
		for arch in $(ARCHES); do \
			$(MAKE) --no-print-directory _build_one OS=$$os ARCH=$$arch ENV=mainnet; \
		done; \
	done

# 单个构建: make build OS=darwin ARCH=arm64 ENV=testnet
build: tidy _build_one

# ── 内部构建目标 ──────────────────────────────────────────

_build_one:
ifndef OS
	$(error OS is required: darwin, windows)
endif
ifndef ARCH
	$(error ARCH is required: amd64, arm64)
endif
ifndef ENV
	$(error ENV is required: local, testnet, mainnet)
endif
	$(eval BIN_NAME := $(APP_NAME)-$(ENV)-$(OS)-$(ARCH)$(EXT_$(OS)))
	$(eval PKG_FMT  := $(PKG_$(OS)))
	$(eval _CC := $(CC_$(OS)_$(ARCH)))
	@echo "Building $(BIN_NAME) ..."
	@mkdir -p $(OUTDIR)
	CGO_ENABLED=1 GOOS=$(OS) GOARCH=$(ARCH) \
		$(if $(_CC),CC=$(_CC)) \
		go build \
		-ldflags "-s -w -X main.buildEnv=$(ENV) -X main.version=$(VERSION)" \
		-o $(OUTDIR)/$(BIN_NAME) $(ENTRY)
	@# 打包
	@cd $(OUTDIR) && \
	if [ "$(PKG_FMT)" = "tar.gz" ]; then \
		tar czf $(APP_NAME)-$(ENV)-$(OS)-$(ARCH).tar.gz $(BIN_NAME) && rm -f $(BIN_NAME); \
	else \
		zip -q $(APP_NAME)-$(ENV)-$(OS)-$(ARCH).zip $(BIN_NAME) && rm -f $(BIN_NAME); \
	fi
	@echo "  -> $(OUTDIR)/$(APP_NAME)-$(ENV)-$(OS)-$(ARCH).$(PKG_FMT)"

# ── 工具 ──────────────────────────────────────────────────

tidy:
	@go mod tidy

clean:
	rm -rf $(OUTDIR)
