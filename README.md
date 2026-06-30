# HashNut MPC Client

HashNut MPC Client is the merchant-side MPC wallet (Party 1) for [HashNut Payment Gateway](https://hashnut.io). It participates in 2-party ECDSA key generation and collaborative signing with the MPC Server (Party 2) to manage EOA receipt addresses for split wallet contracts.

## Prerequisites

- **Go 1.21+** with CGO enabled
- **GCC** (macOS: Xcode Command Line Tools; Windows: [MSYS2](https://www.msys2.org/) MinGW-w64)
- **mingw-w64** (only for cross-compiling Windows builds on macOS): `brew install mingw-w64`

## Build

### Quick Build (current platform)

```bash
cd bin
go build -ldflags "-X main.buildEnv=testnet -X main.version=v1.0.0" -o mpc-gui ../cmd/gui/main.go
```

The `buildEnv` parameter determines the backend server:

| Value | Server |
|-------|--------|
| `local` | `http://localhost:3022` |
| `testnet` | `https://testnet.hashnut.io` |
| `mainnet` | `https://defi.hashnut.io` |

### macOS

```bash
# macOS ARM (Apple Silicon) - native
CGO_ENABLED=1 GOARCH=arm64 go build \
  -ldflags "-X main.buildEnv=mainnet -X main.version=v1.0.0" \
  -o bin/mpc-gui ./cmd/gui

# macOS x86_64 (Intel) - cross-compile on ARM
CGO_ENABLED=1 GOARCH=amd64 go build \
  -ldflags "-X main.buildEnv=mainnet -X main.version=v1.0.0" \
  -o bin/mpc-gui ./cmd/gui
```

### Windows (cross-compile on macOS)

Requires mingw-w64: `brew install mingw-w64`

```bash
# Windows x86_64
CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build \
  -ldflags "-X main.buildEnv=mainnet -X main.version=v1.0.0 -H windowsgui" \
  -o bin/mpc-gui.exe ./cmd/gui
```

> The `-H windowsgui` flag prevents a console window from appearing when double-clicking the `.exe` on Windows.

### Windows (native)

Build on Windows using MSYS2 MinGW-w64 terminal:

```bash
CGO_ENABLED=1 go build ^
  -ldflags "-X main.buildEnv=mainnet -X main.version=v1.0.0 -H windowsgui" ^
  -o bin\mpc-gui.exe .\cmd\gui
```

### Using Makefile

The project includes a Makefile that builds all platform/environment combinations:

```bash
make build OS=darwin ARCH=arm64 ENV=testnet   # Single target
make testnet                                   # All platforms for testnet
make mainnet                                   # All platforms for mainnet
make all                                       # Everything
```

## keys.db - CRITICAL

When you first log in and perform key generation (keygen), the client creates a **`keys.db`** file in the working directory. This SQLite database stores:

- **MPC private key shares** (Party 1 shares for all generated EOA addresses)
- **Split wallet manager keys**
- **Receipt wallet key material**

All private key fields are encrypted with **AES-256-GCM**, derived from your login password via **Argon2id**. However, the database itself is the irreplaceable half of your 2-party MPC key pair.

### IMPORTANT

- **Back up `keys.db` immediately** after keygen and store the backup in a secure location (encrypted USB, password manager, etc.)
- **If you lose `keys.db`, your MPC keys are permanently lost.** The MPC Server only holds Party 2 shares and cannot reconstruct your keys alone.
- **Never share `keys.db`** with anyone. Together with your password, it grants full control over your MPC addresses.
- **Do not delete `keys.db`** unless you are certain all associated receipt addresses have been drained and deactivated.

### Recommended Backup Strategy

1. After each keygen session, copy `keys.db` to a secure backup location
2. Keep at least 2 copies in different physical locations
3. Verify backups periodically by restoring to a test directory

## macOS Gatekeeper

macOS may block unsigned binaries. To run the client:

```bash
# Remove quarantine attribute
xattr -cr mpc-gui

# Then run
./mpc-gui
```

Or: right-click the binary in Finder, select "Open", then confirm.

## License

See [LICENSE](LICENSE) for details.
