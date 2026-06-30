# HashNut MPC Client

HashNut MPC Client 是 [HashNut 支付网关](https://hashnut.io) 的商户端 MPC 钱包（Party 1）。它与 MPC Server（Party 2）参与双方 ECDSA 密钥生成和协作签名，用于管理分账合约的 EOA 收款地址。

## 环境要求

- **Go 1.21+**，需启用 CGO
- **GCC**（macOS: Xcode 命令行工具；Windows: [MSYS2](https://www.msys2.org/) MinGW-w64）
- **mingw-w64**（仅在 macOS 上交叉编译 Windows 版本时需要）：`brew install mingw-w64`

## 编译

### 快速编译（当前平台）

```bash
cd bin
go build -ldflags "-X main.buildEnv=testnet -X main.version=v1.0.0" -o mpc-gui ../cmd/gui/main.go
```

`buildEnv` 参数决定连接的后端服务器：

| 值 | 服务器 |
|----|--------|
| `local` | `http://localhost:3022` |
| `testnet` | `https://testnet.hashnut.io` |
| `mainnet` | `https://defi.hashnut.io` |

### macOS

```bash
# macOS ARM (Apple Silicon) - 原生编译
CGO_ENABLED=1 GOARCH=arm64 go build \
  -ldflags "-X main.buildEnv=testnet -X main.version=v1.0.0" \
  -o bin/mpc-gui-darwin-arm64 ./cmd/gui

# macOS x86_64 (Intel) - 在 ARM 上交叉编译
CGO_ENABLED=1 GOARCH=amd64 go build \
  -ldflags "-X main.buildEnv=testnet -X main.version=v1.0.0" \
  -o bin/mpc-gui-darwin-amd64 ./cmd/gui
```

### Windows（在 macOS 上交叉编译）

需要先安装 mingw-w64：`brew install mingw-w64`

```bash
# Windows x86_64
CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build \
  -ldflags "-X main.buildEnv=testnet -X main.version=v1.0.0 -H windowsgui" \
  -o bin/mpc-gui-amd64.exe ./cmd/gui
```

> `-H windowsgui` 参数可以避免在 Windows 上双击运行时弹出命令行黑窗口。

### Windows（原生编译）

在 Windows 上使用 MSYS2 MinGW-w64 终端编译：

```bash
CGO_ENABLED=1 go build ^
  -ldflags "-X main.buildEnv=testnet -X main.version=v1.0.0 -H windowsgui" ^
  -o bin\mpc-gui.exe .\cmd\gui
```

### 使用 Makefile

项目包含 Makefile，可以批量编译所有平台/环境组合：

```bash
make build OS=darwin ARCH=arm64 ENV=testnet   # 单个目标
make testnet                                   # testnet 所有平台
make mainnet                                   # mainnet 所有平台
make all                                       # 全部
```

## keys.db - 极其重要

首次登录并执行密钥生成（keygen）时，客户端会在工作目录下创建 **`keys.db`** 文件。这个 SQLite 数据库存储了：

- **MPC 私钥分片**（所有已生成 EOA 地址的 Party 1 分片）
- **分账合约管理地址密钥（splitWalletManager）**
- **收款地址密钥材料**

所有私钥字段使用 **AES-256-GCM** 加密，密钥通过 **Argon2id** 从登录密码派生。但数据库本身是双方 MPC 密钥对中不可替代的一半。

### 重要提醒

- **keygen 后请立即备份 `keys.db`**，将备份存放在安全的位置（加密 U 盘、密码管理器等）
- **如果丢失 `keys.db`，您的 MPC 密钥将永久丢失。** MPC Server 仅持有 Party 2 的分片，无法单独恢复您的密钥
- **绝不要将 `keys.db` 分享给任何人。** 结合您的密码，它可以完全控制您的 MPC 地址
- **不要删除 `keys.db`**，除非您确定所有关联的收款地址都已提取资金并停用

### 推荐备份策略

1. 每次 keygen 后，将 `keys.db` 复制到安全的备份位置
2. 至少在 2 个不同的物理位置保存副本
3. 定期验证备份，确认可以正常恢复

## macOS Gatekeeper

macOS 可能会阻止运行未签名的二进制文件。解决方法：

```bash
# 移除隔离属性
xattr -cr mpc-gui-darwin-arm64

# 然后运行
./mpc-gui-darwin-arm64
```

或者：在 Finder 中右键点击二进制文件，选择「打开」，然后确认。

## 许可证

详见 [LICENSE](LICENSE)。
