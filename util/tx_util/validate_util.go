package tx_util

import (
	"regexp"
	"strings"
)

// 预编译正则表达式
var (
	evmAddressRegex = regexp.MustCompile(`^(0x)?[0-9a-fA-F]{40}$`)
	trcAddressRegex = regexp.MustCompile(`^(T)[0-9a-zA-Z]{33}$`)
	evmTxidRegex    = regexp.MustCompile(`^(0x)?[0-9a-fA-F]{64}$`)
	tronTxidRegex   = regexp.MustCompile(`^(0x)?[0-9a-fA-F]{64}$`) // 与 EVM 相同
	ipRegex         = regexp.MustCompile(`^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$`)
)

// IsBlank 检查字符串是否为空或仅包含空白字符（Go 中无 null，空字符串视为空白）
func IsBlank(s string) bool {
	return strings.TrimSpace(s) == ""
}

// IsValidEvmAddress 校验 EVM 地址格式
func IsValidEvmAddress(address string) bool {
	if IsBlank(address) {
		return false
	}
	return evmAddressRegex.MatchString(address)
}

// IsValidTronAddress 校验 TRON 地址格式
func IsValidTronAddress(address string) bool {
	if IsBlank(address) {
		return false
	}
	return trcAddressRegex.MatchString(address)
}

// IsValidEvmTxId 校验 EVM 交易 ID 格式
func IsValidEvmTxId(txId string) bool {
	if IsBlank(txId) {
		return false
	}
	return evmTxidRegex.MatchString(txId)
}

// IsValidTronTxId 校验 TRON 交易 ID 格式
func IsValidTronTxId(txId string) bool {
	if IsBlank(txId) {
		return false
	}
	return tronTxidRegex.MatchString(txId)
}

// IsValidAddress 根据链代码校验地址（链代码不区分大小写）
func IsValidAddress(chainCode, address string) bool {
	if IsBlank(chainCode) || IsBlank(address) {
		return false
	}
	cc := strings.ToLower(chainCode)
	switch cc {
	case "evm", "erc20", "erc721", "erc1155", "eth",
		"bep20", "bep721", "bep1155", "bnb", "bsc",
		"polygon-erc20", "polygon-erc721", "polygon-erc1155", "matic", "polygon":
		return IsValidEvmAddress(address)
	case "trc20", "trc721", "trc1155", "trx", "tron":
		return IsValidTronAddress(address)
	default:
		return false
	}
}

// IsValidTxId 根据链代码校验交易 ID（注意：链代码大小写敏感，与 Java 原逻辑一致）
func IsValidTxId(chainCode, txId string) bool {
	if IsBlank(chainCode) || IsBlank(txId) {
		return false
	}
	// 保持大小写敏感，直接匹配
	switch chainCode {
	case "evm", "erc20", "erc721", "erc1155", "ETH":
		return IsValidEvmTxId(txId)
	case "trc20", "trc721", "trc1155", "TRX", "TRON":
		return IsValidTronTxId(txId)
	case "bep20", "bep721", "bep1155", "BNB", "BSC":
		return IsValidEvmTxId(txId)
	case "polygon-erc20", "polygon-erc721", "polygon-erc1155", "MATIC", "POLYGON":
		return IsValidEvmTxId(txId)
	default:
		return false
	}
}

// IsEvm 判断链是否属于 EVM 系列（链代码不区分大小写）
func IsEvm(chain string) bool {
	c := strings.ToLower(chain)
	switch c {
	case "evm", "erc20", "erc1155", "eth",
		"bep20", "bep1155", "bsc", "bnb",
		"polygon-erc20", "polygon-erc721", "polygon-erc1155", "matic", "polygon":
		return true
	default:
		return false
	}
}

// FormatEvmAddress 格式化 EVM 地址：添加 0x 前缀，截取前42字符，转小写
// 注意：输入地址需有效，否则可能 panic（与 Java 的 substring 行为一致）
func FormatEvmAddress(address string) string {
	if !strings.HasPrefix(address, "0x") {
		address = "0x" + address
	}
	address = address[:42] // 假设长度至少 42
	return strings.ToLower(address)
}

// IsTron 判断链是否属于 TRON 系列（链代码不区分大小写）
func IsTron(chain string) bool {
	c := strings.ToLower(chain)
	switch c {
	case "trc20", "trc721", "trc1155", "tron", "trx":
		return true
	default:
		return false
	}
}

// FormatTronAddress 格式化 TRON 地址：截取前34字符
// 注意：输入地址需有效，否则可能 panic
func FormatTronAddress(address string) string {
	return address[:34] // 假设长度至少 34
}

// IsValidIp 校验 IP 地址（支持 "*" 通配）
func IsValidIp(ip string) bool {
	if IsBlank(ip) {
		return false
	}
	if ip == "*" {
		return true
	}
	return ipRegex.MatchString(ip)
}
