package tx_util

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

// 比特币Base58字母表
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode 将字节数组编码为Base58字符串
func base58Encode(input []byte) string {
	x := big.NewInt(0).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := &big.Int{}
	var result []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}
	// 处理前导零字节
	for _, b := range input {
		if b != 0 {
			break
		}
		result = append(result, base58Alphabet[0])
	}
	// 反转结果
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

// base58Decode 将Base58字符串解码为字节数组
func base58Decode(s string) ([]byte, error) {
	result := big.NewInt(0)
	for _, c := range s {
		index := strings.IndexRune(base58Alphabet, c)
		if index == -1 {
			return nil, errors.New("invalid base58 character")
		}
		result.Mul(result, big.NewInt(58))
		result.Add(result, big.NewInt(int64(index)))
	}
	decoded := result.Bytes()
	// 处理前导零
	for i := 0; i < len(s); i++ {
		if s[i] != base58Alphabet[0] {
			break
		}
		decoded = append([]byte{0}, decoded...)
	}
	return decoded, nil
}

// doubleSha256 计算双SHA256哈希，返回前4字节作为校验和
func doubleSha256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:4]
}

// base58CheckEncode 对payload进行Base58Check编码：payload + 校验和(前4字节双SHA256)，然后Base58编码
func base58CheckEncode(payload []byte) string {
	checksum := doubleSha256(payload)
	data := append(payload, checksum...)
	return base58Encode(data)
}

// base58CheckDecode 解码Base58Check字符串，返回payload，并验证校验和
func base58CheckDecode(s string) ([]byte, error) {
	data, err := base58Decode(s)
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, errors.New("invalid base58check data: too short")
	}
	payload := data[:len(data)-4]
	checksum := data[len(data)-4:]
	expectedChecksum := doubleSha256(payload)
	if string(checksum) != string(expectedChecksum) {
		return nil, errors.New("invalid checksum")
	}
	return payload, nil
}

// EthToTron 将ETH地址（0x开头的16进制字符串）转换为Tron Base58地址
func EthToTron(ethAddress string) (string, error) {
	// 去除0x前缀并转为小写
	clean := strings.TrimPrefix(ethAddress, "0x")
	if len(clean) != 40 {
		return "", errors.New("invalid ETH address length, must be 40 hex characters")
	}
	// 将16进制字符串转为20字节的哈希
	hash, err := hex.DecodeString(clean)
	if err != nil {
		return "", err
	}
	// 构建payload：版本字节0x41 + 20字节哈希
	payload := append([]byte{0x41}, hash...)
	// Base58Check编码
	return base58CheckEncode(payload), nil
}

// TronToEth 将Tron Base58地址转换为ETH地址（0x开头的16进制字符串）
func TronToEth(tronAddress string) (string, error) {
	// Base58Check解码得到payload（21字节：版本+哈希）
	payload, err := base58CheckDecode(tronAddress)
	if err != nil {
		return "", err
	}
	if len(payload) != 21 {
		return "", errors.New("invalid Tron address length, expected 21 bytes")
	}
	// 检查版本字节是否为0x41（可选，但标准Tron地址都是0x41）
	if payload[0] != 0x41 {
		// 如果不是0x41，仍可返回哈希，但这里可以返回错误或警告，根据需求决定
		// 此处选择返回错误，因为预期是Tron地址
		return "", errors.New("invalid Tron address version byte, expected 0x41")
	}
	// 提取20字节哈希
	hash := payload[1:]
	// 转为16进制并添加0x前缀
	return "0x" + hex.EncodeToString(hash), nil
}
