package encrypt_util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id 推荐参数（可根据设备性能调整）
	argonTime    = 1         // 迭代次数
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4         // 并行度
	argonKeyLen  = 32        // AES-256 密钥长度

	// AES-GCM 参数
	ivLen = 12 // 标准推荐值
)

// EncryptedPrivateKey 包含解密所需的所有参数
type EncryptedPrivateKey struct {
	Salt       []byte `json:"salt"`       // 16+ 字节，随机
	IV         []byte `json:"iv"`         // 12 字节
	Ciphertext []byte `json:"ciphertext"` // 加密后的私钥（不含认证标签）
	Tag        []byte `json:"tag"`        // 16 字节，GCM 认证标签
}

// GenerateRandomBytes 密码学安全随机数
func GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

// DeriveKey 使用 Argon2id 从密码派生 256 位密钥
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// Encrypt 使用用户密码加密私钥，返回包含所有加密参数的 EncryptedPrivateKey
func Encrypt(privateKey []byte, password string) (*EncryptedPrivateKey, error) {
	// 1. 生成随机盐
	salt, err := GenerateRandomBytes(16)
	if err != nil {
		return nil, err
	}

	// 2. 派生密钥
	key := DeriveKey(password, salt)

	// 3. 生成随机 IV
	iv, err := GenerateRandomBytes(ivLen)
	if err != nil {
		return nil, err
	}

	// 4. AES-256-GCM 加密
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Seal 输出: ciphertext || tag
	sealed := aesGCM.Seal(nil, iv, privateKey, nil)
	tagStart := len(sealed) - aesGCM.Overhead()
	ciphertext := sealed[:tagStart]
	tag := sealed[tagStart:]

	return &EncryptedPrivateKey{
		Salt:       salt,
		IV:         iv,
		Ciphertext: ciphertext,
		Tag:        tag,
	}, nil
}

// Decrypt 使用密码和 EncryptedPrivateKey 解密出原始私钥
func Decrypt(enc *EncryptedPrivateKey, password string) ([]byte, error) {
	if enc == nil {
		return nil, errors.New("encrypted data is nil")
	}

	// 1. 派生密钥
	key := DeriveKey(password, enc.Salt)

	// 2. AES-GCM 解密
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 重建完整密文
	sealed := append(enc.Ciphertext, enc.Tag...)
	plaintext, err := aesGCM.Open(nil, enc.IV, sealed, nil)
	if err != nil {
		return nil, err // 密码错误或数据被篡改
	}
	return plaintext, nil
}

// MarshalJSON 自定义 JSON 序列化（将字节数组编码为 Base64）
func (e *EncryptedPrivateKey) MarshalJSON() ([]byte, error) {
	type Alias EncryptedPrivateKey
	return json.Marshal(&struct {
		Salt       string `json:"salt"`
		IV         string `json:"iv"`
		Ciphertext string `json:"ciphertext"`
		Tag        string `json:"tag"`
		*Alias
	}{
		Salt:       bytesToBase64(e.Salt),
		IV:         bytesToBase64(e.IV),
		Ciphertext: bytesToBase64(e.Ciphertext),
		Tag:        bytesToBase64(e.Tag),
		Alias:      (*Alias)(e),
	})
}

// UnmarshalJSON 自定义 JSON 反序列化（从 Base64 还原）
func (e *EncryptedPrivateKey) UnmarshalJSON(data []byte) error {
	type Alias EncryptedPrivateKey
	aux := &struct {
		Salt       string `json:"salt"`
		IV         string `json:"iv"`
		Ciphertext string `json:"ciphertext"`
		Tag        string `json:"tag"`
		*Alias
	}{
		Alias: (*Alias)(e),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	var err error
	if e.Salt, err = base64ToBytes(aux.Salt); err != nil {
		return err
	}
	if e.IV, err = base64ToBytes(aux.IV); err != nil {
		return err
	}
	if e.Ciphertext, err = base64ToBytes(aux.Ciphertext); err != nil {
		return err
	}
	if e.Tag, err = base64ToBytes(aux.Tag); err != nil {
		return err
	}
	return nil
}

// 辅助函数：[]byte ↔ Base64
func bytesToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func base64ToBytes(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
