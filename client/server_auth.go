package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// serverPublicKeys 按环境域名映射后端 Ed25519 公钥（32 字节 hex）。
// 每个环境使用独立密钥对，本地开发环境密钥泄漏不影响 testnet/mainnet。
// 更换某环境密钥时，只需更新该环境的公钥并重新编译 MPC Client。
var serverPublicKeys = map[string]string{
	"localhost":          "6c8257d608782310a0f8ca9f71d2ba5e60af0a43c07fafdc3cb231a255b4a075", // local dev
	"testnet.hashnut.io": "38e3f0a422d82009e1f6895bc3574f648895cc91fd8ebe8064c83fa5049fda62", // testnet
	"defi.hashnut.io":    "e6bff0c22573fa3310a0396d5a8eadddb9aa0a1091b2bb3990c7034edfd91d35", // mainnet
}

// challengeMaxAge 挑战响应的最大有效期（防止重放）
const challengeMaxAge = 30 * time.Second

type challengeRequest struct {
	ClientNonce string `json:"clientNonce"`
}

type challengeResponse struct {
	ServerNonce string      `json:"serverNonce"`
	Timestamp   json.Number `json:"timestamp"`
	Signature   string      `json:"signature"`
	PublicKey   string      `json:"publicKey"`
	Error       string      `json:"error,omitempty"`
}

// serverAuthenticated 缓存认证结果，启动时验证一次
var serverAuthenticated bool

// IsServerAuthenticated 返回后端是否已通过身份验证
func (mc *MerchantClient) IsServerAuthenticated() bool {
	return serverAuthenticated
}

// resolveServerPublicKey 根据 payServerURL 的域名查找对应环境的公钥。
func resolveServerPublicKey(payServerURL string) (string, error) {
	u, err := url.Parse(payServerURL)
	if err != nil {
		return "", fmt.Errorf("解析 payServerURL 失败: %w", err)
	}
	host := u.Hostname() // 去掉端口号

	// 精确匹配
	if pubKey, ok := serverPublicKeys[host]; ok {
		return pubKey, nil
	}

	// localhost 兼容: 127.0.0.1 等同于 localhost
	if host == "127.0.0.1" {
		if pubKey, ok := serverPublicKeys["localhost"]; ok {
			return pubKey, nil
		}
	}

	// 子域名匹配: 例如 foo.testnet.hashnut.io → testnet.hashnut.io
	for domain, pubKey := range serverPublicKeys {
		if strings.HasSuffix(host, "."+domain) {
			return pubKey, nil
		}
	}

	return "", fmt.Errorf("未找到域名 %s 对应的后端公钥，请检查 serverPublicKeys 配置", host)
}

// AuthenticateServer 执行挑战-响应认证，验证后端持有正确的 Ed25519 私钥。
// 应在 Start() 阶段调用，验证失败则不应继续 MPC 操作。
func (mc *MerchantClient) AuthenticateServer(ctx context.Context) error {
	serverAuthenticated = false

	// 根据 payServerURL 域名查找对应环境的公钥
	expectedPubKeyHex, err := resolveServerPublicKey(mc.payServerURL)
	if err != nil {
		fmt.Printf("[ServerAuth] %v，跳过认证\n", err)
		serverAuthenticated = true // 未配置公钥的环境允许跳过
		return nil
	}

	// 解析公钥
	serverPubKey, err := hex.DecodeString(expectedPubKeyHex)
	if err != nil || len(serverPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("内置的后端公钥无效: %s", expectedPubKeyHex)
	}

	// 1. 生成随机 clientNonce
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("生成 nonce 失败: %w", err)
	}
	clientNonce := hex.EncodeToString(nonceBytes)

	// 2. 发送挑战请求
	reqBody, _ := json.Marshal(challengeRequest{ClientNonce: clientNonce})
	respData, err := mc.doRawPost(ctx, "/api/v4.0.0/mpc/challenge", reqBody)
	if err != nil {
		return fmt.Errorf("挑战请求失败: %w", err)
	}

	var resp challengeResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("解析挑战响应失败: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("后端挑战错误: %s", resp.Error)
	}

	// 3. 验证公钥指纹匹配
	if resp.PublicKey != expectedPubKeyHex {
		return fmt.Errorf("后端公钥不匹配: 期望=%s, 实际=%s（可能遭遇中间人攻击）", expectedPubKeyHex, resp.PublicKey)
	}

	// 4. 验证时间戳有效（防重放）
	timestampMs, err := resp.Timestamp.Int64()
	if err != nil {
		return fmt.Errorf("解析时间戳失败: %w", err)
	}
	serverTime := time.UnixMilli(timestampMs)
	if math.Abs(float64(time.Since(serverTime))) > float64(challengeMaxAge) {
		return fmt.Errorf("挑战响应时间戳过期: %v（可能遭遇重放攻击）", serverTime)
	}

	// 5. 重建签名消息并验证 Ed25519 签名
	message := clientNonce + resp.ServerNonce + resp.Timestamp.String()
	signature, err := hex.DecodeString(resp.Signature)
	if err != nil {
		return fmt.Errorf("解析签名失败: %w", err)
	}

	if !ed25519.Verify(serverPubKey, []byte(message), signature) {
		return fmt.Errorf("后端签名验证失败（后端身份不可信，可能遭遇域名劫持）")
	}

	serverAuthenticated = true
	fmt.Println("[ServerAuth] 后端身份验证通过")
	return nil
}

// doRawPost 发送原始 POST 请求（不带商户签名，用于挑战认证）
func (mc *MerchantClient) doRawPost(ctx context.Context, urlPath string, body []byte) ([]byte, error) {
	url := mc.payServerURL + urlPath

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := mc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
