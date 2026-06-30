package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hashnut-mpc-client/client/message"
	"hashnut-mpc-client/model"
	"hashnut-mpc-client/util/tx_util"
	"io"
	"net/http"

	"github.com/ethereum/go-ethereum/crypto"
)

// SignTxInfo 包含 sign 端点需要的额外字段
type SignTxInfo struct {
	SignerAddress string // 签名地址
	RawTxData     string // 未签名的原始交易 hex
	MessageHash   string // 交易 hash hex
}

func (mc *MerchantClient) doSignedRequest(ctx context.Context, urlPath, method string, mpcMsg message.MessageContent, sid, chain, splitterWallet string) (json.RawMessage, error) {
	return mc.doSignedRequestWithTx(ctx, urlPath, method, mpcMsg, sid, chain, splitterWallet, nil)
}

// doSignedRequestWithTx 发送带 sign 交易信息的请求（sign 端点使用）
func (mc *MerchantClient) doSignedRequestWithTx(ctx context.Context, urlPath, method string, mpcMsg message.MessageContent, sid, chain, splitterWallet string, txInfo *SignTxInfo) (json.RawMessage, error) {
	walletCtx := mc.walletMgr.GetWalletCtx()
	body, err := mc.createRequestBodyWithTx(
		chain,
		walletCtx.Address,
		splitterWallet,
		sid,
		walletCtx.Address,
		method,
		mpcMsg,
		txInfo,
	)
	if err != nil {
		return nil, fmt.Errorf("创建请求体失败: %w", err)
	}

	sign, hash, err := mc.signWithMerchantKey(chain, body)
	if err != nil {
		return nil, fmt.Errorf("签名失败: %w", err)
	}

	url := mc.payServerURL + urlPath
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("sign", sign)
	req.Header.Set("hash", hash)

	resp, err := mc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	var payResp model.BaseRsp
	if err := json.Unmarshal(respBody, &payResp); err != nil {
		return nil, fmt.Errorf("解析Pay Server响应失败: %w", err)
	}
	if payResp.Code != 0 {
		return nil, fmt.Errorf("Pay Server错误 [%d]: %s", payResp.Code, payResp.Msg)
	}

	return payResp.Data, nil
}

func (mc *MerchantClient) doPlainRequest(ctx context.Context, urlPath string, reqBody interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("序列化请求体失败: %w", err)
	}

	url := mc.payServerURL + urlPath
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := mc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	var payResp model.BaseRsp
	if err := json.Unmarshal(respBody, &payResp); err != nil {
		return nil, fmt.Errorf("解析Pay Server响应失败: %w", err)
	}
	if payResp.Code != 0 {
		return nil, fmt.Errorf("Pay Server错误 [%d]: %s", payResp.Code, payResp.Msg)
	}

	return payResp.Data, nil
}

func (mc *MerchantClient) doSignedJSONRequest(ctx context.Context, urlPath string, reqBody map[string]interface{}) (json.RawMessage, error) {
	walletCtx := mc.walletMgr.GetWalletCtx()
	if _, ok := reqBody["chain"]; !ok {
		reqBody["chain"] = walletCtx.Chain
	}
	if _, ok := reqBody["merchantAddress"]; !ok {
		reqBody["merchantAddress"] = walletCtx.Address
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("序列化请求体失败: %w", err)
	}

	sign, hash, err := mc.signWithMerchantKey(fmt.Sprintf("%v", reqBody["chain"]), body)
	if err != nil {
		return nil, fmt.Errorf("签名失败: %w", err)
	}

	url := mc.payServerURL + urlPath
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("sign", sign)
	req.Header.Set("hash", hash)

	resp, err := mc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	var payResp model.BaseRsp
	if err := json.Unmarshal(respBody, &payResp); err != nil {
		return nil, fmt.Errorf("解析Pay Server响应失败: %w", err)
	}
	if payResp.Code != 0 {
		return nil, fmt.Errorf("Pay Server错误 [%d]: %s", payResp.Code, payResp.Msg)
	}
	return payResp.Data, nil
}

// doGetRequest 发送 GET 请求到 payment 后端（不需要签名）
func (mc *MerchantClient) doGetRequest(ctx context.Context, urlPath string) (json.RawMessage, error) {
	url := mc.payServerURL + urlPath
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}
	resp, err := mc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}
	var payResp model.BaseRsp
	if err := json.Unmarshal(respBody, &payResp); err != nil {
		return nil, fmt.Errorf("解析Pay Server响应失败: %w", err)
	}
	if payResp.Code != 0 {
		return nil, fmt.Errorf("Pay Server错误 [%d]: %s", payResp.Code, payResp.Msg)
	}
	return payResp.Data, nil
}

// doPostJSON 发送不需要签名的 POST JSON 请求
func (mc *MerchantClient) doPostJSON(ctx context.Context, urlPath string, body map[string]interface{}) (json.RawMessage, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	url := mc.payServerURL + urlPath
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := mc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s (url=%s)", resp.StatusCode, string(respBody), urlPath)
	}
	if len(respBody) == 0 {
		return nil, fmt.Errorf("空响应 (url=%s)", urlPath)
	}
	var payResp model.BaseRsp
	if err := json.Unmarshal(respBody, &payResp); err != nil {
		return nil, fmt.Errorf("解析响应失败 (url=%s body=%s): %w", urlPath, string(respBody), err)
	}
	if payResp.Code != 0 {
		return nil, fmt.Errorf("Server错误 [%d]: %s", payResp.Code, payResp.Msg)
	}
	return payResp.Data, nil
}

// 创建HTTP请求体（紧凑格式，用于哈希计算）
func (mc *MerchantClient) createRequestBody(chain, merchant, splitWallet, sid, uid, method string, mpcMsg message.MessageContent) ([]byte, error) {
	return mc.createRequestBodyWithTx(chain, merchant, splitWallet, sid, uid, method, mpcMsg, nil)
}

// createRequestBodyWithTx 创建请求体，可选带 sign 交易信息
func (mc *MerchantClient) createRequestBodyWithTx(chain, merchant, splitWallet, sid, uid, method string, mpcMsg message.MessageContent, txInfo *SignTxInfo) ([]byte, error) {
	reqBody := MerchantReqBody{
		Chain:       chain,
		Merchant:    merchant,
		SplitWallet: splitWallet,
		SID:         sid,
		UID:         uid,
		Method:      method,
	}

	if txInfo != nil {
		reqBody.SignerAddress = txInfo.SignerAddress
		reqBody.RawTxData = txInfo.RawTxData
		reqBody.MessageHash = txInfo.MessageHash
	}

	if mpcMsg != nil {
		mpc, err := mc.createMpcMessage(mpcMsg)
		if err != nil {
			return nil, err
		}
		reqBody.MpcMsg = mpc
	}

	return json.Marshal(reqBody)
}

// 创建MpcMessage的函数
func (mc *MerchantClient) createMpcMessage(content message.MessageContent) (message.MpcMessage, error) {
	if err := content.Validate(); err != nil {
		return message.MpcMessage{}, err
	}
	contentJSON, err := json.Marshal(content)
	if err != nil {
		return message.MpcMessage{}, fmt.Errorf("failed to marshal message content: %v", err)
	}

	return message.MpcMessage{
		Type:          content.Type(),
		Content:       contentJSON,
		ParsedContent: content,
	}, nil
}

// signWithMerchantKey 使用商户私钥来签名
func (mc *MerchantClient) signWithMerchantKey(chain string, body []byte) (string, string, error) {
	walletCtx := mc.walletMgr.GetWalletCtx()
	if walletCtx == nil || walletCtx.PrivateKey == nil {
		return "", "", fmt.Errorf("钱包未加载，请先导入私钥")
	}
	if tx_util.IsEvm(chain) {
		hash := crypto.Keccak256(body)
		hashHex := hex.EncodeToString(hash)
		signature, err := crypto.Sign(hash, walletCtx.PrivateKey)
		if err != nil {
			return "", "", err
		}
		signatureHex := hex.EncodeToString(signature)
		return signatureHex, hashHex, nil
	}

	if tx_util.IsTron(chain) {
		h256h := sha256.New()
		h256h.Write(body)
		hash := h256h.Sum(nil)
		hashHex := hex.EncodeToString(hash)
		signature, err := crypto.Sign(hash, walletCtx.PrivateKey)
		if err != nil {
			return "", "", err
		}
		signatureHex := hex.EncodeToString(signature)
		return signatureHex, hashHex, nil
	}

	return "", "", fmt.Errorf("不支持的链: %s", chain)
}
