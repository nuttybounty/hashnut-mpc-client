package tx_util

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/crypto"
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/fbsobreira/gotron-sdk/pkg/address"
	"github.com/fbsobreira/gotron-sdk/pkg/client"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/api"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

const (
	fullNodeApiKey      = "b38f1241-7e31-4319-a9f5-37d0eb8a6b3f" // 可选，波场节点 API Key
	defaultTronGrpcPort = ":50051"
)

// ContractCallParams 封装合约调用所需的参数
type ContractCallParams struct {
	ContractAddress string        // 合约地址
	Method          string        // 方法签名，如 "transfer(address,uint256)"
	Parameters      []interface{} // 参数列表，用于构建 data
	Data            string        // 如果预先构造好了 data，可直接使用，或者直接使用 Data 字段，但为了灵活性，保留 Parameters
}

// NewTransferParams 创建 transfer 调用的参数
func NewTransferParams(tokenAddr, toAddr string, amount *big.Int) *ContractCallParams {
	return &ContractCallParams{
		ContractAddress: tokenAddr,
		Method:          "transfer(address,uint256)",
		Parameters:      []interface{}{toAddr, amount},
	}
}

// NewApproveParams 创建 approve 调用的参数
func NewApproveParams(tokenAddr, spenderAddr string, amount *big.Int) *ContractCallParams {
	return &ContractCallParams{
		ContractAddress: tokenAddr,
		Method:          "approve(address,uint256)",
		Parameters:      []interface{}{spenderAddr, amount},
	}
}

// NewTransferFromParams 创建 transferFrom 调用的参数
func NewTransferFromParams(tokenAddr, fromAddr, toAddr string, amount *big.Int) *ContractCallParams {
	return &ContractCallParams{
		ContractAddress: tokenAddr,
		Method:          "transferFrom(address,address,uint256)",
		Parameters:      []interface{}{fromAddr, toAddr, amount},
	}
}

// BuildData 根据参数构建 JSON 格式的 data 字符串
func (p *ContractCallParams) BuildData() string {
	if p.Data != "" {
		return p.Data
	}
	// 简单构造：假设 Parameters 顺序对应方法参数，将每个参数转换为 JSON 字段
	// 注意：这里需要更严谨的 ABI 编码，但 SDK 内部可能期望 JSON 格式
	// 实际使用中，可能需要使用 abi 包进行编码，此处简化
	var data string
	// 示例实现，实际可能需要循环构建
	// 此处仅作示意，建议根据实际 SDK 要求实现
	return data
}

// tronTokenAuth QuickNode 用: TLS + x-token header
type tronTokenAuth struct {
	token string
}

func (a *tronTokenAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"x-token": a.token}, nil
}

func (a *tronTokenAuth) RequireTransportSecurity() bool {
	return false
}

// tronGridAuth TronGrid 用: plaintext + TRON-PRO-API-KEY header
type tronGridAuth struct {
	apiKey string
}

func (a *tronGridAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"TRON-PRO-API-KEY": a.apiKey}, nil
}

func (a *tronGridAuth) RequireTransportSecurity() bool {
	return false
}

// NewClient 兼容旧调用（无 provider 时按 endpoint 自动推断）
func NewClient(endpoint, apiKey string) (*client.GrpcClient, error) {
	return NewClientWithProvider(endpoint, apiKey, "")
}

// NewClientWithProvider 根据 provider 选择 gRPC 连接方式
// provider: QUICKNODE (TLS + x-token), TRONGRID (plaintext + TRON-PRO-API-KEY), 空则自动推断
func NewClientWithProvider(endpoint, apiKey, provider string) (*client.GrpcClient, error) {
	if !strings.Contains(endpoint, ":") {
		endpoint = endpoint + defaultTronGrpcPort
	}
	provider = strings.ToUpper(provider)
	if provider == "" {
		// 自动推断: quiknode 域名用 QUICKNODE，其他用 TRONGRID
		if strings.Contains(endpoint, "quiknode") || strings.Contains(endpoint, "quicknode") {
			provider = "QUICKNODE"
		} else {
			provider = "TRONGRID"
		}
	}

	var opts []grpc.DialOption
	switch provider {
	case "QUICKNODE":
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(nil)))
		if apiKey != "" {
			opts = append(opts, grpc.WithPerRPCCredentials(&tronTokenAuth{token: apiKey}))
		}
	default: // TRONGRID 及其他
		opts = append(opts, grpc.WithInsecure())
		if apiKey != "" {
			opts = append(opts, grpc.WithPerRPCCredentials(&tronGridAuth{apiKey: apiKey}))
		}
	}

	// 使用 30 秒超时（默认 5 秒在首次 TLS 握手时容易超时）
	c := client.NewGrpcClientWithTimeout(endpoint, 30*time.Second)
	if err := c.Start(opts...); err != nil {
		// 首次连接失败时重试一次
		fmt.Printf("[TronClient] 首次连接失败: %v，重试中...\n", err)
		c = client.NewGrpcClientWithTimeout(endpoint, 30*time.Second)
		if err := c.Start(opts...); err != nil {
			return nil, fmt.Errorf("连接 Tron gRPC 节点失败 (provider=%s): %w", provider, err)
		}
	}
	return c, nil
}

// NewTronGrpcClient 使用标准 insecure gRPC 连接 Tron 节点（不需要 API Key）
func NewTronGrpcClient(endpoint string) (*client.GrpcClient, error) {
	if !strings.Contains(endpoint, ":") {
		endpoint = endpoint + defaultTronGrpcPort
	}
	c := client.NewGrpcClientWithTimeout(endpoint, 30*time.Second)
	if err := c.Start(grpc.WithInsecure()); err != nil {
		fmt.Printf("[TronClient] 首次连接失败: %v，重试中...\n", err)
		c = client.NewGrpcClientWithTimeout(endpoint, 30*time.Second)
		if err := c.Start(grpc.WithInsecure()); err != nil {
			return nil, fmt.Errorf("连接 Tron gRPC 节点失败: %w", err)
		}
	}
	return c, nil
}

// PrivateHexToTronAddress 其他辅助函数保持不变...
func PrivateHexToTronAddress(privateKeyHex string) (address.Address, error) {
	privKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, err
	}
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	return address.BTCECPrivkeyToAddress(privKey), nil
}

func PrivateKeyToTronAddress(key *ecdsa.PrivateKey) (string, error) {
	keyBytes := crypto.FromECDSA(key)
	privKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	return address.BTCECPrivkeyToAddress(privKey).String(), nil
}

// GetTRXBalance 查询账户 TRX 余额（单位：SUN）
func GetTRXBalance(client *client.GrpcClient, addrStr string) (*big.Int, error) {
	addr, err := address.Base58ToAddress(addrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}
	acc, err := client.GetAccount(addr.String())
	if err != nil {
		return nil, fmt.Errorf("get account failed: %w", err)
	}
	return big.NewInt(acc.GetBalance()), nil
}

// GetTRC20Balance 查询 TRC-20 代币余额（如 USDT）
func GetTRC20Balance(client *client.GrpcClient, contractAddr, ownerAddr string) (*big.Int, error) {
	owner, err := address.Base58ToAddress(ownerAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid owner address: %w", err)
	}
	// 构造 balanceOf 调用参数
	method := "balanceOf(address)"
	data := fmt.Sprintf(`[{"address": "%s"}]`, owner.String())

	// 使用 TriggerConstantContract 模拟调用
	// SDK 签名: TriggerConstantContract(from, contractAddress, method, jsonString)
	result, err := client.TriggerConstantContract(
		ownerAddr,    // from (调用者)
		contractAddr, // contractAddress (合约地址)
		method,
		data,
	)
	if err != nil {
		return nil, fmt.Errorf("trigger constant contract failed: %w", err)
	}
	if !result.Result.Result {
		return nil, fmt.Errorf("trigger constant contract failed: %s", result.Result.Message)
	}
	if len(result.ConstantResult) == 0 {
		return nil, fmt.Errorf("no constant result")
	}
	// 解析返回值（通常是一个 32 字节的 big-endian uint256）
	balance := new(big.Int).SetBytes(result.ConstantResult[0])
	return balance, nil
}

// EstimateEnergy 通用能量估算函数
func EstimateEnergy(client *client.GrpcClient, fromAddr string, params *ContractCallParams, callValue int64) (int64, error) {
	// 构建 data
	var data string
	if params.Data != "" {
		data = params.Data
	} else {
		// 需要根据 Parameters 构建 JSON，此处简化，假设有 BuildData 方法
		// 实际应使用 ABI 编码，但 SDK 可能接受 JSON 字符串
		// 建议：若 Parameters 不为空，将其转换为对应格式
		// 这里使用一个简单的辅助函数 buildDataFromParams
		data = buildDataFromParams(params.Method, params.Parameters)
	}
	fmt.Printf("contract address %s\n", params.ContractAddress)
	fmt.Printf("method %s\n", params.Method)
	fmt.Printf("encoded data %s\n", data)
	estimate, err := client.EstimateEnergy(
		fromAddr,
		params.ContractAddress,
		params.Method,
		data,
		callValue,
		"",
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("estimate energy failed: %w", err)
	}
	if !estimate.Result.Result {
		return 0, fmt.Errorf("estimate energy failed: %s", estimate.Result.Message)
	}
	return estimate.EnergyRequired, nil
}

// TriggerContract 通用触发合约函数
func TriggerContract(client *client.GrpcClient, fromAddr string, params *ContractCallParams, feeLimit, callValue int64) (*api.TransactionExtention, error) {
	var data string
	if params.Data != "" {
		data = params.Data
	} else {
		data = buildDataFromParams(params.Method, params.Parameters)
	}

	return client.TriggerContract(
		fromAddr,
		params.ContractAddress,
		params.Method,
		data,
		feeLimit,
		callValue,
		"",
		0,
	)
}

// buildDataFromParams 辅助函数：将方法和参数转换为 SDK 期望的 data 格式
// 这里需要根据实际 SDK 要求实现，可能是 JSON 字符串或 ABI 编码后的 hex
// 此处仅为示例，实际实现需参考 SDK 文档
func buildDataFromParams(method string, params []interface{}) string {
	// 示例：简单构造 JSON 数组字符串
	// 注意：这不够严谨，实际可能需要使用 abi 包进行编码
	var parts []string
	for _, p := range params {
		switch v := p.(type) {
		case string:
			parts = append(parts, fmt.Sprintf(`{"address": "%s"}`, v))
		case *big.Int:
			parts = append(parts, fmt.Sprintf(`{"uint256": "%s"}`, v.String()))
		default:
			parts = append(parts, fmt.Sprintf(`{"unknown": "%v"}`, v))
		}
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// CreateTronTransferRaw 通用创建交易原始数据
func CreateTronTransferRaw(client *client.GrpcClient, fromAddrStr string, params *ContractCallParams) (*api.TransactionExtention, []byte, error) {
	// 估算费用
	energyRequired, err := EstimateEnergy(client, fromAddrStr, params, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("energy estimation failed: %v", err)
	}
	// 通用的 calculateFeeLimit 函数
	feeLimit := calculateFeeLimit(energyRequired)

	// 构建原始交易
	rawTx, err := TriggerContract(client, fromAddrStr, params, feeLimit, 0)
	if err != nil {
		return nil, nil, err
	}
	// 获取原始交易数据（feeLimit 已修改，需要重新序列化）
	rawData, err := proto.Marshal(rawTx.Transaction.GetRawData())
	if err != nil {
		return nil, nil, err
	}
	// 对原始交易数据做hash
	hashArr := sha256.Sum256(rawData)
	// feeLimit 修改后 RawData 变化，必须更新 Txid（否则与链上实际 txid 不一致）
	rawTx.Txid = hashArr[:]
	return rawTx, hashArr[:], nil
}

// defaultEnergyPrice 能量单价兜底值（sun/energy），仅在链上查询失败时使用。
const defaultEnergyPrice = int64(420)

// GetEnergyPrice 查询链上当前能量单价（sun/energy）。
// 返回格式 "timestamp:price,timestamp:price,..."，取最后一个值。
func GetEnergyPrice(c *client.GrpcClient) int64 {
	resp, err := c.GetEnergyPrices()
	if err != nil || resp == nil || resp.Prices == "" {
		return defaultEnergyPrice
	}
	// 取最后一段 "timestamp:price"
	parts := strings.Split(resp.Prices, ",")
	last := parts[len(parts)-1]
	kv := strings.Split(last, ":")
	if len(kv) != 2 {
		return defaultEnergyPrice
	}
	price, err := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64)
	if err != nil || price <= 0 {
		return defaultEnergyPrice
	}
	return price
}

// calculateFeeLimit 根据能量估算计算 feeLimit（交易上限）。
// feeLimit 只是上限，实际消耗多少扣多少。
func calculateFeeLimit(energyRequired int64) int64 {
	return calculateFeeLimitWithPrice(energyRequired, defaultEnergyPrice)
}

// CalculateFeeLimitWithClient 使用链上实时能量单价计算 feeLimit。
func CalculateFeeLimitWithClient(c *client.GrpcClient, energyRequired int64) int64 {
	return calculateFeeLimitWithPrice(energyRequired, GetEnergyPrice(c))
}

func calculateFeeLimitWithPrice(energyRequired, energyPrice int64) int64 {
	if energyRequired == 0 {
		return 30_000_000 // 默认 30 TRX
	}
	totalFee := energyRequired * energyPrice
	totalFee += 500_000 // 带宽缓冲 0.5 TRX
	// 1.3 倍缓冲
	return totalFee * 13 / 10
}

// EstimateTronContractFee 估算 Tron 合约调用所需 TRX（单位 SUN）。
// 查询链上实时能量单价，返回 1.2 倍缓冲后的费用，用于 TRX 预分配。
func EstimateTronContractFee(c *client.GrpcClient, fromAddr string, params *ContractCallParams) (int64, error) {
	energy, err := EstimateEnergy(c, fromAddr, params, 0)
	if err != nil {
		return 0, err
	}
	price := GetEnergyPrice(c)
	fee := energy * price
	fee += 500_000 // 带宽缓冲 0.5 TRX
	return fee * 6 / 5, nil // 1.2 倍缓冲
}

// GetTRC20Decimals 查询 TRC20 token 的 decimals
func GetTRC20Decimals(c *client.GrpcClient, contractAddr, ownerAddr string) (uint8, error) {
	// SDK 签名: TriggerConstantContract(from, contractAddress, method, jsonString)
	result, err := c.TriggerConstantContract(
		ownerAddr,    // from
		contractAddr, // contractAddress
		"decimals()",
		"[]",
	)
	if err != nil {
		return 0, fmt.Errorf("查询 TRC20 decimals 失败: %w", err)
	}
	if !result.Result.Result {
		return 0, fmt.Errorf("查询 TRC20 decimals 失败: %s", result.Result.Message)
	}
	if len(result.ConstantResult) == 0 {
		return 0, fmt.Errorf("TRC20 decimals 返回为空")
	}
	decimals := new(big.Int).SetBytes(result.ConstantResult[0])
	return uint8(decimals.Uint64()), nil
}

// ConvertTRC20Amount 根据 decimals 将用户输入金额转为最小单位
func ConvertTRC20Amount(amountStr string, decimals uint8) (*big.Int, error) {
	return ConvertToWei(amountStr, decimals)
}

// -------------------- V4 合约交互方法 --------------------

// NewActivateParams 创建 SplitWalletV4.activate(manager, proxyAdmin) 调用参数
func NewActivateParams(splitterAddr, managerAddr, proxyAdminAddr string) *ContractCallParams {
	return &ContractCallParams{
		ContractAddress: splitterAddr,
		Method:          "activate(address,address)",
		Parameters:      []interface{}{managerAddr, proxyAdminAddr},
	}
}

// NewAddReceiptWalletsParams 创建 SplitWalletV4.addReceiptWallets(token, wallets, minAllowance) 调用参数
func NewAddReceiptWalletsParams(splitterAddr, tokenAddr string, walletAddrs []string, minAllowance *big.Int) *ContractCallParams {
	// SDK 期望 JSON 格式的参数
	walletsJSON := "["
	for i, w := range walletAddrs {
		if i > 0 {
			walletsJSON += ","
		}
		walletsJSON += fmt.Sprintf(`"%s"`, w)
	}
	walletsJSON += "]"

	data := fmt.Sprintf(`[{"address":"%s"},{"address[]":%s},{"uint256":"%s"}]`,
		tokenAddr, walletsJSON, minAllowance.String())

	return &ContractCallParams{
		ContractAddress: splitterAddr,
		Method:          "addReceiptWallets(address,address[],uint256)",
		Data:            data,
	}
}

// ---- 使用预编码 ABI calldata 的 Tron 合约调用 (绕过 gotron-sdk 不支持 uint256[] 的限制) ----

// tronAddrToEvm 将 Tron 地址（base58 或 0x）转换为 EVM common.Address
func tronAddrToEvm(addr string) (eth_common.Address, error) {
	if strings.HasPrefix(addr, "0x") {
		return eth_common.HexToAddress(addr), nil
	}
	ethAddr, err := TronToEth(addr)
	if err != nil {
		return eth_common.Address{}, err
	}
	return eth_common.HexToAddress(ethAddr), nil
}

// triggerContractWithData 使用预编码 ABI calldata 触发 Tron 合约（不依赖 SDK 的参数解析）
func triggerContractWithData(c *client.GrpcClient, fromAddr, contractAddr string, calldata []byte, feeLimit, callValue int64) (*api.TransactionExtention, error) {
	fromAddress, err := address.Base58ToAddress(fromAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid from address: %w", err)
	}
	contractAddress, err := address.Base58ToAddress(contractAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid contract address: %w", err)
	}

	ct := &core.TriggerSmartContract{
		OwnerAddress:    fromAddress.Bytes(),
		ContractAddress: contractAddress.Bytes(),
		Data:            calldata,
	}
	if callValue > 0 {
		ct.CallValue = callValue
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := c.Client.TriggerContract(ctx, ct)
	if err != nil {
		return nil, err
	}
	if tx.Result.Code > 0 {
		return tx, fmt.Errorf("%s", tx.Result.Message)
	}
	if feeLimit > 0 {
		tx.Transaction.RawData.FeeLimit = feeLimit
	}
	return tx, nil
}

// estimateEnergyWithData 使用预编码 ABI calldata 估算能量
func estimateEnergyWithData(c *client.GrpcClient, fromAddr, contractAddr string, calldata []byte) (int64, error) {
	fromAddress, err := address.Base58ToAddress(fromAddr)
	if err != nil {
		return 0, fmt.Errorf("invalid from address: %w", err)
	}
	contractAddress, err := address.Base58ToAddress(contractAddr)
	if err != nil {
		return 0, fmt.Errorf("invalid contract address: %w", err)
	}

	ct := &core.TriggerSmartContract{
		OwnerAddress:    fromAddress.Bytes(),
		ContractAddress: contractAddress.Bytes(),
		Data:            calldata,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	estimate, err := c.Client.EstimateEnergy(ctx, ct)
	if err != nil {
		return 0, fmt.Errorf("estimate energy failed: %w", err)
	}
	if !estimate.Result.Result {
		return 0, fmt.Errorf("estimate energy failed: %s", estimate.Result.Message)
	}
	return estimate.EnergyRequired, nil
}

// CreateTronTxWithData 使用预编码 ABI calldata 创建 Tron 交易（含能量估算和签名哈希）
func CreateTronTxWithData(c *client.GrpcClient, fromAddr, contractAddr string, calldata []byte) (*api.TransactionExtention, []byte, error) {
	// 确保地址是 base58 格式
	if strings.HasPrefix(fromAddr, "0x") {
		if addr, err := EthToTron(fromAddr); err == nil {
			fromAddr = addr
		}
	}
	if strings.HasPrefix(contractAddr, "0x") {
		if addr, err := EthToTron(contractAddr); err == nil {
			contractAddr = addr
		}
	}

	energyRequired, err := estimateEnergyWithData(c, fromAddr, contractAddr, calldata)
	if err != nil {
		return nil, nil, fmt.Errorf("energy estimation failed: %v", err)
	}
	feeLimit := calculateFeeLimit(energyRequired)

	rawTx, err := triggerContractWithData(c, fromAddr, contractAddr, calldata, feeLimit, 0)
	if err != nil {
		return nil, nil, err
	}

	rawData, err := proto.Marshal(rawTx.Transaction.GetRawData())
	if err != nil {
		return nil, nil, err
	}
	hashArr := sha256.Sum256(rawData)
	// feeLimit 修改后 RawData 变化，必须更新 Txid（否则与链上实际 txid 不一致）
	rawTx.Txid = hashArr[:]
	return rawTx, hashArr[:], nil
}

// BuildTronClaimData 使用 go-ethereum ABI 构建 claimReceiptERC20Tokens 的 calldata
func BuildTronClaimData(tokenAddrs []string, minAmounts []*big.Int, startIndex, endIndexExcluded uint64) ([]byte, error) {
	tokens := make([]eth_common.Address, len(tokenAddrs))
	for i, addr := range tokenAddrs {
		evmAddr, err := tronAddrToEvm(addr)
		if err != nil {
			return nil, fmt.Errorf("convert token address %s failed: %w", addr, err)
		}
		tokens[i] = evmAddr
	}
	return BuildClaimReceiptERC20TokensData(tokens, minAmounts, new(big.Int).SetUint64(startIndex), new(big.Int).SetUint64(endIndexExcluded))
}

// BuildTronReleaseData 使用 go-ethereum ABI 构建 releaseERC20Tokens 的 calldata
func BuildTronReleaseData(tokenAddrs []string, account string) ([]byte, error) {
	tokens := make([]eth_common.Address, len(tokenAddrs))
	for i, addr := range tokenAddrs {
		evmAddr, err := tronAddrToEvm(addr)
		if err != nil {
			return nil, fmt.Errorf("convert token address %s failed: %w", addr, err)
		}
		tokens[i] = evmAddr
	}
	accountAddr, err := tronAddrToEvm(account)
	if err != nil {
		return nil, fmt.Errorf("convert account address %s failed: %w", account, err)
	}
	return BuildReleaseERC20TokensData(tokens, accountAddr)
}

// GetTronReceiptWalletCount 查询 SplitWalletV4 的 receipt wallet 总数 (Tron)
func GetTronReceiptWalletCount(c *client.GrpcClient, splitterAddr, callerAddr string) (uint64, error) {
	if strings.HasPrefix(splitterAddr, "0x") {
		if addr, err := EthToTron(splitterAddr); err == nil {
			splitterAddr = addr
		}
	}
	if strings.HasPrefix(callerAddr, "0x") {
		if addr, err := EthToTron(callerAddr); err == nil {
			callerAddr = addr
		}
	}

	result, err := c.TriggerConstantContract(callerAddr, splitterAddr, "getReceiptWalletCount()", "[]")
	if err != nil {
		return 0, fmt.Errorf("查询 receiptWalletCount 失败: %w", err)
	}
	if !result.Result.Result {
		return 0, fmt.Errorf("查询 receiptWalletCount 失败: %s", result.Result.Message)
	}
	if len(result.ConstantResult) == 0 {
		return 0, fmt.Errorf("receiptWalletCount 返回为空")
	}
	count := new(big.Int).SetBytes(result.ConstantResult[0])
	return count.Uint64(), nil
}

// GetTronBalanceERC20 查询 payee 在 split wallet 中某 token 的可提取余额 (Tron)
func GetTronBalanceERC20(c *client.GrpcClient, splitterAddr, tokenAddr, accountAddr, callerAddr string) (*big.Int, error) {
	if strings.HasPrefix(splitterAddr, "0x") {
		if addr, err := EthToTron(splitterAddr); err == nil {
			splitterAddr = addr
		}
	}
	if strings.HasPrefix(callerAddr, "0x") {
		if addr, err := EthToTron(callerAddr); err == nil {
			callerAddr = addr
		}
	}

	data := fmt.Sprintf(`[{"address":"%s"},{"address":"%s"}]`, tokenAddr, accountAddr)
	result, err := c.TriggerConstantContract(callerAddr, splitterAddr, "balanceERC20(address,address)", data)
	if err != nil {
		return nil, fmt.Errorf("查询 balanceERC20 失败: %w", err)
	}
	if !result.Result.Result {
		return nil, fmt.Errorf("查询 balanceERC20 失败: %s", result.Result.Message)
	}
	if len(result.ConstantResult) == 0 {
		return nil, fmt.Errorf("balanceERC20 返回为空")
	}
	return new(big.Int).SetBytes(result.ConstantResult[0]), nil
}

// GetTronAllReceiptWallets 查询合约中所有注册的 receipt wallet 地址 (Tron)
func GetTronAllReceiptWallets(c *client.GrpcClient, splitterAddr, callerAddr string) ([]string, error) {
	if strings.HasPrefix(splitterAddr, "0x") {
		if addr, err := EthToTron(splitterAddr); err == nil {
			splitterAddr = addr
		}
	}
	if strings.HasPrefix(callerAddr, "0x") {
		if addr, err := EthToTron(callerAddr); err == nil {
			callerAddr = addr
		}
	}

	result, err := c.TriggerConstantContract(callerAddr, splitterAddr, "getAllReceiptWallets()", "[]")
	if err != nil {
		return nil, fmt.Errorf("查询 getAllReceiptWallets 失败: %w", err)
	}
	if !result.Result.Result {
		return nil, fmt.Errorf("查询 getAllReceiptWallets 失败: %s", result.Result.Message)
	}
	if len(result.ConstantResult) == 0 {
		return nil, fmt.Errorf("getAllReceiptWallets 返回为空")
	}

	// 解析 ABI 编码的 address[] 返回值
	data := result.ConstantResult[0]
	if len(data) < 64 {
		return nil, nil // 空数组
	}
	// 前 32 字节是 offset，接下来 32 字节是数组长度
	length := new(big.Int).SetBytes(data[32:64]).Int64()
	if length == 0 {
		return nil, nil
	}

	var wallets []string
	for i := int64(0); i < length; i++ {
		start := 64 + i*32
		if start+32 > int64(len(data)) {
			break
		}
		// 地址在 32 字节中右对齐，取后 20 字节，加 41 前缀转 Tron 地址
		addrBytes := data[start+12 : start+32]
		tronHex := "41" + hex.EncodeToString(addrBytes)
		wallets = append(wallets, address.HexToAddress(tronHex).String())
	}
	return wallets, nil
}

// GetTronCollectableBalance 查询所有 receipt wallet 中指定 token 的可归集余额总和 (Tron)
func GetTronCollectableBalance(c *client.GrpcClient, splitterAddr, tokenAddr, callerAddr string) (*big.Int, error) {
	wallets, err := GetTronAllReceiptWallets(c, splitterAddr, callerAddr)
	if err != nil {
		return nil, err
	}
	total := big.NewInt(0)
	for _, wallet := range wallets {
		balance, err := GetTRC20Balance(c, tokenAddr, wallet)
		if err != nil {
			continue
		}
		total.Add(total, balance)
	}
	return total, nil
}

// SimulateTronClaimReceiptERC20Tokens 模拟调用 claimReceiptERC20Tokens，返回每种 token 的可归集金额
// 使用 TriggerConstantContract 不消耗能量
func SimulateTronClaimReceiptERC20Tokens(c *client.GrpcClient, callerAddr, splitterAddr string, tokenAddrs []string, minAmounts []*big.Int, startIndex, endIndexExcluded uint64) ([]*big.Int, error) {
	// 使用 go-ethereum ABI 编码 calldata
	calldata, err := BuildTronClaimData(tokenAddrs, minAmounts, startIndex, endIndexExcluded)
	if err != nil {
		return nil, fmt.Errorf("build claim calldata failed: %w", err)
	}

	// 地址转换
	if strings.HasPrefix(callerAddr, "0x") {
		if addr, err := EthToTron(callerAddr); err == nil {
			callerAddr = addr
		}
	}
	if strings.HasPrefix(splitterAddr, "0x") {
		if addr, err := EthToTron(splitterAddr); err == nil {
			splitterAddr = addr
		}
	}

	fromAddress, err := address.Base58ToAddress(callerAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid caller address: %w", err)
	}
	contractAddress, err := address.Base58ToAddress(splitterAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid contract address: %w", err)
	}

	ct := &core.TriggerSmartContract{
		OwnerAddress:    fromAddress.Bytes(),
		ContractAddress: contractAddress.Bytes(),
		Data:            calldata,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := c.Client.TriggerConstantContract(ctx, ct)
	if err != nil {
		return nil, fmt.Errorf("simulate claim failed: %w", err)
	}
	if !result.Result.Result {
		return nil, fmt.Errorf("simulate claim failed: %s", result.Result.Message)
	}
	if len(result.ConstantResult) == 0 {
		return nil, fmt.Errorf("simulate claim: empty result")
	}

	// 解析 ABI 编码的 uint256[] 返回值
	values, err := splitWalletV4ParsedABI.Unpack("claimReceiptERC20Tokens", result.ConstantResult[0])
	if err != nil {
		return nil, fmt.Errorf("unpack simulate result failed: %w", err)
	}
	if len(values) != 1 {
		return nil, fmt.Errorf("unexpected result size %d", len(values))
	}
	claimed, ok := values[0].([]*big.Int)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", values[0])
	}
	return claimed, nil
}

// QueryTronReceiptNativeBalance 查询指定范围内 receipt wallet 的原生代币 (TRX) 可归集余额
func QueryTronReceiptNativeBalance(c *client.GrpcClient, callerAddr, splitterAddr string, minAmount *big.Int, startIndex, endIndexExcluded uint64) (*big.Int, uint64, error) {
	// 使用 go-ethereum ABI 编码 calldata
	calldata, err := splitWalletV4ParsedABI.Pack("queryReceiptNativeBalance", minAmount, new(big.Int).SetUint64(startIndex), new(big.Int).SetUint64(endIndexExcluded))
	if err != nil {
		return nil, 0, fmt.Errorf("pack queryReceiptNativeBalance failed: %w", err)
	}

	if strings.HasPrefix(callerAddr, "0x") {
		if addr, err := EthToTron(callerAddr); err == nil {
			callerAddr = addr
		}
	}
	if strings.HasPrefix(splitterAddr, "0x") {
		if addr, err := EthToTron(splitterAddr); err == nil {
			splitterAddr = addr
		}
	}

	fromAddress, err := address.Base58ToAddress(callerAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid caller address: %w", err)
	}
	contractAddress, err := address.Base58ToAddress(splitterAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid contract address: %w", err)
	}

	ct := &core.TriggerSmartContract{
		OwnerAddress:    fromAddress.Bytes(),
		ContractAddress: contractAddress.Bytes(),
		Data:            calldata,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := c.Client.TriggerConstantContract(ctx, ct)
	if err != nil {
		return nil, 0, fmt.Errorf("query native balance failed: %w", err)
	}
	if !result.Result.Result {
		return nil, 0, fmt.Errorf("query native balance failed: %s", result.Result.Message)
	}
	if len(result.ConstantResult) == 0 {
		return nil, 0, fmt.Errorf("query native balance: empty result")
	}

	values, err := splitWalletV4ParsedABI.Unpack("queryReceiptNativeBalance", result.ConstantResult[0])
	if err != nil {
		return nil, 0, fmt.Errorf("unpack result failed: %w", err)
	}
	if len(values) != 2 {
		return nil, 0, fmt.Errorf("unexpected result size %d", len(values))
	}
	totalBalance := values[0].(*big.Int)
	walletCount := values[1].(*big.Int)
	return totalBalance, walletCount.Uint64(), nil
}

// GetTronSplitWalletProxyAdmin 查询 SplitWalletV4 的 proxyAdmin 地址
func GetTronSplitWalletProxyAdmin(c *client.GrpcClient, splitterAddr, callerAddr string) (string, error) {
	// 确保地址是 base58 格式
	if strings.HasPrefix(splitterAddr, "0x") {
		if addr, err := EthToTron(splitterAddr); err == nil {
			splitterAddr = addr
		}
	} else if strings.HasPrefix(splitterAddr, "41") && len(splitterAddr) == 42 {
		splitterAddr = address.HexToAddress(splitterAddr).String()
	}
	if strings.HasPrefix(callerAddr, "0x") {
		if addr, err := EthToTron(callerAddr); err == nil {
			callerAddr = addr
		}
	} else if strings.HasPrefix(callerAddr, "41") && len(callerAddr) == 42 {
		callerAddr = address.HexToAddress(callerAddr).String()
	}
	fmt.Printf("GetTronSplitWalletProxyAdmin: splitter=%s, caller=%s\n", splitterAddr, callerAddr)

	result, err := c.TriggerConstantContract(
		callerAddr,    // from (调用者)
		splitterAddr,  // contractAddress (合约地址)
		"getProxyAdmin()",
		"[]",
	)
	if err != nil {
		return "", fmt.Errorf("查询 proxyAdmin 失败: %w", err)
	}
	if !result.Result.Result {
		return "", fmt.Errorf("查询 proxyAdmin 失败: %s", result.Result.Message)
	}
	if len(result.ConstantResult) == 0 || len(result.ConstantResult[0]) < 32 {
		return "", fmt.Errorf("proxyAdmin 返回为空")
	}
	// 返回结果是 32 字节 ABI 编码的地址，前 12 字节是 0 填充
	addrBytes := result.ConstantResult[0][12:32]
	tronHex := "41" + hex.EncodeToString(addrBytes)
	return address.HexToAddress(tronHex).String(), nil
}

// BuildTronSweepTx 构建 TRX 原生转账交易（回收 gas）
func BuildTronSweepTx(c *client.GrpcClient, fromAddr, toAddr string) (*api.TransactionExtention, int64, error) {
	balance, err := GetTRXBalance(c, fromAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("获取余额失败: %w", err)
	}

	// 预留带宽费用 (约 0.3 TRX = 300000 SUN)
	bandwidthFee := int64(300_000)
	sendAmount := balance.Int64() - bandwidthFee
	if sendAmount <= 0 {
		return nil, 0, fmt.Errorf("余额不足以支付带宽费用")
	}

	from, err := address.Base58ToAddress(fromAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid from address: %w", err)
	}
	to, err := address.Base58ToAddress(toAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid to address: %w", err)
	}

	tx, err := c.Transfer(from.String(), to.String(), sendAmount)
	if err != nil {
		return nil, 0, fmt.Errorf("构造转账交易失败: %w", err)
	}

	return tx, sendAmount, nil
}

// BuildTronSendTRXTx 构建指定金额的 TRX 转账交易（转 gas 到 receipt wallet/manager）
func BuildTronSendTRXTx(c *client.GrpcClient, fromAddr, toAddr string, amount int64) (*api.TransactionExtention, error) {
	from, err := address.Base58ToAddress(fromAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid from address: %w", err)
	}
	to, err := address.Base58ToAddress(toAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid to address: %w", err)
	}

	tx, err := c.Transfer(from.String(), to.String(), amount)
	if err != nil {
		return nil, fmt.Errorf("构造 TRX 转账交易失败: %w", err)
	}
	return tx, nil
}

// GetTronTxHashBytes 获取 Tron 交易的 SHA256 哈希（用于 MPC 签名）
func GetTronTxHashBytes(rawTx *api.TransactionExtention) ([]byte, error) {
	rawData, err := proto.Marshal(rawTx.Transaction.GetRawData())
	if err != nil {
		return nil, fmt.Errorf("序列化交易失败: %w", err)
	}
	hashArr := sha256.Sum256(rawData)
	return hashArr[:], nil
}

// EncodeTronRawDataHex 将 Tron Transaction.RawData 序列化为 hex 字符串（不含 0x 前缀）
func EncodeTronRawDataHex(rawTx *api.TransactionExtention) (string, error) {
	rawData, err := proto.Marshal(rawTx.Transaction.GetRawData())
	if err != nil {
		return "", fmt.Errorf("序列化 Tron rawData 失败: %w", err)
	}
	return hex.EncodeToString(rawData), nil
}

// FormatSUN 格式化 SUN 为 TRX（1 TRX = 10^6 SUN）
func FormatSUN(sun *big.Int) string {
	trx := new(big.Float).SetInt(sun)
	trx.Quo(trx, big.NewFloat(1e6))
	trxStr := trx.Text('f', 6)
	trxStr = strings.TrimRight(trxStr, "0")
	trxStr = strings.TrimRight(trxStr, ".")
	return trxStr
}

// SignWithPrivateKey 使用 ECDSA 私钥对哈希签名，返回 65 字节签名 (r+s+v)
func SignWithPrivateKey(privateKey *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	sig, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, fmt.Errorf("签名失败: %w", err)
	}
	return sig, nil
}

// SignTronTransaction 将 MPC 签名应用到 Tron 交易上
// signHex: 65 字节的签名 hex (r + s + v)，v 为 0/1
func SignTronTransaction(rawTx *api.TransactionExtention, signHex string) error {
	signBytes, err := hex.DecodeString(signHex)
	if err != nil {
		return fmt.Errorf("解码签名失败: %w", err)
	}
	rawTx.Transaction.Signature = append(rawTx.Transaction.Signature, signBytes)
	return nil
}

// BroadcastTronTransaction 广播已签名的 Tron 交易
func BroadcastTronTransaction(c *client.GrpcClient, rawTx *api.TransactionExtention) (string, error) {
	result, err := c.Broadcast(rawTx.Transaction)
	if err != nil {
		return "", fmt.Errorf("广播交易失败: %w", err)
	}
	if !result.Result || result.Code != api.Return_SUCCESS {
		return "", fmt.Errorf("广播交易失败: code=%s, msg=%s", result.Code, string(result.Message))
	}
	return hex.EncodeToString(rawTx.Txid), nil
}
