package tx_util

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/text/unicode/norm"
	"math/big"
	"strings"
)

const (
	// 标准gas limit用于代币转账（通常为65000-100000）,将默认值提高，参考实际交易数据
	defaultTokenGasLimit = uint64(100000) // ERC20 approve/transfer 的合理默认值
	maxTokenGasLimit     = uint64(500000) // 上限（批量操作可能需要更多）
)

const splitWalletProxyABI = `[
	{"inputs":[{"internalType":"address","name":"manager","type":"address"},{"internalType":"address","name":"proxyAdmin_","type":"address"}],"name":"activate","outputs":[],"stateMutability":"nonpayable","type":"function"},
	{"inputs":[],"name":"getProxyAdmin","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}
]`

type TransferParam struct {
	chainID big.Int
	from    string
	token   string
	to      string
	amount  string
}

type TxFeeData struct {
	BaseFee     *big.Int
	MaxPriority *big.Int
	MaxFee      *big.Int
	GasTipCap   *big.Int
	GasFeeCap   *big.Int
}

// CreateEthClientWithEndpoint 使用指定的 endpoint 和 apiKey 创建以太坊客户端
func CreateEthClientWithEndpoint(endpoint, apiKey string) (*ethclient.Client, error) {
	url := fmt.Sprintf("https://%s/%s", endpoint, apiKey)
	return ethclient.Dial(url)
}

// GetEthBalance 获取ETH/MATIC余额
func GetEthBalance(client *ethclient.Client, address eth_common.Address) (*big.Int, error) {
	ctx := context.Background()
	return client.BalanceAt(ctx, address, nil)
}

// GetAmountWei 获取金额单位Wei
func GetAmountWei(ctx context.Context, client *ethclient.Client, tokenAddress eth_common.Address, amountStr string) (*big.Int, uint8, error) {
	// 获取代币decimal
	decimals, err := GetTokenDecimals(ctx, client, tokenAddress)
	if err != nil {
		return nil, 0, err
	}

	// 转换金额为最小单位
	amountWei, err := ConvertToWei(amountStr, decimals)
	if err != nil {
		return nil, 0, err
	}
	return amountWei, decimals, nil
}

func BuildSplitWalletActivateData(manager, proxyAdmin eth_common.Address) ([]byte, error) {
	parsed, err := abi.JSON(strings.NewReader(splitWalletProxyABI))
	if err != nil {
		return nil, err
	}
	return parsed.Pack("activate", manager, proxyAdmin)
}

func GetSplitWalletProxyAdmin(ctx context.Context, client *ethclient.Client, splitter eth_common.Address) (eth_common.Address, error) {
	parsed, err := abi.JSON(strings.NewReader(splitWalletProxyABI))
	if err != nil {
		return eth_common.Address{}, err
	}
	data, err := parsed.Pack("getProxyAdmin")
	if err != nil {
		return eth_common.Address{}, err
	}
	result, err := client.CallContract(ctx, ethereum.CallMsg{
		To:   &splitter,
		Data: data,
	}, nil)
	if err != nil {
		return eth_common.Address{}, err
	}
	values, err := parsed.Unpack("getProxyAdmin", result)
	if err != nil {
		return eth_common.Address{}, err
	}
	if len(values) != 1 {
		return eth_common.Address{}, fmt.Errorf("unexpected getProxyAdmin result size %d", len(values))
	}
	proxyAdmin, ok := values[0].(eth_common.Address)
	if !ok {
		return eth_common.Address{}, fmt.Errorf("unexpected getProxyAdmin result type %T", values[0])
	}
	return proxyAdmin, nil
}

// BuildSweepTx 构建将源地址所有原生代币（ETH/MATIC）发送到目标地址的未签名交易
// 参数:
//   - ctx: 上下文
//   - client: 以太坊客户端
//   - chainID: 链ID
//   - from: 源地址（发送方）
//   - to: 目标地址（接收方）
//
// 返回:
//   - *types.Transaction: 未签名的交易
//   - *big.Int: 实际发送的金额（扣除预期gas费用后）
//   - error: 错误信息
func BuildSweepTx(ctx context.Context, client *ethclient.Client, chainID big.Int, from, to eth_common.Address) (*types.Transaction, *big.Int, error) {
	balance, err := GetEthBalance(client, from)
	if err != nil {
		return nil, nil, fmt.Errorf("获取余额失败: %w", err)
	}

	// 1. 获取一个合理的 Gas 价格上限（例如：建议价的 1.5 倍，确保交易能快速被打包）
	suggestedGasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("获取 gas 价格失败: %w", err)
	}
	gasPrice := new(big.Int).Mul(suggestedGasPrice, big.NewInt(150))
	gasPrice.Div(gasPrice, big.NewInt(100)) // 建议价的 1.5 倍

	// 2. 获取准确的 Gas 用量（原生转账固定为 21000）
	//    这里可以直接使用 21000，避免估算不准确。
	gasLimit := uint64(21000) // 标准 ETH/POL 转账 Gas 用量

	// 3. 计算总费用上限 = gasLimit * gasPrice
	maxGasCost := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), gasPrice)

	// 4. 检查余额是否足够支付费用上限
	if balance.Cmp(maxGasCost) <= 0 {
		// 如果余额刚好等于或少于费用，则无法进行 sweep（除非余额为0）
		return nil, nil, fmt.Errorf("余额 %s 不足以支付最高 gas 费用 %s",
			FormatWeiToETH(balance), FormatWeiToETH(maxGasCost))
	}

	// 5. 关键步骤：可发送金额 = 余额 - 费用上限
	//    这样，无论最终实际 Gas 价格是多少，发送金额 + 实际费用 <= 余额
	sendAmount := new(big.Int).Sub(balance, maxGasCost)

	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return nil, nil, fmt.Errorf("获取 nonce 失败: %w", err)
	}

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    sendAmount,
		Gas:      gasLimit, // 使用准确的 21000
		GasPrice: gasPrice, // 使用您设定的上限价格
		Data:     []byte{},
	})
	return tx, sendAmount, nil
}

// BuildLegacyRawTx 构造未签名的 EIP-1559 交易（向后兼容函数名）
// 参数:
//   - ctx: 上下文
//   - client: 以太坊客户端
//   - chainID: 链ID
//   - from: 发送方地址
//   - to: 接收方地址（合约地址或普通地址）
//   - value: 转账金额（wei），通常为 0（对于 approve）
//   - data: 调用数据（如 approve 编码）
//
// 返回:
//   - *types.Transaction: 未签名的交易（EIP-1559 或 Legacy fallback）
//   - error: 错误信息
func BuildLegacyRawTx(ctx context.Context, client *ethclient.Client, chainID big.Int, from, to eth_common.Address, value big.Int, data []byte) (*types.Transaction, error) {
	// 获取 nonce
	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return nil, fmt.Errorf("获取 nonce 失败: %w", err)
	}

	// 估算 gasLimit
	gasLimit, err := EstimateGas(ctx, client, from, to, &value, data)
	if err != nil {
		defaultGas := uint64(21000)
		if len(data) > 0 {
			defaultGas = 100000
		}
		fmt.Printf("估算 gas 失败，使用默认值 %d: %v\n", defaultGas, err)
		gasLimit = defaultGas
	}

	// 尝试 EIP-1559
	feeData, err := GetFeeData(ctx, client)
	if err == nil && feeData.BaseFee != nil && feeData.BaseFee.Sign() > 0 {
		fmt.Printf("\n=== 交易基本信息 (EIP-1559) ===\n")
		fmt.Printf("链ID: %d\n", chainID.Int64())
		fmt.Printf("Nonce: %d\n", nonce)
		fmt.Printf("Gas Limit: %d\n", gasLimit)
		fmt.Printf("Base Fee: %s Gwei\n", FormatGwei(feeData.BaseFee))
		fmt.Printf("Max Priority Fee: %s Gwei\n", FormatGwei(feeData.GasTipCap))
		fmt.Printf("Max Fee: %s Gwei\n", FormatGwei(feeData.GasFeeCap))

		cid := new(big.Int).Set(&chainID)
		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   cid,
			Nonce:     nonce,
			To:        &to,
			Value:     &value,
			Gas:       gasLimit,
			GasTipCap: feeData.GasTipCap,
			GasFeeCap: feeData.GasFeeCap,
			Data:      data,
		})
		return tx, nil
	}

	// Fallback: Legacy 交易（不支持 EIP-1559 的链）
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取建议 gasPrice 失败: %w", err)
	}

	fmt.Printf("\n=== 交易基本信息 (Legacy fallback) ===\n")
	fmt.Printf("链ID: %d\n", chainID.Int64())
	fmt.Printf("Nonce: %d\n", nonce)
	fmt.Printf("Gas Limit: %d\n", gasLimit)
	fmt.Printf("Gas Price: %s Gwei\n", FormatGwei(gasPrice))

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    &value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})
	return tx, nil
}

// BuildLegacyRawTxWithGasLimit 构造未签名的交易，使用指定的 gasLimit（不估算）
func BuildLegacyRawTxWithGasLimit(ctx context.Context, client *ethclient.Client, chainID big.Int, from, to eth_common.Address, value big.Int, data []byte, gasLimit uint64) (*types.Transaction, error) {
	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return nil, fmt.Errorf("获取 nonce 失败: %w", err)
	}

	// 尝试 EIP-1559
	feeData, feeErr := GetFeeData(ctx, client)
	if feeErr == nil && feeData.BaseFee != nil && feeData.BaseFee.Sign() > 0 {
		fmt.Printf("\n=== 交易基本信息 (EIP-1559, 指定 GasLimit) ===\n")
		fmt.Printf("Nonce: %d, Gas Limit: %d, Max Fee: %s Gwei, Tip: %s Gwei\n", nonce, gasLimit, FormatGwei(feeData.GasFeeCap), FormatGwei(feeData.GasTipCap))

		cid := new(big.Int).Set(&chainID)
		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   cid,
			Nonce:     nonce,
			To:        &to,
			Value:     &value,
			Gas:       gasLimit,
			GasTipCap: feeData.GasTipCap,
			GasFeeCap: feeData.GasFeeCap,
			Data:      data,
		})
		return tx, nil
	}

	// Fallback: Legacy
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取建议 gasPrice 失败: %w", err)
	}
	fmt.Printf("\n=== 交易基本信息 (Legacy fallback, 指定 GasLimit) ===\n")
	fmt.Printf("Nonce: %d, Gas Limit: %d, Gas Price: %s Gwei\n", nonce, gasLimit, FormatGwei(gasPrice))

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    &value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})
	return tx, nil
}

// BuildDynamicFeeRawTx 构造未签名的交易
func BuildDynamicFeeRawTx(ctx context.Context, client *ethclient.Client, chainID big.Int, fromAddress, toAddress eth_common.Address, value big.Int, data []byte) (*types.Transaction, error) {
	// 获取nonce
	nonce, err := client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return nil, err
	}

	// 获取EIP-1559手续费数据
	feeData, err := GetFeeData(ctx, client)
	if err != nil {
		return nil, err
	}

	fmt.Printf("\n=== 交易基本信息 ===\n")
	fmt.Printf("链ID: %s\n", chainID.String())
	fmt.Printf("Nonce: %d\n", nonce)

	gasLimit, err := EstimateGas(ctx, client, fromAddress, toAddress, big.NewInt(0), []byte(data))
	if err != nil {
		fmt.Printf("估算gas失败，使用默认值 %d: %v\n", defaultTokenGasLimit, err)
		gasLimit = defaultTokenGasLimit
	} else {
		// 增加15%的安全余量
		gasLimit = gasLimit * 115 / 100
		if gasLimit < defaultTokenGasLimit {
			gasLimit = defaultTokenGasLimit
		}
	}

	// 创建EIP-1559交易
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   &chainID,
		Nonce:     nonce,
		To:        &toAddress,
		Value:     &value,
		Gas:       gasLimit,
		GasTipCap: feeData.GasTipCap, // 优先费用
		GasFeeCap: feeData.GasFeeCap, // 最大费用
		Data:      data,
	})

	return tx, nil
}

// EstimateLegacyTxFee 估算执行 Legacy 类型交易所需的最大 Gas 费用（wei）
// 参数:
//   - ctx: 上下文
//   - client: 以太坊客户端
//   - from: 交易发送方地址（用于估算 gasLimit）
//   - to: 目标地址（合约地址或普通地址）
//   - value: 转账金额（wei），通常为 0
//   - data: 调用数据（如 approve 的编码）
//   - gasPriceMultiplier: Gas 价格乘数（例如 1.2 表示建议价的 1.2 倍），若 <=0 则默认使用 1.2
//
// 返回:
//   - *big.Int: 预估的最大 Gas 费用（wei）
//   - error: 错误信息
func EstimateLegacyTxFee(ctx context.Context, client *ethclient.Client, from, to eth_common.Address, value *big.Int, data []byte, gasPriceMultiplier float64) (*big.Int, error) {
	// 1. 获取建议 GasPrice
	suggestedGasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取建议 gasPrice 失败: %w", err)
	}

	// 2. 确定乘数（默认 1.2）
	multiplier := gasPriceMultiplier
	if multiplier <= 0 {
		multiplier = 1.2
	}
	// 转换为整数计算（避免浮点误差）
	multiplierInt := big.NewInt(int64(multiplier * 100)) // 保留两位小数
	gasPrice := new(big.Int).Mul(suggestedGasPrice, multiplierInt)
	gasPrice.Div(gasPrice, big.NewInt(100))

	// 3. 估算 GasLimit
	gasLimit, err := EstimateGas(ctx, client, from, to, value, data)
	if err != nil {
		// 估算失败时，使用一个保守的默认值（如 50000），并记录警告
		fmt.Printf("估算 gas 失败，使用默认值 50000: %v\n", err)
		gasLimit = 50000
	} else {
		// 增加 15% 安全余量（与 BuildLegacyRawTx 保持一致）
		gasLimit = gasLimit * 115 / 100
	}

	// 4. 计算总费用 = gasLimit * gasPrice
	totalFee := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), gasPrice)
	return totalFee, nil
}

// AppendSign 获取签名后为交易添加签名
func AppendSign(chainID *big.Int, tx *types.Transaction, sign []byte) (*types.Transaction, error) {
	signer := types.NewLondonSigner(chainID)
	signedTx, err := tx.WithSignature(signer, sign)
	if err != nil {
		panic(fmt.Sprintf("应用签名到交易失败: %v", err))
	}
	return signedTx, nil
}

// SendRawTransaction 发送签名后的交易
func SendRawTransaction(ctx context.Context, client *ethclient.Client, signedTx *types.Transaction) ([]byte, error) {
	// 交易转成二进制
	txData, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// 直接使用eth_sendRawTransaction RPC方法
	var result string
	rawTxHex := hexutil.Encode(txData)
	fmt.Printf("[SendRawTransaction] txHash(local)=%s, rawTx length=%d\n", signedTx.Hash().Hex(), len(rawTxHex))
	err = client.Client().CallContext(ctx, &result, "eth_sendRawTransaction", rawTxHex)
	fmt.Printf("[SendRawTransaction] RPC result=%q, err=%v\n", result, err)
	if err != nil {
		return nil, fmt.Errorf("RPC调用失败: %v", err)
	}

	// 解析返回结果
	if strings.HasPrefix(result, "0x") {
		result = strings.TrimPrefix(result, "0x")
	}

	// 如果返回的是JSON字符串（带引号），去除引号
	if strings.HasPrefix(result, "\"") && strings.HasSuffix(result, "\"") {
		result = strings.Trim(result, "\"")
	}

	// 检查是否有错误
	if strings.Contains(strings.ToLower(result), "error") {
		// 尝试解析错误信息
		var errorMsg map[string]interface{}
		if err := json.Unmarshal([]byte(result), &errorMsg); err == nil {
			if errStr, ok := errorMsg["message"].(string); ok {
				return nil, fmt.Errorf("交易发送失败: %s", errStr)
			}
		}
		return nil, fmt.Errorf("交易发送失败: %s", result)
	}

	return hex.DecodeString(result)
}

// GetFeeData 获取EIP-1559手续费数据
func GetFeeData(ctx context.Context, client *ethclient.Client) (*TxFeeData, error) {
	// 获取当前base fee
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("获取区块头失败: %v", err)
	}

	baseFee := header.BaseFee
	if baseFee == nil {
		// 如果网络不支持EIP-1559，使用传统gas price
		gasPrice, err := client.SuggestGasPrice(ctx)
		if err != nil {
			return nil, fmt.Errorf("获取gas price失败: %v", err)
		}
		return &TxFeeData{
			BaseFee:   big.NewInt(0),
			MaxFee:    gasPrice,
			GasTipCap: big.NewInt(1_500_000_000), // 1.5 Gwei
			GasFeeCap: gasPrice,
		}, nil
	}

	// 获取建议的优先费用
	maxPriorityFee, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		// 如果失败，使用默认值 (1.5 Gwei for Polygon)
		maxPriorityFee = big.NewInt(1_500_000_000) // 1.5 Gwei
	}

	// 计算最大费用 (base fee * 1.5 + max priority fee)
	maxFee := new(big.Int).Mul(baseFee, big.NewInt(3))
	maxFee.Div(maxFee, big.NewInt(2)) // base fee * 1.5
	maxFee.Add(maxFee, maxPriorityFee)

	// 确保maxFee至少比baseFee + maxPriorityFee大
	minFee := new(big.Int).Add(baseFee, maxPriorityFee)
	if maxFee.Cmp(minFee) < 0 {
		maxFee = minFee
	}

	// GasFeeCap是最大费用，GasTipCap是优先费用
	return &TxFeeData{
		BaseFee:     baseFee,
		MaxPriority: maxPriorityFee,
		MaxFee:      maxFee,
		GasTipCap:   maxPriorityFee,
		GasFeeCap:   maxFee,
	}, nil
}

// EstimateGas 估算gas
func EstimateGas(ctx context.Context, client *ethclient.Client, fromAddress, toAddress eth_common.Address, value *big.Int, data []byte) (uint64, error) {
	msg := ethereum.CallMsg{
		From:  fromAddress,
		To:    &toAddress,
		Value: value,
		Data:  data,
	}
	estimatedGas, err := client.EstimateGas(ctx, msg)
	if err != nil {
		return defaultTokenGasLimit, fmt.Errorf("估算gas失败，已使用默认值 %d: %v", defaultTokenGasLimit, err)
	}
	// 增加 30% 安全余量
	gasWithBuffer := estimatedGas * 130 / 100
	if gasWithBuffer > maxTokenGasLimit {
		gasWithBuffer = maxTokenGasLimit
	}
	return gasWithBuffer, nil
}

// ConvertToWei 转换金额为最小单位
func ConvertToWei(amountStr string, decimals uint8) (*big.Int, error) {
	// 标准化字符串（处理Unicode）
	amountStr = norm.NFC.String(strings.TrimSpace(amountStr))

	// 检查是否为有效数字
	if len(amountStr) == 0 {
		return nil, fmt.Errorf("金额不能为空")
	}

	// 分割整数和小数部分
	parts := strings.Split(amountStr, ".")
	if len(parts) > 2 {
		return nil, fmt.Errorf("无效的金额格式")
	}

	// 处理整数部分
	integerPart := parts[0]
	if integerPart == "" {
		integerPart = "0"
	}

	// 创建大整数
	result := new(big.Int)
	result.SetString(integerPart, 10)

	// 乘以10^decimals
	multiplier := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	result.Mul(result, multiplier)

	// 如果有小数部分
	if len(parts) == 2 {
		decimalPart := parts[1]
		if decimalPart != "" {
			// 确保小数部分不超过decimals位
			if len(decimalPart) > int(decimals) {
				decimalPart = decimalPart[:decimals]
			} else if len(decimalPart) < int(decimals) {
				// 补零
				decimalPart = decimalPart + strings.Repeat("0", int(decimals)-len(decimalPart))
			}

			decimalValue := new(big.Int)
			decimalValue.SetString(decimalPart, 10)
			result.Add(result, decimalValue)
		}
	}

	return result, nil
}

// ConvertWeiToDecimal 将wei转换为十进制字符串
func ConvertWeiToDecimal(wei *big.Int, decimals uint8) string {
	if wei == nil {
		return "0"
	}

	// 创建10^decimals的除数
	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)

	// 计算整数部分
	integerPart := new(big.Int).Div(wei, divisor)

	// 计算小数部分
	fractionalPart := new(big.Int).Mod(wei, divisor)

	// 如果小数部分为0，直接返回整数部分
	if fractionalPart.Sign() == 0 {
		return integerPart.String()
	}

	// 将小数部分格式化为decimals位的字符串
	fracStr := fractionalPart.String()

	// 补零到decimals位
	if len(fracStr) < int(decimals) {
		fracStr = strings.Repeat("0", int(decimals)-len(fracStr)) + fracStr
	}

	// 去除尾部的零
	fracStr = strings.TrimRight(fracStr, "0")

	// 如果小数部分全为零，只返回整数部分
	if fracStr == "" {
		return integerPart.String()
	}

	return integerPart.String() + "." + fracStr
}

// FormatGwei 格式化Gwei单位
func FormatGwei(wei *big.Int) string {
	gwei := new(big.Float).SetInt(wei)
	gwei.Quo(gwei, big.NewFloat(1e9))

	gweiStr := gwei.Text('f', 3)
	gweiStr = strings.TrimRight(gweiStr, "0")
	gweiStr = strings.TrimRight(gweiStr, ".")

	return gweiStr
}

// FormatWeiToETH 格式化ETH单位（1 ETH = 10^18 Wei）
func FormatWeiToETH(wei *big.Int) string {
	eth := new(big.Float).SetInt(wei)
	eth.Quo(eth, big.NewFloat(1e18)) // 1 POL = 10^18 wei

	// 根据数值大小选择合适的小数位
	ethStr := eth.Text('f', 10) // 最多10位小数
	ethStr = strings.TrimRight(ethStr, "0")
	ethStr = strings.TrimRight(ethStr, ".")

	return ethStr
}

// -------------------- Nonce 诊断与修复 --------------------

// NonceDiagnosis nonce 诊断结果
type NonceDiagnosis struct {
	Address      string
	LatestNonce  uint64 // 最新已确认的 nonce
	PendingNonce uint64 // 包含 pending 的 nonce
	PendingCount uint64 // 卡住的交易数量
	HasPending   bool   // 是否存在卡住的交易
}

// DiagnoseNonce 诊断 EVM 地址的 nonce 状态
func DiagnoseNonce(ctx context.Context, client *ethclient.Client, address eth_common.Address) (*NonceDiagnosis, error) {
	latestNonce, err := client.NonceAt(ctx, address, nil) // "latest"
	if err != nil {
		return nil, fmt.Errorf("查询 latest nonce 失败: %w", err)
	}
	pendingNonce, err := client.PendingNonceAt(ctx, address) // "pending"
	if err != nil {
		return nil, fmt.Errorf("查询 pending nonce 失败: %w", err)
	}

	pendingCount := uint64(0)
	if pendingNonce > latestNonce {
		pendingCount = pendingNonce - latestNonce
	}

	return &NonceDiagnosis{
		Address:      address.Hex(),
		LatestNonce:  latestNonce,
		PendingNonce: pendingNonce,
		PendingCount: pendingCount,
		HasPending:   pendingCount > 0,
	}, nil
}

// CheckNonceHealth 检查 nonce 状态，如果有 pending 交易则返回错误
func CheckNonceHealth(ctx context.Context, client *ethclient.Client, address eth_common.Address) error {
	diag, err := DiagnoseNonce(ctx, client, address)
	if err != nil {
		return err
	}
	if diag.HasPending {
		return fmt.Errorf("检测到 %d 笔卡住的交易 (latest nonce: %d, pending nonce: %d)，请先修复 pending 交易后再操作",
			diag.PendingCount, diag.LatestNonce, diag.PendingNonce)
	}
	return nil
}

// ForceResetNonce 强制重置卡住的 nonce：对每个卡住的 nonce 发送 0 值自转交易覆盖
func ForceResetNonce(ctx context.Context, client *ethclient.Client, chainID *big.Int, address eth_common.Address, privateKey *ecdsa.PrivateKey, logFn func(string)) error {
	diag, err := DiagnoseNonce(ctx, client, address)
	if err != nil {
		return err
	}
	if !diag.HasPending {
		logFn("无卡住的交易，无需修复")
		return nil
	}

	logFn(fmt.Sprintf("检测到 %d 笔卡住的交易 (nonce %d ~ %d)，开始修复...",
		diag.PendingCount, diag.LatestNonce, diag.PendingNonce-1))

	// 获取当前 gas price 的 2 倍，确保能替换卡住的交易
	suggestedGasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return fmt.Errorf("获取 gas price 失败: %w", err)
	}
	replaceGasPrice := new(big.Int).Mul(suggestedGasPrice, big.NewInt(2))

	signer := types.NewLondonSigner(chainID)

	for nonce := diag.LatestNonce; nonce < diag.PendingNonce; nonce++ {
		logFn(fmt.Sprintf("  修复 nonce %d...", nonce))

		tx := types.NewTx(&types.LegacyTx{
			Nonce:    nonce,
			To:       &address, // 自转
			Value:    big.NewInt(0),
			Gas:      21000,
			GasPrice: replaceGasPrice,
			Data:     []byte{},
		})

		signedTx, err := types.SignTx(tx, signer, privateKey)
		if err != nil {
			return fmt.Errorf("nonce %d 签名失败: %w", nonce, err)
		}

		txID, err := SendRawTransaction(ctx, client, signedTx)
		if err != nil {
			return fmt.Errorf("nonce %d 发送失败: %w (后续 nonce 无法继续)", nonce, err)
		}
		logFn(fmt.Sprintf("  nonce %d 替换交易已发送: 0x%s", nonce, hex.EncodeToString(txID)))
	}

	logFn("nonce 修复完成")
	return nil
}

// EncodeUnsignedTxHex 将 unsigned EVM 交易编码为 RLP hex 字符串（含 0x 前缀）。
// 编码格式与 web3j TransactionEncoder.encode(rawTx, chainId) 一致。
func EncodeUnsignedTxHex(tx *types.Transaction, chainID *big.Int) string {
	signer := types.NewLondonSigner(chainID)
	// 利用 signer.Hash 的内部逻辑：它对 (nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0) 做 RLP 编码再 keccak256。
	// 我们直接用 types.Transaction 的 MarshalBinary，但对于 legacy tx 需要特殊处理。
	// 最可靠的方式是用 rlp 直接编码。
	//
	// go-ethereum 没有直接暴露 signer 编码后的 RLP 字节，
	// 但 LegacyTx 的 RLP 编码就是 (nonce, gasPrice, gasLimit, to, value, data)。
	// EIP-155 签名用的 hash 是 rlp(nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0)。
	//
	// 我们这里直接传 LegacyTx 的 MarshalBinary (不含 envelope type byte) 给 Java 端，
	// Java 端用 TransactionDecoder.decode 解析后再自行计算 EIP-155 hash。
	_ = signer // 确保 import 不报错

	// Legacy tx: MarshalBinary 返回 RLP(nonce, gasPrice, gasLimit, to, value, data)
	raw, err := tx.MarshalBinary()
	if err != nil {
		return ""
	}
	return "0x" + hex.EncodeToString(raw)
}
