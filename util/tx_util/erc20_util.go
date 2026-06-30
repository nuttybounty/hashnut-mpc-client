package tx_util

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	Erc20ABI = `[
        {
            "constant": true,
            "inputs": [],
            "name": "name",
            "outputs": [{"name": "", "type": "string"}],
            "type": "function"
        },
        {
            "constant": true,
            "inputs": [],
            "name": "symbol",
            "outputs": [{"name": "", "type": "string"}],
            "type": "function"
        },
        {
            "constant": true,
            "inputs": [],
            "name": "decimals",
            "outputs": [{"name": "", "type": "uint8"}],
            "type": "function"
        },
        {
            "constant": true,
            "inputs": [],
            "name": "totalSupply",
            "outputs": [{"name": "", "type": "uint256"}],
            "type": "function"
        },
        {
            "constant": true,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "type": "function"
        },
        {
            "constant": false,
            "inputs": [
                {"name": "_to", "type": "address"},
                {"name": "_value", "type": "uint256"}
            ],
            "name": "transfer",
            "outputs": [{"name": "success", "type": "bool"}],
            "type": "function"
        },
        {
            "constant": false,
            "inputs": [
                {"name": "_from", "type": "address"},
                {"name": "_to", "type": "address"},
                {"name": "_value", "type": "uint256"}
            ],
            "name": "transferFrom",
            "outputs": [{"name": "success", "type": "bool"}],
            "type": "function"
        },
        {
            "constant": false,
            "inputs": [
                {"name": "_spender", "type": "address"},
                {"name": "_value", "type": "uint256"}
            ],
            "name": "approve",
            "outputs": [{"name": "success", "type": "bool"}],
            "type": "function"
        },
        {
            "constant": true,
            "inputs": [
                {"name": "_owner", "type": "address"},
                {"name": "_spender", "type": "address"}
            ],
            "name": "allowance",
            "outputs": [{"name": "remaining", "type": "uint256"}],
            "type": "function"
        },
        
        {
            "anonymous": false,
            "inputs": [
                {"indexed": true, "name": "from", "type": "address"},
                {"indexed": true, "name": "to", "type": "address"},
                {"indexed": false, "name": "value", "type": "uint256"}
            ],
            "name": "Transfer",
            "type": "event"
        },
        {
            "anonymous": false,
            "inputs": [
                {"indexed": true, "name": "owner", "type": "address"},
                {"indexed": true, "name": "spender", "type": "address"},
                {"indexed": false, "name": "value", "type": "uint256"}
            ],
            "name": "Approval",
            "type": "event"
        }
    ]`
)

// 内部缓存的已解析 ABI，不对外暴露
var erc20ParsedABI abi.ABI
var splitWalletV4ParsedABI abi.ABI
var proxyAdminParsedABI abi.ABI

func init() {
	parsed, err := abi.JSON(strings.NewReader(Erc20ABI))
	if err != nil {
		panic(fmt.Sprintf("failed to parse ERC20 ABI: %v", err))
	}
	erc20ParsedABI = parsed

	splitWalletABI := `[
		{
			"inputs": [
				{"internalType": "address", "name": "token", "type": "address"},
				{"internalType": "address[]", "name": "wallets", "type": "address[]"},
				{"internalType": "uint256", "name": "minAllowance", "type": "uint256"}
			],
			"name": "addReceiptWallets",
			"outputs": [],
			"stateMutability": "nonpayable",
			"type": "function"
		},
		{
			"inputs": [
				{"internalType": "address[]", "name": "tokens", "type": "address[]"},
				{"internalType": "uint256[]", "name": "minAmounts", "type": "uint256[]"},
				{"internalType": "uint256", "name": "startIndex", "type": "uint256"},
				{"internalType": "uint256", "name": "endIndexExcluded", "type": "uint256"}
			],
			"name": "claimReceiptERC20Tokens",
			"outputs": [{"internalType": "uint256[]", "name": "totalClaimed", "type": "uint256[]"}],
			"stateMutability": "nonpayable",
			"type": "function"
		},
		{
			"inputs": [
				{"internalType": "uint256", "name": "minAmount", "type": "uint256"},
				{"internalType": "uint256", "name": "startIndex", "type": "uint256"},
				{"internalType": "uint256", "name": "endIndexExcluded", "type": "uint256"}
			],
			"name": "queryReceiptNativeBalance",
			"outputs": [
				{"internalType": "uint256", "name": "totalBalance", "type": "uint256"},
				{"internalType": "uint256", "name": "walletCount", "type": "uint256"}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [
				{"internalType": "address[]", "name": "tokens", "type": "address[]"},
				{"internalType": "address", "name": "account", "type": "address"}
			],
			"name": "releaseERC20Tokens",
			"outputs": [],
			"stateMutability": "nonpayable",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "getReceiptWalletCount",
			"outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [
				{"internalType": "contract IERC20", "name": "token", "type": "address"},
				{"internalType": "address", "name": "account", "type": "address"}
			],
			"name": "balanceERC20",
			"outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "getAllReceiptWallets",
			"outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}],
			"stateMutability": "view",
			"type": "function"
		}
	]`
	parsedSplitWalletABI, err := abi.JSON(strings.NewReader(splitWalletABI))
	if err != nil {
		panic(fmt.Sprintf("failed to parse SplitWalletV4 ABI: %v", err))
	}
	splitWalletV4ParsedABI = parsedSplitWalletABI

	proxyAdminABI := `[
		{
			"inputs": [
				{"internalType": "contract ITransparentUpgradeableProxy", "name": "proxy", "type": "address"},
				{"internalType": "address", "name": "implementation", "type": "address"}
			],
			"name": "upgrade",
			"outputs": [],
			"stateMutability": "nonpayable",
			"type": "function"
		}
	]`
	parsedProxyAdminABI, err := abi.JSON(strings.NewReader(proxyAdminABI))
	if err != nil {
		panic(fmt.Sprintf("failed to parse ProxyAdmin ABI: %v", err))
	}
	proxyAdminParsedABI = parsedProxyAdminABI
}

// -------------------- 构建调用数据函数 --------------------

// BuildTransferData 构建 transfer 函数调用数据
func BuildTransferData(toAddress eth_common.Address, amount *big.Int) ([]byte, error) {
	return erc20ParsedABI.Pack("transfer", toAddress, amount)
}

// BuildApproveData 构建 approve 函数调用数据
func BuildApproveData(spenderAddress eth_common.Address, amount *big.Int) ([]byte, error) {
	return erc20ParsedABI.Pack("approve", spenderAddress, amount)
}

// BuildTransferFromData 构建 transferFrom 函数调用数据
func BuildTransferFromData(from, to eth_common.Address, amount *big.Int) ([]byte, error) {
	return erc20ParsedABI.Pack("transferFrom", from, to, amount)
}

// BuildBalanceOfData 构建 balanceOf 函数调用数据
func BuildBalanceOfData(owner eth_common.Address) ([]byte, error) {
	return erc20ParsedABI.Pack("balanceOf", owner)
}

// BuildNameData 构建 name 函数调用数据
func BuildNameData() ([]byte, error) {
	return erc20ParsedABI.Pack("name")
}

// BuildSymbolData 构建 symbol 函数调用数据
func BuildSymbolData() ([]byte, error) {
	return erc20ParsedABI.Pack("symbol")
}

// BuildDecimalsData 构建 decimals 函数调用数据
func BuildDecimalsData() ([]byte, error) {
	return erc20ParsedABI.Pack("decimals")
}

// BuildTotalSupplyData 构建 totalSupply 函数调用数据
func BuildTotalSupplyData() ([]byte, error) {
	return erc20ParsedABI.Pack("totalSupply")
}

// BuildAllowanceData 构建 allowance 函数调用数据
func BuildAllowanceData(owner, spender eth_common.Address) ([]byte, error) {
	return erc20ParsedABI.Pack("allowance", owner, spender)
}

func BuildAddReceiptWalletsData(token eth_common.Address, wallets []eth_common.Address, minAllowance *big.Int) ([]byte, error) {
	return splitWalletV4ParsedABI.Pack("addReceiptWallets", token, wallets, minAllowance)
}

// -------------------- 解包返回数据函数 --------------------

// UnpackBalanceOf 从合约返回的原始数据中解包出余额
func UnpackBalanceOf(data []byte) (*big.Int, error) {
	var balance *big.Int
	err := erc20ParsedABI.UnpackIntoInterface(&balance, "balanceOf", data)
	return balance, err
}

// UnpackName 解包 name 返回的字符串
func UnpackName(data []byte) (string, error) {
	var name string
	err := erc20ParsedABI.UnpackIntoInterface(&name, "name", data)
	return name, err
}

// UnpackSymbol 解包 symbol 返回的字符串
func UnpackSymbol(data []byte) (string, error) {
	var symbol string
	err := erc20ParsedABI.UnpackIntoInterface(&symbol, "symbol", data)
	return symbol, err
}

// UnpackDecimals 解包 decimals 返回的 uint8
func UnpackDecimals(data []byte) (uint8, error) {
	var decimals uint8
	err := erc20ParsedABI.UnpackIntoInterface(&decimals, "decimals", data)
	return decimals, err
}

// UnpackTotalSupply 解包 totalSupply 返回的总供应量
func UnpackTotalSupply(data []byte) (*big.Int, error) {
	var totalSupply *big.Int
	err := erc20ParsedABI.UnpackIntoInterface(&totalSupply, "totalSupply", data)
	return totalSupply, err
}

// UnpackAllowance 解包 allowance 返回的授权额度
func UnpackAllowance(data []byte) (*big.Int, error) {
	var allowance *big.Int
	err := erc20ParsedABI.UnpackIntoInterface(&allowance, "allowance", data)
	return allowance, err
}

// UnpackTransfer 解包 transfer 返回的布尔值（通常用于直接调用时模拟结果）
func UnpackTransfer(data []byte) (bool, error) {
	var success bool
	err := erc20ParsedABI.UnpackIntoInterface(&success, "transfer", data)
	return success, err
}

// UnpackApprove 解包 approve 返回的布尔值
func UnpackApprove(data []byte) (bool, error) {
	var success bool
	err := erc20ParsedABI.UnpackIntoInterface(&success, "approve", data)
	return success, err
}

// -------------------- 高级查询函数（直接与链交互） --------------------

// GetTokenBalance 获取指定地址的代币余额
func GetTokenBalance(ctx context.Context, client *ethclient.Client, tokenAddress, holder eth_common.Address) (*big.Int, error) {
	data, err := BuildBalanceOfData(holder)
	if err != nil {
		return nil, fmt.Errorf("build balanceOf data failed: %w", err)
	}

	msg := ethereum.CallMsg{
		To:   &tokenAddress,
		Data: data,
	}
	result, err := client.CallContract(ctx, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("call contract failed: %w", err)
	}

	return UnpackBalanceOf(result)
}

// GetTokenName 获取代币名称
func GetTokenName(ctx context.Context, client *ethclient.Client, tokenAddress eth_common.Address) (string, error) {
	data, err := BuildNameData()
	if err != nil {
		return "", fmt.Errorf("build name data failed: %w", err)
	}

	msg := ethereum.CallMsg{To: &tokenAddress, Data: data}
	result, err := client.CallContract(ctx, msg, nil)
	if err != nil {
		return "", fmt.Errorf("call contract failed: %w", err)
	}

	return UnpackName(result)
}

// GetTokenSymbol 获取代币符号
func GetTokenSymbol(ctx context.Context, client *ethclient.Client, tokenAddress eth_common.Address) (string, error) {
	data, err := BuildSymbolData()
	if err != nil {
		return "", fmt.Errorf("build symbol data failed: %w", err)
	}

	msg := ethereum.CallMsg{To: &tokenAddress, Data: data}
	result, err := client.CallContract(ctx, msg, nil)
	if err != nil {
		return "", fmt.Errorf("call contract failed: %w", err)
	}

	return UnpackSymbol(result)
}

// GetTokenDecimals 获取代币小数位数
func GetTokenDecimals(ctx context.Context, client *ethclient.Client, tokenAddress eth_common.Address) (uint8, error) {
	data, err := BuildDecimalsData()
	if err != nil {
		return 0, fmt.Errorf("build decimals data failed: %w", err)
	}

	msg := ethereum.CallMsg{To: &tokenAddress, Data: data}
	result, err := client.CallContract(ctx, msg, nil)
	if err != nil {
		return 0, fmt.Errorf("call contract failed: %w", err)
	}

	return UnpackDecimals(result)
}

// GetTokenTotalSupply 获取代币总供应量
func GetTokenTotalSupply(ctx context.Context, client *ethclient.Client, tokenAddress eth_common.Address) (*big.Int, error) {
	data, err := BuildTotalSupplyData()
	if err != nil {
		return nil, fmt.Errorf("build totalSupply data failed: %w", err)
	}

	msg := ethereum.CallMsg{To: &tokenAddress, Data: data}
	result, err := client.CallContract(ctx, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("call contract failed: %w", err)
	}

	return UnpackTotalSupply(result)
}

// GetTokenAllowance 获取授权额度
func GetTokenAllowance(ctx context.Context, client *ethclient.Client, tokenAddress, owner, spender eth_common.Address) (*big.Int, error) {
	data, err := BuildAllowanceData(owner, spender)
	if err != nil {
		return nil, fmt.Errorf("build allowance data failed: %w", err)
	}

	msg := ethereum.CallMsg{To: &tokenAddress, Data: data}
	result, err := client.CallContract(ctx, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("call contract failed: %w", err)
	}

	return UnpackAllowance(result)
}

// -------------------- ProxyAdmin 合约调用 --------------------

// BuildUpgradeData 构建 ProxyAdmin.upgrade(proxy, implementation) 调用数据
func BuildUpgradeData(proxyAddress, implementationAddress eth_common.Address) ([]byte, error) {
	return proxyAdminParsedABI.Pack("upgrade", proxyAddress, implementationAddress)
}

// -------------------- SplitWalletV4 合约调用 --------------------

// BuildClaimReceiptERC20TokensData 构建 claimReceiptERC20Tokens 调用数据
func BuildClaimReceiptERC20TokensData(tokens []eth_common.Address, minAmounts []*big.Int, startIndex, endIndexExcluded *big.Int) ([]byte, error) {
	return splitWalletV4ParsedABI.Pack("claimReceiptERC20Tokens", tokens, minAmounts, startIndex, endIndexExcluded)
}

// BuildReleaseERC20TokensData 构建 releaseERC20Tokens 调用数据
func BuildReleaseERC20TokensData(tokens []eth_common.Address, account eth_common.Address) ([]byte, error) {
	return splitWalletV4ParsedABI.Pack("releaseERC20Tokens", tokens, account)
}

// GetReceiptWalletCount 查询合约中注册的 receipt wallet 总数
func GetReceiptWalletCount(ctx context.Context, client *ethclient.Client, splitter eth_common.Address) (*big.Int, error) {
	data, err := splitWalletV4ParsedABI.Pack("getReceiptWalletCount")
	if err != nil {
		return nil, fmt.Errorf("pack getReceiptWalletCount failed: %w", err)
	}
	result, err := client.CallContract(ctx, ethereum.CallMsg{To: &splitter, Data: data}, nil)
	if err != nil {
		return nil, fmt.Errorf("call getReceiptWalletCount failed: %w", err)
	}
	values, err := splitWalletV4ParsedABI.Unpack("getReceiptWalletCount", result)
	if err != nil {
		return nil, fmt.Errorf("unpack getReceiptWalletCount failed: %w", err)
	}
	if len(values) != 1 {
		return nil, fmt.Errorf("unexpected getReceiptWalletCount result size %d", len(values))
	}
	count, ok := values[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("unexpected getReceiptWalletCount result type %T", values[0])
	}
	return count, nil
}

// GetBalanceERC20 查询 payee 在 split wallet 中某 token 的可提取余额
func GetBalanceERC20(ctx context.Context, client *ethclient.Client, splitter eth_common.Address, token, account eth_common.Address) (*big.Int, error) {
	data, err := splitWalletV4ParsedABI.Pack("balanceERC20", token, account)
	if err != nil {
		return nil, fmt.Errorf("pack balanceERC20 failed: %w", err)
	}
	result, err := client.CallContract(ctx, ethereum.CallMsg{To: &splitter, Data: data}, nil)
	if err != nil {
		return nil, fmt.Errorf("call balanceERC20 failed: %w", err)
	}
	values, err := splitWalletV4ParsedABI.Unpack("balanceERC20", result)
	if err != nil {
		return nil, fmt.Errorf("unpack balanceERC20 failed: %w", err)
	}
	if len(values) != 1 {
		return nil, fmt.Errorf("unexpected balanceERC20 result size %d", len(values))
	}
	balance, ok := values[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("unexpected balanceERC20 result type %T", values[0])
	}
	return balance, nil
}

// GetAllReceiptWallets 查询合约中所有注册的 receipt wallet 地址
func GetAllReceiptWallets(ctx context.Context, client *ethclient.Client, splitter eth_common.Address) ([]eth_common.Address, error) {
	data, err := splitWalletV4ParsedABI.Pack("getAllReceiptWallets")
	if err != nil {
		return nil, fmt.Errorf("pack getAllReceiptWallets failed: %w", err)
	}
	result, err := client.CallContract(ctx, ethereum.CallMsg{To: &splitter, Data: data}, nil)
	if err != nil {
		return nil, fmt.Errorf("call getAllReceiptWallets failed: %w", err)
	}
	values, err := splitWalletV4ParsedABI.Unpack("getAllReceiptWallets", result)
	if err != nil {
		return nil, fmt.Errorf("unpack getAllReceiptWallets failed: %w", err)
	}
	if len(values) != 1 {
		return nil, fmt.Errorf("unexpected getAllReceiptWallets result size %d", len(values))
	}
	wallets, ok := values[0].([]eth_common.Address)
	if !ok {
		return nil, fmt.Errorf("unexpected getAllReceiptWallets result type %T", values[0])
	}
	return wallets, nil
}

// GetCollectableBalance 查询所有 receipt wallet 中指定 token 的可归集余额总和
func GetCollectableBalance(ctx context.Context, client *ethclient.Client, splitter, token eth_common.Address) (*big.Int, error) {
	wallets, err := GetAllReceiptWallets(ctx, client, splitter)
	if err != nil {
		return nil, err
	}
	total := big.NewInt(0)
	for _, wallet := range wallets {
		balance, err := GetTokenBalance(ctx, client, token, wallet)
		if err != nil {
			continue // 跳过查询失败的地址
		}
		total.Add(total, balance)
	}
	return total, nil
}

// SimulateClaimReceiptERC20Tokens 模拟调用 claimReceiptERC20Tokens，返回每种 token 的可归集金额
// 使用 eth_call 不消耗 gas，用于判断该批次是否有资金可归集
func SimulateClaimReceiptERC20Tokens(ctx context.Context, client *ethclient.Client, from, splitter eth_common.Address, tokens []eth_common.Address, minAmounts []*big.Int, startIndex, endIndexExcluded *big.Int) ([]*big.Int, error) {
	data, err := BuildClaimReceiptERC20TokensData(tokens, minAmounts, startIndex, endIndexExcluded)
	if err != nil {
		return nil, fmt.Errorf("pack claimReceiptERC20Tokens failed: %w", err)
	}
	result, err := client.CallContract(ctx, ethereum.CallMsg{
		From: from,
		To:   &splitter,
		Data: data,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("simulate claimReceiptERC20Tokens failed: %w", err)
	}
	values, err := splitWalletV4ParsedABI.Unpack("claimReceiptERC20Tokens", result)
	if err != nil {
		return nil, fmt.Errorf("unpack claimReceiptERC20Tokens result failed: %w", err)
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

// QueryReceiptNativeBalance 查询指定范围内 receipt wallet 的原生代币可归集余额
func QueryReceiptNativeBalance(ctx context.Context, client *ethclient.Client, splitter eth_common.Address, minAmount, startIndex, endIndexExcluded *big.Int) (*big.Int, uint64, error) {
	data, err := splitWalletV4ParsedABI.Pack("queryReceiptNativeBalance", minAmount, startIndex, endIndexExcluded)
	if err != nil {
		return nil, 0, fmt.Errorf("pack queryReceiptNativeBalance failed: %w", err)
	}
	result, err := client.CallContract(ctx, ethereum.CallMsg{To: &splitter, Data: data}, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("call queryReceiptNativeBalance failed: %w", err)
	}
	values, err := splitWalletV4ParsedABI.Unpack("queryReceiptNativeBalance", result)
	if err != nil {
		return nil, 0, fmt.Errorf("unpack queryReceiptNativeBalance failed: %w", err)
	}
	if len(values) != 2 {
		return nil, 0, fmt.Errorf("unexpected result size %d", len(values))
	}
	totalBalance := values[0].(*big.Int)
	walletCount := values[1].(*big.Int)
	return totalBalance, walletCount.Uint64(), nil
}
