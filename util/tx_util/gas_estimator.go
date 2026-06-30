package tx_util

import (
	"context"
	"fmt"
	"math/big"

	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	GasLimitNativeTransfer = uint64(21000)
	GasLimitApprove        = uint64(60000)
	GasLimitAddReceiptBase = uint64(50000)   // addReceiptWallets 基础 gas
	GasLimitAddReceiptPer  = uint64(100000) // 每增加一个地址的额外 gas（含 3 个 SSTORE + allowance 查询）
	DefaultSafetyFactor    = 1.5
)

// GasEstimate 单项操作的 gas 评估结果
type GasEstimate struct {
	Operation   string   // 操作名称
	Count       int      // 操作次数
	GasLimit    uint64   // 单次 gasLimit
	GasPrice    *big.Int // gasPrice (legacy) 或 maxFeePerGas (EIP-1559)
	IsEIP1559   bool
	RequiredWei *big.Int // 单次所需 wei = gasLimit × gasPrice × safetyFactor
	TotalWei    *big.Int // 总计 = RequiredWei × Count
}

// BatchSetupEstimate 批量 setup 的完整 gas 评估
type BatchSetupEstimate struct {
	Chain          string
	NativeSymbol   string
	SafetyFactor   float64
	WalletCount    int
	GasPrice       *big.Int
	IsEIP1559      bool

	FundTransfer      GasEstimate // 商户钱包转 gas（N+1 笔: N 个 receipt + 1 个 manager）
	Approve           GasEstimate // receipt wallet approve（N 笔）
	AddReceiptWallets GasEstimate // manager addReceiptWallets（1 笔）
	SweepReceipt      GasEstimate // receipt wallet sweep（N 笔）
	SweepManager      GasEstimate // manager sweep（1 笔）

	PerReceiptWallet *big.Int // 每个 receipt wallet 需转入的 gas
	ManagerTotal     *big.Int // manager 需转入的 gas
	FundingFeeTotal  *big.Int // 批量转 gas 的手续费总和
	MerchantTotal    *big.Int // 商户钱包总需余额
	MerchantBalance  *big.Int // 商户钱包当前余额
	Sufficient       bool
}

// GetGasPriceWithSafety 获取 gas price 并应用安全系数
func GetGasPriceWithSafety(ctx context.Context, client *ethclient.Client, safetyFactor float64) (*big.Int, bool, error) {
	if safetyFactor <= 0 {
		safetyFactor = DefaultSafetyFactor
	}

	// 尝试 EIP-1559
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("获取区块头失败: %w", err)
	}

	if header.BaseFee != nil {
		// EIP-1559: maxFeePerGas = baseFee × 2 + maxPriorityFee
		tipCap, err := client.SuggestGasTipCap(ctx)
		if err != nil {
			tipCap = big.NewInt(1_500_000_000) // 1.5 Gwei fallback
		}
		maxFee := new(big.Int).Mul(header.BaseFee, big.NewInt(2))
		maxFee.Add(maxFee, tipCap)
		// 应用安全系数
		sfInt := big.NewInt(int64(safetyFactor * 100))
		maxFee.Mul(maxFee, sfInt)
		maxFee.Div(maxFee, big.NewInt(100))
		return maxFee, true, nil
	}

	// Legacy
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("获取 gas price 失败: %w", err)
	}
	sfInt := big.NewInt(int64(safetyFactor * 100))
	gasPrice.Mul(gasPrice, sfInt)
	gasPrice.Div(gasPrice, big.NewInt(100))
	return gasPrice, false, nil
}

// newEstimate 创建单项评估
func newEstimate(operation string, count int, gasLimit uint64, gasPrice *big.Int, isEIP1559 bool) GasEstimate {
	requiredWei := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), gasPrice)
	totalWei := new(big.Int).Mul(requiredWei, big.NewInt(int64(count)))
	return GasEstimate{
		Operation:   operation,
		Count:       count,
		GasLimit:    gasLimit,
		GasPrice:    gasPrice,
		IsEIP1559:   isEIP1559,
		RequiredWei: requiredWei,
		TotalWei:    totalWei,
	}
}

// EstimateBatchSetup 评估批量创建 receipt wallet 的 gas 费用
func EstimateBatchSetup(
	ctx context.Context,
	client *ethclient.Client,
	merchantAddress eth_common.Address,
	chain, nativeSymbol string,
	walletCount int,
	safetyFactor float64,
) (*BatchSetupEstimate, error) {
	if safetyFactor <= 0 {
		safetyFactor = DefaultSafetyFactor
	}

	gasPrice, isEIP1559, err := GetGasPriceWithSafety(ctx, client, safetyFactor)
	if err != nil {
		return nil, err
	}

	// 各项评估
	fundTransferCount := walletCount + 1 // N 个 receipt + 1 个 manager
	fundTransfer := newEstimate("native transfer (fund gas)", fundTransferCount, GasLimitNativeTransfer, gasPrice, isEIP1559)
	approve := newEstimate("ERC20 approve", walletCount, GasLimitApprove, gasPrice, isEIP1559)
	addReceiptGas := GasLimitAddReceiptBase + GasLimitAddReceiptPer*uint64(walletCount)
	addReceipt := newEstimate("addReceiptWallets", 1, addReceiptGas, gasPrice, isEIP1559)
	sweepReceipt := newEstimate("sweep receipt", walletCount, GasLimitNativeTransfer, gasPrice, isEIP1559)
	sweepManager := newEstimate("sweep manager", 1, GasLimitNativeTransfer, gasPrice, isEIP1559)

	// 每个 receipt wallet 需转入: approve + sweep
	perReceipt := new(big.Int).Add(approve.RequiredWei, sweepReceipt.RequiredWei)

	// manager 需转入: addReceiptWallets + sweep
	managerTotal := new(big.Int).Add(addReceipt.RequiredWei, sweepManager.RequiredWei)

	// 商户钱包总需: 转 gas 手续费 + 转入 receipt wallets + 转入 manager
	fundingFee := fundTransfer.TotalWei
	receiptFunding := new(big.Int).Mul(perReceipt, big.NewInt(int64(walletCount)))
	merchantTotal := new(big.Int).Add(fundingFee, receiptFunding)
	merchantTotal.Add(merchantTotal, managerTotal)

	// 查询商户余额
	balance, err := client.BalanceAt(ctx, merchantAddress, nil)
	if err != nil {
		return nil, fmt.Errorf("获取商户钱包余额失败: %w", err)
	}

	return &BatchSetupEstimate{
		Chain:        chain,
		NativeSymbol: nativeSymbol,
		SafetyFactor: safetyFactor,
		WalletCount:  walletCount,
		GasPrice:     gasPrice,
		IsEIP1559:    isEIP1559,

		FundTransfer:      fundTransfer,
		Approve:           approve,
		AddReceiptWallets: addReceipt,
		SweepReceipt:      sweepReceipt,
		SweepManager:      sweepManager,

		PerReceiptWallet: perReceipt,
		ManagerTotal:     managerTotal,
		FundingFeeTotal:  fundingFee,
		MerchantTotal:    merchantTotal,
		MerchantBalance:  balance,
		Sufficient:       balance.Cmp(merchantTotal) >= 0,
	}, nil
}

// PrintEstimate 格式化输出评估结果
func PrintEstimate(est *BatchSetupEstimate) {
	gasType := "Legacy"
	if est.IsEIP1559 {
		gasType = "EIP-1559"
	}

	fmt.Printf("\n⛽ Gas 费评估 (%s, %d 个地址)\n\n", est.Chain, est.WalletCount)
	fmt.Printf("当前 Gas Price: %s gwei (%s)\n", FormatGwei(est.GasPrice), gasType)
	fmt.Printf("安全系数: %.1fx\n\n", est.SafetyFactor)

	fmt.Println("📋 操作明细:")
	printLine := func(e GasEstimate) {
		fmt.Printf("  %-28s gasLimit: %-10d 每笔需要: %s %s\n",
			fmt.Sprintf("%s × %d", e.Operation, e.Count),
			e.GasLimit,
			FormatWeiToETH(e.RequiredWei),
			est.NativeSymbol)
	}
	printLine(est.Approve)
	printLine(est.AddReceiptWallets)
	printLine(est.SweepReceipt)
	printLine(est.SweepManager)

	fmt.Println()
	fmt.Println("💰 资金需求:")
	fmt.Printf("  每个 receipt wallet 需转入: %s %s (approve + sweep)\n", FormatWeiToETH(est.PerReceiptWallet), est.NativeSymbol)
	fmt.Printf("  manager 需转入:            %s %s (addReceiptWallets + sweep)\n", FormatWeiToETH(est.ManagerTotal), est.NativeSymbol)
	fmt.Printf("  批量转 gas 手续费:          %s %s (%d 笔转账)\n", FormatWeiToETH(est.FundingFeeTotal), est.NativeSymbol, est.FundTransfer.Count)
	fmt.Println("  ────────────────────────────────────")
	fmt.Printf("  总计需要商户钱包余额:       %s %s\n\n", FormatWeiToETH(est.MerchantTotal), est.NativeSymbol)

	suffIcon := "✅ 充足"
	if !est.Sufficient {
		suffIcon = "❌ 不足"
	}
	fmt.Printf("  当前商户钱包余额:           %s %s %s\n\n", FormatWeiToETH(est.MerchantBalance), est.NativeSymbol, suffIcon)
}
