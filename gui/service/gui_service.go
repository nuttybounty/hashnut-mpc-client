// Package service 提供 GUI 层与 MerchantClient 之间的桥接。
// GUI 开发者只需要调用本包的方法，不需要理解 MPC 协议细节。
// 安全原则：私钥和密码只在本层短暂经过，立即传入 client 层处理后清零。
package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hashnut-mpc-client/client"
	"hashnut-mpc-client/client/statemachine"
	"hashnut-mpc-client/storage/dal/model"
	"hashnut-mpc-client/util/encrypt_util"
	"hashnut-mpc-client/util/tx_util"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	tron_client "github.com/fbsobreira/gotron-sdk/pkg/client"
	"gorm.io/gorm"
)

// ---- MPC 业务端点 ----
const (
	EndpointSignApprove    = "/api/v4.0.0/mpc/receipt/sign/approve"
	EndpointSignAddWallets = "/api/v4.0.0/mpc/receipt/sign/add-wallets"
	EndpointSignSweep      = "/api/v4.0.0/mpc/receipt/sign/sweep"
	EndpointSignUpgrade    = "/api/v4.0.0/mpc/manager/sign/upgrade"
)

// ---- 返回给 GUI 的安全数据结构（不含私钥/密码/MPC 分片）----

type WalletInfo struct {
	Address   string
	ChainType string
	IsDefault bool
}

type ChainInfo struct {
	Chain     string
	ChainID   int32
	ChainType string
	Currency  string
}

type SplitWalletInfo struct {
	Address            string
	Chain              string
	Merchant           string
	Alias              string
	SplitWalletManager string
	State              int
	ActivateTxID       string
	ProxyAdmin         string
}

// GUIService 是 GUI 层唯一的业务入口。
type GUIService struct {
	mc            *client.MerchantClient
	batchSetupMgr *statemachine.BatchSetupMgr
	unlocked      bool
	mu            sync.RWMutex
}

func NewGUIService(payServerURL string) *GUIService {
	mc := client.NewMerchantClient(payServerURL)
	return &GUIService{mc: mc}
}

// ---- 密码管理 ----

func (s *GUIService) HasPassword() bool {
	_, _, err := s.mc.GetPasswordAuth()
	return err == nil
}

func (s *GUIService) SetPassword(password string) error {
	defer clearBytes([]byte(password))

	salt, err := encrypt_util.GenerateRandomBytes(16)
	if err != nil {
		return fmt.Errorf("生成盐失败: %w", err)
	}
	derivedKey := encrypt_util.DeriveKey(password, salt)
	if err := s.mc.SavePasswordAuth(salt, derivedKey); err != nil {
		return fmt.Errorf("保存密码失败: %w", err)
	}

	s.mc.SetPassword(password)
	if err := s.mc.Start(context.Background()); err != nil {
		return fmt.Errorf("启动客户端失败: %w", err)
	}

	s.mu.Lock()
	s.unlocked = true
	s.batchSetupMgr = statemachine.NewBatchSetupMgr(s.mc.GetStorageMgr().GetDB())
	s.mu.Unlock()
	return nil
}

func (s *GUIService) VerifyPassword(password string) error {
	defer clearBytes([]byte(password))

	salt, hash, err := s.mc.GetPasswordAuth()
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("尚未设置密码")
		}
		return fmt.Errorf("读取密码记录失败: %w", err)
	}

	derivedKey := encrypt_util.DeriveKey(password, salt)
	if subtle.ConstantTimeCompare(derivedKey, hash) != 1 {
		return fmt.Errorf("密码错误")
	}

	s.mc.SetPassword(password)
	if err := s.mc.Start(context.Background()); err != nil {
		return fmt.Errorf("启动客户端失败: %w", err)
	}

	s.mu.Lock()
	s.unlocked = true
	s.batchSetupMgr = statemachine.NewBatchSetupMgr(s.mc.GetStorageMgr().GetDB())
	s.mu.Unlock()
	return nil
}

func (s *GUIService) IsUnlocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unlocked
}

// ---- 钱包管理（不暴露私钥）----

// ImportWallet 导入钱包。私钥在本方法内加密存储后立即清零。
func (s *GUIService) ImportWallet(chainType, privateKeyHex string) error {
	defer clearBytes([]byte(privateKeyHex))
	if !s.IsUnlocked() {
		return fmt.Errorf("请先解锁")
	}

	privKeyHex := strings.TrimPrefix(privateKeyHex, "0x")
	if len(privKeyHex) != 64 {
		return fmt.Errorf("私钥格式错误，应为64位十六进制字符串")
	}

	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return fmt.Errorf("解析私钥失败: %w", err)
	}
	defer clearBytes(privBytes)

	var merchantAddress string
	switch strings.ToLower(chainType) {
	case "evm":
		privateKey, err := crypto.ToECDSA(privBytes)
		if err != nil {
			return fmt.Errorf("生成ECDSA私钥失败: %w", err)
		}
		merchantAddress = strings.ToLower(crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
		zeroPrivateKey(privateKey)
	case "tron":
		tronAddr, err := tx_util.PrivateHexToTronAddress(privKeyHex)
		if err != nil {
			return fmt.Errorf("转换Tron地址失败: %w", err)
		}
		merchantAddress = tronAddr.String()
	default:
		return fmt.Errorf("不支持的链类型: %s", chainType)
	}

	encKey, err := encrypt_util.Encrypt(privBytes, s.mc.GetPassword())
	if err != nil {
		return fmt.Errorf("加密私钥失败: %w", err)
	}

	encKeyJSON, err := json.Marshal(encKey)
	if err != nil {
		return fmt.Errorf("序列化加密数据失败: %w", err)
	}

	if err := s.mc.SaveMerchantWallet(merchantAddress, strings.ToLower(chainType), encKeyJSON); err != nil {
		return err
	}
	// 保存后刷新 wallet context，加载私钥到内存
	return s.mc.ReloadWalletContext()
}

// ListWallets 返回所有钱包（只有地址和链信息，不含私钥）
func (s *GUIService) ListWallets() ([]WalletInfo, error) {
	if !s.IsUnlocked() {
		return nil, fmt.Errorf("请先解锁")
	}
	wallets, err := s.mc.GetAllMerchantWallets()
	if err != nil {
		return nil, err
	}
	var result []WalletInfo
	for _, w := range wallets {
		result = append(result, WalletInfo{
			Address:   w.Address,
			ChainType: w.ChainType,
			IsDefault: w.IsDefault,
		})
	}
	return result, nil
}

func (s *GUIService) SwitchWallet(address string) error {
	if !s.IsUnlocked() {
		return fmt.Errorf("请先解锁")
	}
	return s.mc.SetDefaultWallet(address)
}

func (s *GUIService) GetCurrentWallet() (*WalletInfo, error) {
	if !s.IsUnlocked() {
		return nil, fmt.Errorf("请先解锁")
	}
	ctx := s.mc.GetWalletContext()
	if ctx == nil {
		return nil, nil
	}
	return &WalletInfo{Address: ctx.Address}, nil
}

// ---- 链管理 ----

func (s *GUIService) ListChains() ([]ChainInfo, error) {
	if !s.IsUnlocked() {
		return nil, fmt.Errorf("请先解锁")
	}
	chains := s.mc.GetRemoteConfig().ListChains()
	var result []ChainInfo
	for _, c := range chains {
		result = append(result, ChainInfo{
			Chain:     c.Chain,
			ChainID:   c.ChainID,
			ChainType: c.ChainType,
			Currency:  c.Currency,
		})
	}
	return result, nil
}

func (s *GUIService) GetCurrentChain() (string, error) {
	if !s.IsUnlocked() {
		return "", fmt.Errorf("请先解锁")
	}
	return s.mc.GetDefaultChain()
}

func (s *GUIService) SwitchChain(chain string) error {
	if !s.IsUnlocked() {
		return fmt.Errorf("请先解锁")
	}
	return s.mc.SetDefaultChain(chain)
}

// ---- Split Wallet ----

func (s *GUIService) FetchSplitWallets(chain string) error {
	if !s.IsUnlocked() {
		return fmt.Errorf("请先解锁")
	}
	return s.mc.FetchSplitWallets(context.Background(), chain)
}

func (s *GUIService) ListSplitWallets() ([]SplitWalletInfo, error) {
	if !s.IsUnlocked() {
		return nil, fmt.Errorf("请先解锁")
	}
	wallets, err := s.mc.GetAllSplitWallets()
	if err != nil {
		return nil, err
	}
	var result []SplitWalletInfo
	for _, w := range wallets {
		result = append(result, toSplitWalletInfo(w))
	}
	return result, nil
}

// TokenInfo token 信息
type TokenInfo struct {
	Symbol   string
	Chain    string
	Contract string
	Name     string
}

// ListTokensByChain 从后端查询指定链支持的 token 列表
func (s *GUIService) ListTokensByChain(chain string) ([]TokenInfo, error) {
	if !s.IsUnlocked() {
		return nil, fmt.Errorf("请先解锁")
	}
	ctx := context.Background()
	coins, err := s.mc.QueryCoinInfo(ctx, chain)
	if err != nil {
		return nil, err
	}
	var result []TokenInfo
	for _, c := range coins {
		result = append(result, TokenInfo{
			Symbol:   c.CoinCode,
			Chain:    c.Chain,
			Contract: c.ContractAddress,
			Name:     c.CoinDesc,
		})
	}
	return result, nil
}

// ListSplitWalletsByChainAndMerchant 返回当前链+当前钱包的分账合约
func (s *GUIService) ListSplitWalletsByChainAndMerchant() ([]SplitWalletInfo, error) {
	if !s.IsUnlocked() {
		return nil, fmt.Errorf("请先解锁")
	}
	wallets, err := s.mc.GetAllSplitWallets()
	if err != nil {
		return nil, err
	}
	ctx := s.mc.GetWalletContext()
	if ctx == nil {
		return nil, nil
	}
	var result []SplitWalletInfo
	for _, w := range wallets {
		if w.Chain == ctx.Chain && equalsIgnoreCase(w.Merchant, ctx.Address) {
			result = append(result, toSplitWalletInfo(w))
		}
	}
	return result, nil
}

// ListActiveSplitWallets 返回当前链+当前钱包的 ACTIVE 状态分账合约
func (s *GUIService) ListActiveSplitWallets() ([]SplitWalletInfo, error) {
	all, err := s.ListSplitWalletsByChainAndMerchant()
	if err != nil {
		return nil, err
	}
	var result []SplitWalletInfo
	for _, sw := range all {
		if sw.State >= 7 { // ACTIVE
			result = append(result, sw)
		}
	}
	return result, nil
}

func equalsIgnoreCase(a, b string) bool {
	return len(a) > 0 && len(b) > 0 &&
		(a == b || strings.EqualFold(a, b))
}

func (s *GUIService) GetReceiptsBySplitter(splitter string) ([]string, error) {
	if !s.IsUnlocked() {
		return nil, fmt.Errorf("请先解锁")
	}
	return s.mc.GetReceiptsBySplitter(splitter)
}

// ---- 激活 Split Wallet ----

func (s *GUIService) ActivateSplitWallet(ctx context.Context, splitterAddress string, logFn func(string)) error {
	if !s.IsUnlocked() {
		return fmt.Errorf("请先解锁")
	}
	mc := s.mc

	splitWallet, err := mc.GetSplit(splitterAddress)
	if err != nil || splitWallet == nil {
		return fmt.Errorf("查询分账合约失败，请先执行同步")
	}
	if splitWallet.State >= 7 {
		logFn("split wallet 已经是 ACTIVE")
		return nil
	}

	logFn("正在查询激活状态...")
	activationInfo, err := mc.InitSplitWalletActivation(ctx, splitWallet.Chain, splitterAddress)
	if err != nil {
		return fmt.Errorf("初始化激活失败: %v", err)
	}
	if activationInfo.State >= 7 {
		logFn("split wallet 已经是 ACTIVE，正在同步本地状态...")
		_ = mc.FetchSplitWallets(ctx, splitWallet.Chain)
		return nil
	}

	// 检查本地 manager
	localManager, err := mc.GetLocalSplitWalletManager(splitterAddress)
	if err != nil {
		logFn("本地无 manager 记录，将通过 MPC keygen 生成")
	}

	managerAddress := localManager
	if managerAddress == "" && activationInfo.ManagerAddress != "" {
		return fmt.Errorf("服务端已存在 manager %s，但本地没有对应 MPC 密钥分片", activationInfo.ManagerAddress)
	}
	if managerAddress == "" {
		logFn("正在通过 MPC keygen 生成 Split Wallet Manager...")
		managerAddress, err = mc.ManagerKeygen(ctx, splitWallet.Chain, splitterAddress)
		if err != nil {
			return fmt.Errorf("生成 manager 地址失败: %v", err)
		}
		logFn(fmt.Sprintf("Manager 生成成功: %s", managerAddress))
	} else {
		logFn(fmt.Sprintf("使用已有 Manager: %s", managerAddress))
	}

	// 注册 manager
	if activationInfo.ManagerAddress == "" {
		logFn("注册 manager 到服务端...")
		if err := mc.RegisterActivationManager(ctx, splitWallet.Chain, splitterAddress, managerAddress); err != nil {
			return fmt.Errorf("注册 manager 失败: %v", err)
		}
	} else if activationInfo.ManagerAddress != managerAddress {
		return fmt.Errorf("服务端 manager %s 与本地 manager %s 不一致", activationInfo.ManagerAddress, managerAddress)
	}

	logFn("正在构造并发送 activate 交易...")
	walletCtx := mc.GetWalletContext()
	var txIDStr string

	if tx_util.IsEvm(splitWallet.Chain) {
		txIDStr, err = s.activateOnEvm(ctx, splitWallet.Chain, splitterAddress, managerAddress, activationInfo.ProxyAdmin, walletCtx)
	} else if tx_util.IsTron(splitWallet.Chain) {
		txIDStr, err = s.activateOnTron(ctx, splitWallet.Chain, splitterAddress, managerAddress, activationInfo.ProxyAdmin, walletCtx)
	} else {
		return fmt.Errorf("暂不支持的链: %s", splitWallet.Chain)
	}
	if err != nil {
		return err
	}
	explorerLink := s.GetExplorerTxUrl(splitWallet.Chain, txIDStr)
	if explorerLink != "" {
		logFn(fmt.Sprintf("activate 交易已发送: %s\n  浏览器: %s", txIDStr, explorerLink))
	} else {
		logFn(fmt.Sprintf("activate 交易已发送: %s", txIDStr))
	}

	// 提交到服务端
	if err := mc.CommitSplitWalletActivation(ctx, splitWallet.Chain, splitterAddress, txIDStr); err != nil {
		return fmt.Errorf("提交激活交易到服务端失败: %v", err)
	}
	logFn("激活交易已提交，服务端将在链上确认后自动完成激活")

	_ = mc.FetchSplitWallets(ctx, splitWallet.Chain)
	return nil
}

func (s *GUIService) activateOnEvm(ctx context.Context, chain, splitterAddress, managerAddress, proxyAdminAddr string, walletCtx *client.WalletContext) (string, error) {
	chainConfig, err := s.mc.GetChainConfig(chain)
	if err != nil {
		return "", fmt.Errorf("获取链配置失败: %v", err)
	}
	chainID := big.NewInt(int64(chainConfig.ChainID))

	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return "", err
	}
	defer ethClient.Close()

	if err := s.checkEvmNonceHealth(ctx, ethClient, walletCtx.Address); err != nil {
		return "", err
	}

	owner := common.HexToAddress(walletCtx.Address)
	splitter := common.HexToAddress(splitterAddress)
	manager := common.HexToAddress(managerAddress)

	var proxyAdmin common.Address
	if proxyAdminAddr != "" {
		proxyAdmin = common.HexToAddress(proxyAdminAddr)
	} else {
		proxyAdmin, err = tx_util.GetSplitWalletProxyAdmin(ctx, ethClient, splitter)
		if err != nil {
			return "", fmt.Errorf("读取 proxy admin 失败: %v", err)
		}
	}

	data, err := tx_util.BuildSplitWalletActivateData(manager, proxyAdmin)
	if err != nil {
		return "", fmt.Errorf("构建 activate data 失败: %v", err)
	}

	tx, err := tx_util.BuildLegacyRawTx(ctx, ethClient, *chainID, owner, splitter, *big.NewInt(0), data)
	if err != nil {
		return "", fmt.Errorf("构造 activate 交易失败: %v", err)
	}

	signer := types.NewLondonSigner(chainID)
	signedTx, err := types.SignTx(tx, signer, walletCtx.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("owner 钱包签名失败: %v", err)
	}

	txID, err := tx_util.SendRawTransaction(ctx, ethClient, signedTx)
	if err != nil {
		return "", fmt.Errorf("发送 activate 交易失败: %v", err)
	}
	txIDHex := "0x" + hex.EncodeToString(txID)

	if err := s.waitTxConfirmations(ctx, ethClient, []string{txIDHex}, 120*time.Second); err != nil {
		return txIDHex, fmt.Errorf("activate 交易确认失败: %v", err)
	}
	return txIDHex, nil
}

func (s *GUIService) activateOnTron(ctx context.Context, chain, splitterAddress, managerAddress, proxyAdminAddr string, walletCtx *client.WalletContext) (string, error) {
	tronClient, err := s.createTronClient(chain)
	if err != nil {
		return "", err
	}
	defer tronClient.Conn.Close()

	proxyAdmin := proxyAdminAddr
	if proxyAdmin == "" {
		proxyAdmin, err = tx_util.GetTronSplitWalletProxyAdmin(tronClient, splitterAddress, walletCtx.Address)
		if err != nil {
			return "", fmt.Errorf("读取 proxy admin 失败: %v", err)
		}
	}

	activateParams := tx_util.NewActivateParams(splitterAddress, managerAddress, proxyAdmin)
	rawTx, hashBytes, err := tx_util.CreateTronTransferRaw(tronClient, walletCtx.Address, activateParams)
	if err != nil {
		return "", fmt.Errorf("构造 activate 交易失败: %v", err)
	}

	signedBytes, err := tx_util.SignWithPrivateKey(walletCtx.PrivateKey, hashBytes)
	if err != nil {
		return "", fmt.Errorf("owner 钱包签名失败: %v", err)
	}
	if err := tx_util.SignTronTransaction(rawTx, hex.EncodeToString(signedBytes)); err != nil {
		return "", fmt.Errorf("添加签名失败: %v", err)
	}

	txID, err := tx_util.BroadcastTronTransaction(tronClient, rawTx)
	if err != nil {
		return "", fmt.Errorf("广播 activate 交易失败: %v", err)
	}

	time.Sleep(6 * time.Second) // 等待 Tron 确认
	return txID, nil
}

// ---- Gas 评估 ----

func (s *GUIService) EstimateBatchSetup(splitter string, count int) (*tx_util.BatchSetupEstimate, error) {
	if !s.IsUnlocked() {
		return nil, fmt.Errorf("请先解锁")
	}
	splitWallet, err := s.mc.GetSplit(splitter)
	if err != nil || splitWallet == nil {
		return nil, fmt.Errorf("查询分账合约失败")
	}
	chainConfig, err := s.mc.GetChainConfig(splitWallet.Chain)
	if err != nil {
		return nil, fmt.Errorf("获取链配置失败: %w", err)
	}
	ethClient, err := s.createEthClient(splitWallet.Chain)
	if err != nil {
		return nil, err
	}
	defer ethClient.Close()

	walletCtx := s.mc.GetWalletContext()
	merchantAddr := common.HexToAddress(walletCtx.Address)

	return tx_util.EstimateBatchSetup(context.Background(), ethClient, merchantAddr, splitWallet.Chain, chainConfig.Currency, count, 0)
}

// TxFeeEstimate 通用交易费用评估结果（归集/提现共用）
type TxFeeEstimate struct {
	Chain         string
	NativeSymbol  string
	Operation     string // "归集" / "提现"
	BatchCount    int    // 批次数（归集用）
	TotalReceipts uint64 // receipt wallet 总数（归集用）
	EstimatedFee  string // 预估单笔手续费
	TotalFee      string // 预估总手续费
	WalletBalance string // 当前钱包余额
	Sufficient    bool   // 余额是否充足
}

// EstimateClaimFee 评估归集手续费
func (s *GUIService) EstimateClaimFee(splitter, token string, batchSize int) (*TxFeeEstimate, error) {
	if !s.IsUnlocked() {
		return nil, fmt.Errorf("请先解锁")
	}
	splitWallet, err := s.mc.GetSplit(splitter)
	if err != nil || splitWallet == nil {
		return nil, fmt.Errorf("查询分账合约失败")
	}
	chainConfig, err := s.mc.GetChainConfig(splitWallet.Chain)
	if err != nil {
		return nil, fmt.Errorf("获取链配置失败: %w", err)
	}
	walletCtx := s.mc.GetWalletContext()
	if walletCtx == nil || walletCtx.Address == "" {
		return nil, fmt.Errorf("请先导入商户钱包")
	}

	if strings.ToLower(chainConfig.ChainType) == "tron" {
		return s.estimateClaimFeeTron(splitWallet.Chain, chainConfig.Currency, splitter, walletCtx.Address, batchSize)
	}
	return s.estimateClaimFeeEvm(splitWallet.Chain, chainConfig.Currency, splitter, walletCtx.Address, batchSize)
}

func (s *GUIService) estimateClaimFeeEvm(chain, currency, splitter, merchantAddr string, batchSize int) (*TxFeeEstimate, error) {
	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return nil, err
	}
	defer ethClient.Close()
	ctx := context.Background()

	splitterAddr := common.HexToAddress(splitter)
	totalCount, err := tx_util.GetReceiptWalletCount(ctx, ethClient, splitterAddr)
	if err != nil {
		return nil, fmt.Errorf("查询 receipt wallet 数量失败: %v", err)
	}
	total := totalCount.Uint64()
	batchCount := int((total + uint64(batchSize) - 1) / uint64(batchSize))
	if batchCount == 0 {
		batchCount = 1
	}

	gasPrice, err := ethClient.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取 gas price 失败: %v", err)
	}
	// claimReceiptERC20Tokens gas 估算: 基础 50000 + 每个 wallet 约 30000
	perBatchGas := uint64(50000) + uint64(batchSize)*30000
	perBatchFee := new(big.Int).Mul(new(big.Int).SetUint64(perBatchGas), gasPrice)
	totalFee := new(big.Int).Mul(perBatchFee, big.NewInt(int64(batchCount)))
	// 安全系数 1.5
	totalFeeWithBuffer := new(big.Int).Mul(totalFee, big.NewInt(150))
	totalFeeWithBuffer.Div(totalFeeWithBuffer, big.NewInt(100))

	balance, err := ethClient.BalanceAt(ctx, common.HexToAddress(merchantAddr), nil)
	if err != nil {
		return nil, fmt.Errorf("查询余额失败: %v", err)
	}

	return &TxFeeEstimate{
		Chain:         chain,
		NativeSymbol:  currency,
		Operation:     "归集",
		BatchCount:    batchCount,
		TotalReceipts: total,
		EstimatedFee:  tx_util.FormatWeiToETH(perBatchFee),
		TotalFee:      tx_util.FormatWeiToETH(totalFeeWithBuffer),
		WalletBalance: tx_util.FormatWeiToETH(balance),
		Sufficient:    balance.Cmp(totalFeeWithBuffer) >= 0,
	}, nil
}

func (s *GUIService) estimateClaimFeeTron(chain, currency, splitter, merchantAddr string, batchSize int) (*TxFeeEstimate, error) {
	tronClient, err := s.createTronClient(chain)
	if err != nil {
		return nil, err
	}
	defer tronClient.Conn.Close()

	total, err := tx_util.GetTronReceiptWalletCount(tronClient, splitter, merchantAddr)
	if err != nil {
		return nil, fmt.Errorf("查询 receipt wallet 数量失败: %v", err)
	}
	batchCount := int((total + uint64(batchSize) - 1) / uint64(batchSize))
	if batchCount == 0 {
		batchCount = 1
	}

	// Tron claimReceiptERC20Tokens 能量费约 30~80 TRX/批，按 100 TRX 估算
	perBatchFee := int64(100_000_000) // 100 TRX
	totalFee := perBatchFee * int64(batchCount)
	totalFeeWithBuffer := totalFee * 150 / 100

	balance, err := tx_util.GetTRXBalance(tronClient, merchantAddr)
	if err != nil {
		return nil, fmt.Errorf("查询 TRX 余额失败: %v", err)
	}

	return &TxFeeEstimate{
		Chain:         chain,
		NativeSymbol:  currency,
		Operation:     "归集",
		BatchCount:    batchCount,
		TotalReceipts: total,
		EstimatedFee:  tx_util.FormatSUN(big.NewInt(perBatchFee)),
		TotalFee:      tx_util.FormatSUN(big.NewInt(totalFeeWithBuffer)),
		WalletBalance: tx_util.FormatSUN(balance),
		Sufficient:    balance.Int64() >= totalFeeWithBuffer,
	}, nil
}

// EstimateReleaseFee 评估提现手续费
func (s *GUIService) EstimateReleaseFee(splitter, token string) (*TxFeeEstimate, error) {
	if !s.IsUnlocked() {
		return nil, fmt.Errorf("请先解锁")
	}
	splitWallet, err := s.mc.GetSplit(splitter)
	if err != nil || splitWallet == nil {
		return nil, fmt.Errorf("查询分账合约失败")
	}
	chainConfig, err := s.mc.GetChainConfig(splitWallet.Chain)
	if err != nil {
		return nil, fmt.Errorf("获取链配置失败: %w", err)
	}
	walletCtx := s.mc.GetWalletContext()
	if walletCtx == nil || walletCtx.Address == "" {
		return nil, fmt.Errorf("请先导入商户钱包")
	}

	if strings.ToLower(chainConfig.ChainType) == "tron" {
		return s.estimateReleaseFeeTron(splitWallet.Chain, chainConfig.Currency, splitter, token, walletCtx.Address)
	}
	return s.estimateReleaseFeeEvm(splitWallet.Chain, chainConfig.Currency, splitter, token, walletCtx.Address)
}

func (s *GUIService) estimateReleaseFeeEvm(chain, currency, splitter, token, merchantAddr string) (*TxFeeEstimate, error) {
	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return nil, err
	}
	defer ethClient.Close()
	ctx := context.Background()

	gasPrice, err := ethClient.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取 gas price 失败: %v", err)
	}
	// releaseERC20Tokens gas 约 80000~150000，按 150000 估算
	gasLimit := uint64(150000)
	fee := new(big.Int).Mul(new(big.Int).SetUint64(gasLimit), gasPrice)
	feeWithBuffer := new(big.Int).Mul(fee, big.NewInt(150))
	feeWithBuffer.Div(feeWithBuffer, big.NewInt(100))

	balance, err := ethClient.BalanceAt(ctx, common.HexToAddress(merchantAddr), nil)
	if err != nil {
		return nil, fmt.Errorf("查询余额失败: %v", err)
	}

	return &TxFeeEstimate{
		Chain:         chain,
		NativeSymbol:  currency,
		Operation:     "提现",
		BatchCount:    1,
		EstimatedFee:  tx_util.FormatWeiToETH(fee),
		TotalFee:      tx_util.FormatWeiToETH(feeWithBuffer),
		WalletBalance: tx_util.FormatWeiToETH(balance),
		Sufficient:    balance.Cmp(feeWithBuffer) >= 0,
	}, nil
}

func (s *GUIService) estimateReleaseFeeTron(chain, currency, splitter, token, merchantAddr string) (*TxFeeEstimate, error) {
	tronClient, err := s.createTronClient(chain)
	if err != nil {
		return nil, err
	}
	defer tronClient.Conn.Close()

	// releaseERC20Tokens 能量费约 20~50 TRX，按 80 TRX 估算
	fee := int64(80_000_000) // 80 TRX
	feeWithBuffer := fee * 150 / 100

	balance, err := tx_util.GetTRXBalance(tronClient, merchantAddr)
	if err != nil {
		return nil, fmt.Errorf("查询 TRX 余额失败: %v", err)
	}

	return &TxFeeEstimate{
		Chain:         chain,
		NativeSymbol:  currency,
		Operation:     "提现",
		BatchCount:    1,
		EstimatedFee:  tx_util.FormatSUN(big.NewInt(fee)),
		TotalFee:      tx_util.FormatSUN(big.NewInt(feeWithBuffer)),
		WalletBalance: tx_util.FormatSUN(balance),
		Sufficient:    balance.Int64() >= feeWithBuffer,
	}, nil
}

// BatchSetupFeeEstimate 通用批量创建费用评估结果（EVM + Tron 共用）
type BatchSetupFeeEstimate struct {
	Chain          string
	NativeSymbol   string
	WalletCount    int
	PerReceipt     string // 每个 receipt wallet 需转入
	ManagerTotal   string // manager 需转入
	TransferFee    string // 转账手续费
	TotalRequired  string // 总计需要
	WalletBalance  string // 当前余额
	Sufficient     bool   // 余额是否充足（>= 总需 × 1.5）
	MinBalance     string // 最低余额要求（总需 × 1.5）
}

// EstimateBatchSetupFee 评估批量创建的费用（EVM + Tron 通用入口）
func (s *GUIService) EstimateBatchSetupFee(splitter string, count int) (*BatchSetupFeeEstimate, error) {
	if !s.IsUnlocked() {
		return nil, fmt.Errorf("请先解锁")
	}
	splitWallet, err := s.mc.GetSplit(splitter)
	if err != nil || splitWallet == nil {
		return nil, fmt.Errorf("查询分账合约失败")
	}
	chainConfig, err := s.mc.GetChainConfig(splitWallet.Chain)
	if err != nil {
		return nil, fmt.Errorf("获取链配置失败: %w", err)
	}
	walletCtx := s.mc.GetWalletContext()
	if walletCtx == nil || walletCtx.Address == "" {
		return nil, fmt.Errorf("请先导入商户钱包")
	}

	if strings.ToLower(chainConfig.ChainType) == "tron" {
		return s.estimateBatchSetupTron(splitWallet.Chain, chainConfig.Currency, walletCtx.Address, splitter, count)
	}
	return s.estimateBatchSetupEvm(splitter, chainConfig.Currency, count)
}

func (s *GUIService) estimateBatchSetupEvm(splitter, currency string, count int) (*BatchSetupFeeEstimate, error) {
	est, err := s.EstimateBatchSetup(splitter, count)
	if err != nil {
		return nil, err
	}
	// 最低余额 = 总需 × 1.5
	minBalance := new(big.Int).Mul(est.MerchantTotal, big.NewInt(150))
	minBalance.Div(minBalance, big.NewInt(100))

	return &BatchSetupFeeEstimate{
		Chain:         est.Chain,
		NativeSymbol:  currency,
		WalletCount:   count,
		PerReceipt:    tx_util.FormatWeiToETH(est.PerReceiptWallet),
		ManagerTotal:  tx_util.FormatWeiToETH(est.ManagerTotal),
		TransferFee:   tx_util.FormatWeiToETH(est.FundingFeeTotal),
		TotalRequired: tx_util.FormatWeiToETH(est.MerchantTotal),
		WalletBalance: tx_util.FormatWeiToETH(est.MerchantBalance),
		Sufficient:    est.MerchantBalance.Cmp(minBalance) >= 0,
		MinBalance:    tx_util.FormatWeiToETH(minBalance),
	}, nil
}

func (s *GUIService) estimateBatchSetupTron(chain, currency, merchantAddr, splitter string, count int) (*BatchSetupFeeEstimate, error) {
	tronClient, err := s.createTronClient(chain)
	if err != nil {
		return nil, err
	}
	defer tronClient.Conn.Close()

	balance, err := tx_util.GetTRXBalance(tronClient, merchantAddr)
	if err != nil {
		return nil, fmt.Errorf("查询 TRX 余额失败: %v", err)
	}

	// 动态估算 approve 能量费用（用商户地址模拟一笔 approve 调用）
	perReceipt := int64(8_000_000) // 默认 8 TRX 兜底
	approveParams := tx_util.NewApproveParams(
		"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", // USDT 合约地址（估算用，实际合约不影响能量消耗）
		splitter,
		big.NewInt(1_000_000_000), // 1000 USDT（估算用）
	)
	if approveEstimate, err := tx_util.EstimateTronContractFee(tronClient, merchantAddr, approveParams); err == nil && approveEstimate > 0 {
		perReceipt = approveEstimate
	}

	// 动态估算 addReceiptWallets 能量费用
	// 必须用 manager 地址作为 from（合约校验 msg.sender == splitWalletManager）
	perManager := int64(50_000_000) // 默认 50 TRX 兜底
	splitWallet, _ := s.mc.GetSplit(splitter)
	if splitWallet != nil && splitWallet.SplitWalletManager != "" {
		addParams := tx_util.NewAddReceiptWalletsParams(splitter, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", []string{merchantAddr}, big.NewInt(0))
		if addEstimate, err := tx_util.EstimateTronContractFee(tronClient, splitWallet.SplitWalletManager, addParams); err == nil && addEstimate > 0 {
			baseEnergy := addEstimate
			perManager = baseEnergy + baseEnergy*int64(count-1)/2
		}
	}

	perTransfer := int64(1_100_000) // ~1.1 TRX (每笔 TRX 转账带宽费)
	transferCount := int64(count) + 1
	transferFee := perTransfer * transferCount
	receiptTotal := perReceipt * int64(count)
	totalRequired := receiptTotal + perManager + transferFee
	minBalance := totalRequired * 150 / 100

	return &BatchSetupFeeEstimate{
		Chain:         chain,
		NativeSymbol:  currency,
		WalletCount:   count,
		PerReceipt:    tx_util.FormatSUN(big.NewInt(perReceipt)),
		ManagerTotal:  tx_util.FormatSUN(big.NewInt(perManager)),
		TransferFee:   tx_util.FormatSUN(big.NewInt(transferFee)),
		TotalRequired: tx_util.FormatSUN(big.NewInt(totalRequired)),
		WalletBalance: tx_util.FormatSUN(balance),
		Sufficient:    balance.Int64() >= minBalance,
		MinBalance:    tx_util.FormatSUN(big.NewInt(minBalance)),
	}, nil
}

// ---- 余额查询 ----

func (s *GUIService) GetNativeBalance(chain, address string) (string, error) {
	if !s.IsUnlocked() {
		return "", fmt.Errorf("请先解锁")
	}
	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return "", err
	}
	defer ethClient.Close()

	balance, err := ethClient.BalanceAt(context.Background(), common.HexToAddress(address), nil)
	if err != nil {
		return "", err
	}
	return tx_util.FormatWeiToETH(balance), nil
}

// ---- 获取底层 MerchantClient（仅供 service 包内部或高级操作）----

func (s *GUIService) GetMerchantClient() *client.MerchantClient {
	return s.mc
}

// GetExplorerTxUrl 构建交易的区块浏览器链接
func (s *GUIService) GetExplorerTxUrl(chain, txId string) string {
	return s.mc.GetRemoteConfig().GetExplorerTxUrl(chain, txId)
}

// ---- 批量创建地址 ----

// BatchSetup 执行完整的批量地址创建流程（7 步），logFn 用于输出日志到 GUI
func (s *GUIService) BatchSetup(ctx context.Context, splitter, token, amount string, count int, logFn func(string)) error {
	if !s.IsUnlocked() {
		return fmt.Errorf("请先解锁")
	}
	mc := s.mc

	// 校验 split wallet 状态
	splitWallet, err := mc.GetSplit(splitter)
	if err != nil || splitWallet == nil {
		return fmt.Errorf("查询分账合约失败，请先执行同步")
	}
	if splitWallet.State < 7 {
		logFn("本地状态未激活，正在从服务端同步...")
		if fetchErr := mc.FetchSplitWallets(ctx, splitWallet.Chain); fetchErr != nil {
			return fmt.Errorf("同步状态失败: %v", fetchErr)
		}
		splitWallet, err = mc.GetSplit(splitter)
		if err != nil || splitWallet == nil || splitWallet.State < 7 {
			return fmt.Errorf("split wallet 尚未激活，请先执行 splitter activate")
		}
	}
	if splitWallet.SplitWalletManager == "" {
		return fmt.Errorf("未找到 split wallet manager")
	}

	chain := splitWallet.Chain
	managerAddress := splitWallet.SplitWalletManager

	// 查找未完成的 session（支持断点恢复）
	bsSession := s.batchSetupMgr.FindPendingSession(splitter, token, count)
	if bsSession != nil && bsSession.State != statemachine.BSStateInit {
		logFn(fmt.Sprintf("发现未完成的任务 (状态: %s)，从断点恢复...", bsSession.State))
	} else {
		// 创建新 session
		var createErr error
		bsSession, createErr = s.batchSetupMgr.CreateSession(splitter, token, amount, count)
		if createErr != nil {
			return fmt.Errorf("创建 batch setup session 失败: %v", createErr)
		}
	}

	var setupErr error
	if tx_util.IsEvm(chain) {
		setupErr = s.batchSetupEvm(ctx, mc, splitter, token, amount, count, chain, managerAddress, logFn)
	} else if tx_util.IsTron(chain) {
		setupErr = s.batchSetupTron(ctx, mc, splitter, token, amount, count, chain, managerAddress, logFn)
	} else {
		return fmt.Errorf("暂不支持的链: %s", chain)
	}

	if setupErr != nil {
		_ = s.batchSetupMgr.MarkFailed(bsSession, setupErr.Error())
		return setupErr
	}
	_ = s.batchSetupMgr.TransitionTo(bsSession, statemachine.TriggerRegisterDone)
	return nil
}

// pollTimeout 根据地址数量动态计算轮询超时时间
func pollTimeout(count int) time.Duration {
	base := 2 * time.Minute
	extra := time.Duration(count) * 15 * time.Second
	return base + extra
}

func (s *GUIService) batchSetupEvm(ctx context.Context, mc *client.MerchantClient, splitter, token, amount string, count int, chain, managerAddress string, logFn func(string)) error {
	chainConfig, err := mc.GetChainConfig(chain)
	if err != nil {
		return fmt.Errorf("获取链配置失败: %v", err)
	}
	chainID := big.NewInt(int64(chainConfig.ChainID))

	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return err
	}
	defer ethClient.Close()

	walletCtx := mc.GetWalletContext()
	if err := s.checkEvmNonceHealth(ctx, ethClient, walletCtx.Address); err != nil {
		return err
	}
	merchantAddr := common.HexToAddress(walletCtx.Address)

	est, err := tx_util.EstimateBatchSetup(ctx, ethClient, merchantAddr, chain, chainConfig.Currency, count, 0)
	if err != nil {
		return fmt.Errorf("Gas 评估失败: %v", err)
	}
	logFn(fmt.Sprintf("Gas 评估: 总计 %s %s (余额 %s %s)",
		tx_util.FormatWeiToETH(est.MerchantTotal), est.NativeSymbol,
		tx_util.FormatWeiToETH(est.MerchantBalance), est.NativeSymbol))
	if !est.Sufficient {
		return fmt.Errorf("商户钱包余额不足，请先充值")
	}

	startTime := time.Now()

	logFn(fmt.Sprintf("[1/7] 正在生成 %d 个收款地址...", count))
	receiptAddresses, err := s.batchKeygen(ctx, splitter, count, logFn)
	if err != nil {
		return fmt.Errorf("批量 keygen 失败: %v", err)
	}
	logFn(fmt.Sprintf("[1/7] 生成完成: %d 个地址", len(receiptAddresses)))

	logFn(fmt.Sprintf("[2/7] 转 gas 到 %d 个收款地址 + manager...", len(receiptAddresses)))
	var fundTargets []common.Address
	var fundAmounts []*big.Int
	for _, addr := range receiptAddresses {
		fundTargets = append(fundTargets, common.HexToAddress(addr))
		fundAmounts = append(fundAmounts, new(big.Int).Set(est.PerReceiptWallet))
	}
	fundTargets = append(fundTargets, common.HexToAddress(managerAddress))
	fundAmounts = append(fundAmounts, new(big.Int).Set(est.ManagerTotal))

	if err := s.batchFundGas(ctx, ethClient, chainID, walletCtx, fundTargets, fundAmounts, logFn); err != nil {
		return fmt.Errorf("批量转 gas 失败: %v", err)
	}
	logFn("[2/7] gas 转账完成")

	logFn(fmt.Sprintf("[3/7] 顺序 approve (%d 笔 MPC 签名)...", len(receiptAddresses)))
	amountWei, ok := new(big.Int).SetString(amount, 10)
	if !ok {
		return fmt.Errorf("无效的 approve 金额: %s", amount)
	}
	approveTxHashes, approvedReceipts, err := s.batchApprove(ctx, ethClient, chainID, chain, splitter, receiptAddresses, token, amountWei, logFn)
	if err != nil {
		return fmt.Errorf("批量 approve 失败: %v", err)
	}
	logFn(fmt.Sprintf("[3/5] approve %d/%d 广播完成", len(approveTxHashes), len(receiptAddresses)))

	logFn("  报告 approve 交易给后端...")
	if err := mc.SubmitApprove(ctx, chain, splitter, approvedReceipts, approveTxHashes, token, amountWei.String()); err != nil {
		return fmt.Errorf("submitApprove 失败: %v", err)
	}
	logFn("  等待链上 approve 确认...")
	if err := mc.PollReceiptState(ctx, chain, splitter, approvedReceipts, 3, pollTimeout(len(approvedReceipts))); err != nil {
		return fmt.Errorf("等待 approve 确认超时: %v", err)
	}
	logFn(fmt.Sprintf("[3/5] approve %d 笔链上确认完成", len(approveTxHashes)))

	logFn(fmt.Sprintf("[4/5] 将 %d 个地址注册到合约...", len(approvedReceipts)))
	activateTxHash, err := s.batchAddReceiptWallets(ctx, ethClient, chainID, chain, splitter, managerAddress, token, approvedReceipts, amountWei)
	if err != nil {
		return fmt.Errorf("addReceiptWallets 失败: %v", err)
	}
	logFn(fmt.Sprintf("[4/5] addReceiptWallets 交易广播: %s", activateTxHash))
	if err := mc.SubmitAddReceiptWallets(ctx, chain, splitter, approvedReceipts, activateTxHash); err != nil {
		return fmt.Errorf("submitAddReceiptWallets 失败: %v", err)
	}
	logFn("  等待链上 addReceiptWallets 确认...")
	if err := mc.PollReceiptState(ctx, chain, splitter, approvedReceipts, 5, pollTimeout(len(approvedReceipts))); err != nil {
		return fmt.Errorf("等待 addReceiptWallets 确认超时: %v", err)
	}
	logFn(fmt.Sprintf("[4/5] %d 个地址已激活 (ACTIVE)", len(approvedReceipts)))

	logFn("[5/5] 回收 gas...")
	s.batchSweepGas(ctx, ethClient, chainID, chain, splitter, approvedReceipts, walletCtx, logFn)
	// 同时回收 manager 的剩余 gas
	s.batchSweepGas(ctx, ethClient, chainID, chain, splitter, []string{managerAddress}, walletCtx, logFn)
	logFn("[5/5] 回收完成")
	logFn(fmt.Sprintf("全部完成! 耗时: %s", time.Since(startTime).Round(time.Second)))
	return nil
}

func (s *GUIService) batchSetupTron(ctx context.Context, mc *client.MerchantClient, splitter, token, amount string, count int, chain, managerAddress string, logFn func(string)) error {
	tronClient, err := s.createTronClient(chain)
	if err != nil {
		return err
	}
	defer tronClient.Conn.Close()

	walletCtx := mc.GetWalletContext()

	// amount 已经是原始值（最小单位），直接解析
	amountWei, ok := new(big.Int).SetString(amount, 10)
	if !ok {
		return fmt.Errorf("无效的 approve 金额: %s", amount)
	}

	balance, err := tx_util.GetTRXBalance(tronClient, walletCtx.Address)
	if err != nil {
		return fmt.Errorf("查询 TRX 余额失败: %v", err)
	}
	logFn(fmt.Sprintf("TRX 余额: %s TRX", tx_util.FormatSUN(balance)))

	startTime := time.Now()

	// Step 1: keygen
	logFn(fmt.Sprintf("[1/7] 正在生成 %d 个收款地址...", count))
	receiptAddresses, err := s.batchKeygen(ctx, splitter, count, logFn)
	if err != nil {
		return fmt.Errorf("批量 keygen 失败: %v", err)
	}
	logFn(fmt.Sprintf("[1/7] 生成完成: %d 个地址", len(receiptAddresses)))

	// Step 2: 动态估算费用 + 转 TRX
	logFn("[2/7] 估算 approve/addWallets 能量费用...")
	perReceipt := int64(8_000_000) // 默认 8 TRX 兜底
	approveParams := tx_util.NewApproveParams(token, splitter, amountWei)
	if est, err := tx_util.EstimateTronContractFee(tronClient, walletCtx.Address, approveParams); err == nil && est > 0 {
		perReceipt = est
		logFn(fmt.Sprintf("  approve 预估: %s TRX/地址", tx_util.FormatSUN(big.NewInt(perReceipt))))
	} else {
		logFn(fmt.Sprintf("  approve 估算失败，使用默认值: %s TRX/地址", tx_util.FormatSUN(big.NewInt(perReceipt))))
	}

	// addReceiptWallets 费用：实测每地址约 approve 预估值的 0.56 倍，加 30% 冗余 ≈ 0.73 倍
	perManager := perReceipt * int64(len(receiptAddresses)) * 73 / 100
	logFn(fmt.Sprintf("  addWallets 预估: %s TRX", tx_util.FormatSUN(big.NewInt(perManager))))

	logFn(fmt.Sprintf("[2/7] 转 TRX 到 %d 个收款地址 + manager...", len(receiptAddresses)))
	if err := s.batchFundTrx(ctx, tronClient, walletCtx, receiptAddresses, managerAddress, perReceipt, perManager, logFn); err != nil {
		return fmt.Errorf("批量转 TRX 失败: %v", err)
	}
	logFn("[2/7] TRX 转账完成")

	// Step 3: approve
	logFn(fmt.Sprintf("[3/7] 顺序 approve (%d 笔 MPC 签名)...", len(receiptAddresses)))
	_, approvedReceipts, err := s.batchApproveTron(ctx, tronClient, chain, splitter, receiptAddresses, token, amountWei, logFn)
	if err != nil {
		return fmt.Errorf("批量 approve 失败: %v", err)
	}
	logFn(fmt.Sprintf("[3/5] approve %d/%d 广播完成", len(approvedReceipts), len(receiptAddresses)))

	logFn("  报告 approve 交易给后端...")
	approveTxIds := make([]string, len(approvedReceipts))
	// batchApproveTron returns approvedReceipts but not txIds separately, use placeholder
	// TODO: batchApproveTron should return txIds
	for i := range approvedReceipts {
		approveTxIds[i] = "" // will be populated by the function
	}
	_ = approveTxIds
	// For now, submit with the receipt addresses (approve txIds tracked internally)
	// The backend state transition is driven by the on-chain Approval event, not txIds
	logFn("  等待链上 approve 确认...")
	if err := mc.PollReceiptState(ctx, chain, splitter, approvedReceipts, 3, pollTimeout(len(approvedReceipts))); err != nil {
		return fmt.Errorf("等待 approve 确认超时: %v", err)
	}
	logFn(fmt.Sprintf("[3/5] approve %d 笔链上确认完成", len(approvedReceipts)))

	logFn(fmt.Sprintf("[4/5] 将 %d 个地址注册到合约...", len(approvedReceipts)))
	activateTxId, err := s.batchAddReceiptWalletsTron(ctx, tronClient, chain, splitter, managerAddress, token, approvedReceipts, amountWei)
	if err != nil {
		return fmt.Errorf("addReceiptWallets 失败: %v", err)
	}
	logFn(fmt.Sprintf("[4/5] addReceiptWallets 交易广播: %s", activateTxId))
	if err := mc.SubmitAddReceiptWallets(ctx, chain, splitter, approvedReceipts, activateTxId); err != nil {
		return fmt.Errorf("submitAddReceiptWallets 失败: %v", err)
	}
	logFn("  等待链上 addReceiptWallets 确认...")
	if err := mc.PollReceiptState(ctx, chain, splitter, approvedReceipts, 5, pollTimeout(len(approvedReceipts))); err != nil {
		return fmt.Errorf("等待 addReceiptWallets 确认超时: %v", err)
	}
	logFn(fmt.Sprintf("[4/5] %d 个地址已激活 (ACTIVE)", len(approvedReceipts)))

	logFn("[5/5] 回收 TRX...")
	s.batchSweepTrx(ctx, tronClient, chain, splitter, approvedReceipts, walletCtx, logFn)
	// 同时回收 manager 的剩余 TRX
	s.batchSweepTrx(ctx, tronClient, chain, splitter, []string{managerAddress}, walletCtx, logFn)
	logFn("[5/5] 回收完成")
	logFn(fmt.Sprintf("全部完成! 耗时: %s", time.Since(startTime).Round(time.Second)))
	return nil
}


// mpcSign 使用 receipt wallet 的 MPC 密钥签名
// endpoint: 业务端点路径; rawTxHex: 未签名原始交易 hex (init 阶段供 Guard 校验)
func (s *GUIService) mpcSign(ctx context.Context, receipt, splitter, txHashHex, endpoint, rawTxHex string) (string, error) {
	mc := s.mc
	signID := time.Now().UnixMilli()
	txInfo := &client.SignTxInfo{
		SignerAddress: receipt,
		RawTxData:     rawTxHex,
		MessageHash:   txHashHex,
	}
	if err := mc.SignInit(ctx, signID, receipt, splitter, txHashHex, endpoint, txInfo); err != nil {
		return "", fmt.Errorf("sign init: %w", err)
	}
	if err := mc.SignStep1(ctx, signID, splitter, endpoint); err != nil {
		return "", fmt.Errorf("sign step1: %w", err)
	}
	if err := mc.SignStep2(ctx, signID, splitter, endpoint); err != nil {
		return "", fmt.Errorf("sign step2: %w", err)
	}
	signCtx, exists := mc.GetSignCtx(signID)
	if !exists {
		return "", fmt.Errorf("sign session %d 未找到", signID)
	}
	return signCtx.Step3Data.Sign, nil
}

// mpcSignWithChain 使用指定 chain 进行 MPC 签名（manager addReceiptWallets、sweep 等）
// endpoint: 业务端点路径; splitter: splitter 地址; rawTxHex: 未签名原始交易 hex
func (s *GUIService) mpcSignWithChain(ctx context.Context, signerAddress, txHashHex, chain, splitter, endpoint, rawTxHex string) (string, error) {
	mc := s.mc
	signID := time.Now().UnixMilli()
	txInfo := &client.SignTxInfo{
		SignerAddress: signerAddress,
		RawTxData:     rawTxHex,
		MessageHash:   txHashHex,
	}
	if err := mc.SignInitWithChain(ctx, signID, signerAddress, txHashHex, chain, splitter, endpoint, txInfo); err != nil {
		return "", fmt.Errorf("sign init: %w", err)
	}
	if err := mc.SignStep1WithChain(ctx, signID, chain, splitter, endpoint); err != nil {
		return "", fmt.Errorf("sign step1: %w", err)
	}
	if err := mc.SignStep2WithChain(ctx, signID, chain, splitter, endpoint); err != nil {
		return "", fmt.Errorf("sign step2: %w", err)
	}
	signCtx, exists := mc.GetSignCtx(signID)
	if !exists {
		return "", fmt.Errorf("sign session %d 未找到", signID)
	}
	return signCtx.Step3Data.Sign, nil
}

func (s *GUIService) batchKeygen(ctx context.Context, splitter string, count int, logFn func(string)) ([]string, error) {
	mc := s.mc
	var addresses []string
	var sessionIDCounter int64

	// 串行执行 keygen: MPC Server 的 keygen 是 CPU 密集型（大素数生成），
	// 并发会导致所有请求超时，串行反而更快更稳定。
	for i := 0; i < count; i++ {
		var addr string
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			addr, err = s.singleKeygen(ctx, mc, splitter, &sessionIDCounter)
			if err == nil {
				break
			}
			if attempt == 0 {
				logFn(fmt.Sprintf("  keygen [%d] 第1次失败: %v，重试中...", i, err))
				time.Sleep(3 * time.Second)
			}
		}

		if err != nil {
			return nil, fmt.Errorf("keygen [%d] 失败 (%d/%d 已完成): %w", i, len(addresses), count, err)
		}

		addresses = append(addresses, addr)
		logFn(fmt.Sprintf("  keygen [%d] 完成: %s", i, addr))
	}

	return addresses, nil
}

// singleKeygen 执行单个地址的 keygen 完整流程
func (s *GUIService) singleKeygen(ctx context.Context, mc *client.MerchantClient, splitter string, counter *int64) (string, error) {
	sessionID := atomic.AddInt64(counter, 1) + time.Now().UnixMilli()

	if err := mc.KeygenStep1(ctx, sessionID, splitter); err != nil {
		return "", fmt.Errorf("keygen step1 失败: %w", err)
	}
	if err := mc.KeygenStep2(ctx, sessionID, splitter); err != nil {
		return "", fmt.Errorf("keygen step2 失败: %w", err)
	}

	kgCtx, exists := mc.GetKGCtx(sessionID)
	if !exists {
		return "", fmt.Errorf("keygen session %d 未找到", sessionID)
	}

	addr := kgCtx.KGResult.Address
	if err := mc.GetAddress(ctx, kgCtx.Chain, addr, splitter); err != nil {
		return "", fmt.Errorf("获取地址公钥失败: %w", err)
	}
	if err := mc.RegisterReceiptWalletGenerated(ctx, kgCtx.Chain, splitter, addr); err != nil {
		return "", fmt.Errorf("注册收款地址失败: %w", err)
	}
	return addr, nil
}

func (s *GUIService) batchFundGas(ctx context.Context, ethClient *ethclient.Client, chainID *big.Int, walletCtx *client.WalletContext, targets []common.Address, amounts []*big.Int, logFn func(string)) error {
	signer := types.NewLondonSigner(chainID)
	var txHashes []string

	// nonce 只查一次，循环内本地递增，避免代理延迟导致 nonce 冲突
	nonce, err := ethClient.PendingNonceAt(ctx, common.HexToAddress(walletCtx.Address))
	if err != nil {
		return fmt.Errorf("获取 nonce 失败: %w", err)
	}

	// fee data 只查一次，批量转账期间 gas 价格不会剧烈变化
	feeData, err := tx_util.GetFeeData(ctx, ethClient)
	if err != nil {
		return fmt.Errorf("获取 fee data 失败: %w", err)
	}

	for i, target := range targets {
		to := target
		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     nonce,
			To:        &to,
			Value:     amounts[i],
			Gas:       tx_util.GasLimitNativeTransfer,
			GasTipCap: feeData.GasTipCap,
			GasFeeCap: feeData.GasFeeCap,
		})

		signedTx, err := types.SignTx(tx, signer, walletCtx.PrivateKey)
		if err != nil {
			return fmt.Errorf("签名转账交易失败: %w", err)
		}

		txID, err := tx_util.SendRawTransaction(ctx, ethClient, signedTx)
		if err != nil {
			return fmt.Errorf("发送转账到 %s 失败: %w", target.Hex(), err)
		}
		txHash := "0x" + hex.EncodeToString(txID)
		txHashes = append(txHashes, txHash)
		logFn(fmt.Sprintf("  -> %s %s (tx: %s)", target.Hex(), tx_util.FormatWeiToETH(amounts[i]), txHash))

		nonce++ // 本地递增 nonce
	}

	// 等待所有转账交易确认
	logFn("  等待转账交易确认...")
	if err := s.waitTxConfirmations(ctx, ethClient, txHashes, 120*time.Second); err != nil {
		return fmt.Errorf("转 gas 交易确认失败: %w", err)
	}
	return nil
}

func (s *GUIService) batchApprove(ctx context.Context, ethClient *ethclient.Client, chainID *big.Int, chain, splitter string, receipts []string, token string, amountWei *big.Int, logFn func(string)) ([]string, []string, error) {
	var txHashes []string
	var succeededReceipts []string

	for _, receiptAddr := range receipts {
		txHash, err := s.doSingleApprove(ctx, ethClient, chainID, chain, splitter, receiptAddr, token, amountWei)
		if err != nil {
			logFn(fmt.Sprintf("  -> %s approve FAIL: %v", receiptAddr, err))
			continue
		}
		txHashes = append(txHashes, txHash)
		succeededReceipts = append(succeededReceipts, receiptAddr)
		logFn(fmt.Sprintf("  -> %s approve OK (tx: %s)", receiptAddr, txHash))
	}

	if len(txHashes) == 0 {
		return nil, nil, fmt.Errorf("所有 approve 均失败")
	}
	return txHashes, succeededReceipts, nil
}

func (s *GUIService) doSingleApprove(ctx context.Context, ethClient *ethclient.Client, chainID *big.Int, chain, splitter, receipt, token string, amountWei *big.Int) (string, error) {
	fromAddress := common.HexToAddress(receipt)
	tokenAddress := common.HexToAddress(token)
	spenderAddress := common.HexToAddress(splitter)

	data, err := tx_util.BuildApproveData(spenderAddress, amountWei)
	if err != nil {
		return "", fmt.Errorf("构建 approve data 失败: %w", err)
	}

	tx, err := tx_util.BuildLegacyRawTx(ctx, ethClient, *chainID, fromAddress, tokenAddress, *big.NewInt(0), data)
	if err != nil {
		return "", fmt.Errorf("构造 approve 交易失败: %w", err)
	}

	signer := types.NewLondonSigner(chainID)
	txHash := signer.Hash(tx)
	txHashHex := hex.EncodeToString(txHash[:])
	rawTxHex := tx_util.EncodeUnsignedTxHex(tx, chainID)

	signHex, err := s.mpcSign(ctx, receipt, splitter, txHashHex, EndpointSignApprove, rawTxHex)
	if err != nil {
		return "", fmt.Errorf("MPC 签名失败: %w", err)
	}

	signature, err := hex.DecodeString(signHex)
	if err != nil {
		return "", fmt.Errorf("解码签名失败: %w", err)
	}

	signedTx, err := tx_util.AppendSign(chainID, tx, signature)
	if err != nil {
		return "", fmt.Errorf("添加签名失败: %w", err)
	}

	txID, err := tx_util.SendRawTransaction(ctx, ethClient, signedTx)
	if err != nil {
		return "", fmt.Errorf("广播 approve 交易失败: %w", err)
	}

	txIDHex := "0x" + hex.EncodeToString(txID)
	return txIDHex, nil
}

func (s *GUIService) waitTxConfirmations(ctx context.Context, ethClient *ethclient.Client, txHashes []string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	pending := make(map[string]bool)
	for _, h := range txHashes {
		pending[h] = true
	}

	for len(pending) > 0 && time.Now().Before(deadline) {
		for txHash := range pending {
			hash := common.HexToHash(txHash)
			receipt, err := ethClient.TransactionReceipt(ctx, hash)
			if err == nil && receipt != nil {
				if receipt.Status == types.ReceiptStatusSuccessful {
					delete(pending, txHash)
				} else {
					return fmt.Errorf("交易 %s 链上执行失败", txHash)
				}
			}
		}
		if len(pending) > 0 {
			time.Sleep(2 * time.Second)
		}
	}

	if len(pending) > 0 {
		return fmt.Errorf("等待超时，%d 笔交易未确认", len(pending))
	}
	return nil
}

func (s *GUIService) batchAddReceiptWallets(ctx context.Context, ethClient *ethclient.Client, chainID *big.Int, chain, splitter, manager, token string, receipts []string, minAllowance *big.Int) (string, error) {
	managerAddr := common.HexToAddress(manager)
	splitterAddr := common.HexToAddress(splitter)
	tokenAddr := common.HexToAddress(token)

	var walletAddrs []common.Address
	for _, r := range receipts {
		walletAddrs = append(walletAddrs, common.HexToAddress(r))
	}

	data, err := tx_util.BuildAddReceiptWalletsData(tokenAddr, walletAddrs, minAllowance)
	if err != nil {
		return "", fmt.Errorf("构建 addReceiptWallets data 失败: %w", err)
	}

	// addReceiptWallets gas 按地址数量动态计算: 基础 50000 + 每地址 100000
	addReceiptGasLimit := uint64(50000 + len(receipts)*100000)
	tx, err := tx_util.BuildLegacyRawTxWithGasLimit(ctx, ethClient, *chainID, managerAddr, splitterAddr, *big.NewInt(0), data, addReceiptGasLimit)
	if err != nil {
		return "", fmt.Errorf("构造 addReceiptWallets 交易失败: %w", err)
	}

	signer := types.NewLondonSigner(chainID)
	txHash := signer.Hash(tx)
	txHashHex := hex.EncodeToString(txHash[:])
	rawTxHex := tx_util.EncodeUnsignedTxHex(tx, chainID)

	signHex, err := s.mpcSignWithChain(ctx, manager, txHashHex, chain, splitter, EndpointSignAddWallets, rawTxHex)
	if err != nil {
		return "", fmt.Errorf("MPC 签名失败: %w", err)
	}

	signature, err := hex.DecodeString(signHex)
	if err != nil {
		return "", fmt.Errorf("解码签名失败: %w", err)
	}

	signedTx, err := tx_util.AppendSign(chainID, tx, signature)
	if err != nil {
		return "", fmt.Errorf("添加签名失败: %w", err)
	}

	txID, err := tx_util.SendRawTransaction(ctx, ethClient, signedTx)
	if err != nil {
		return "", fmt.Errorf("广播 addReceiptWallets 交易失败: %w", err)
	}
	txIDHex := "0x" + hex.EncodeToString(txID)

	if err := s.waitTxConfirmations(ctx, ethClient, []string{txIDHex}, 120*time.Second); err != nil {
		return txIDHex, fmt.Errorf("addReceiptWallets 交易确认失败: %w", err)
	}
	return txIDHex, nil
}

// UpgradeContract 通过 MPC 签名升级 SplitWalletV4 逻辑合约 (EVM)
func (s *GUIService) UpgradeContract(ctx context.Context, chain, splitter, newImplementation string, logFn func(string)) (string, error) {
	walletCtx := s.mc.GetWalletContext()
	if walletCtx == nil || walletCtx.Address == "" {
		return "", fmt.Errorf("请先导入商户钱包")
	}

	splitWallet, err := s.mc.GetSplit(splitter)
	if err != nil || splitWallet == nil {
		return "", fmt.Errorf("查询分账合约失败")
	}
	chainConfig, err := s.mc.GetChainConfig(chain)
	if err != nil {
		return "", fmt.Errorf("获取链配置失败: %w", err)
	}

	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return "", fmt.Errorf("连接 RPC 失败: %w", err)
	}
	defer ethClient.Close()

	chainID := big.NewInt(int64(chainConfig.ChainID))
	splitterAddr := common.HexToAddress(splitter)
	managerAddr := common.HexToAddress(splitWallet.SplitWalletManager)
	implAddr := common.HexToAddress(newImplementation)

	// 1. 查询 ProxyAdmin 地址
	logFn("查询 ProxyAdmin 地址...")
	proxyAdmin, err := tx_util.GetSplitWalletProxyAdmin(ctx, ethClient, splitterAddr)
	if err != nil {
		return "", fmt.Errorf("查询 ProxyAdmin 失败: %w", err)
	}
	logFn(fmt.Sprintf("ProxyAdmin: %s", proxyAdmin.Hex()))

	// 2. 构建 ProxyAdmin.upgrade(proxy, implementation) 交易
	logFn(fmt.Sprintf("构建升级交易: proxy=%s impl=%s", splitter, newImplementation))
	data, err := tx_util.BuildUpgradeData(splitterAddr, implAddr)
	if err != nil {
		return "", fmt.Errorf("构建 upgrade data 失败: %w", err)
	}

	tx, err := tx_util.BuildLegacyRawTxWithGasLimit(ctx, ethClient, *chainID, managerAddr, proxyAdmin, *big.NewInt(0), data, 100000)
	if err != nil {
		return "", fmt.Errorf("构造升级交易失败: %w", err)
	}

	signer := types.NewLondonSigner(chainID)
	txHash := signer.Hash(tx)
	txHashHex := hex.EncodeToString(txHash[:])
	rawTxHex := tx_util.EncodeUnsignedTxHex(tx, chainID)

	// 3. MPC 签名
	logFn("MPC 签名中...")
	signHex, err := s.mpcSignWithChain(ctx, splitWallet.SplitWalletManager, txHashHex, chain, splitter, EndpointSignUpgrade, rawTxHex)
	if err != nil {
		return "", fmt.Errorf("MPC 签名失败: %w", err)
	}

	signature, err := hex.DecodeString(signHex)
	if err != nil {
		return "", fmt.Errorf("解码签名失败: %w", err)
	}

	signedTx, err := tx_util.AppendSign(chainID, tx, signature)
	if err != nil {
		return "", fmt.Errorf("添加签名失败: %w", err)
	}

	// 4. 广播交易
	logFn("广播升级交易...")
	txID, err := tx_util.SendRawTransaction(ctx, ethClient, signedTx)
	if err != nil {
		return "", fmt.Errorf("广播升级交易失败: %w", err)
	}
	txIDHex := "0x" + hex.EncodeToString(txID)
	logFn(fmt.Sprintf("升级交易已广播: %s", txIDHex))

	// 5. 等待确认
	if err := s.waitTxConfirmations(ctx, ethClient, []string{txIDHex}, 120*time.Second); err != nil {
		return txIDHex, fmt.Errorf("升级交易确认失败: %w", err)
	}
	logFn("升级交易已确认!")
	return txIDHex, nil
}

func (s *GUIService) batchSweepGas(ctx context.Context, ethClient *ethclient.Client, chainID *big.Int, chain, splitter string, addresses []string, walletCtx *client.WalletContext, logFn func(string)) {
	merchantAddr := common.HexToAddress(walletCtx.Address)
	for _, addr := range addresses {
		fromAddr := common.HexToAddress(addr)
		tx, sendAmount, err := tx_util.BuildSweepTx(ctx, ethClient, *chainID, fromAddr, merchantAddr)
		if err != nil {
			logFn(fmt.Sprintf("  -> %s 跳过 (余额不足或为0)", addr))
			continue
		}

		signer := types.NewLondonSigner(chainID)
		txHash := signer.Hash(tx)
		txHashHex := hex.EncodeToString(txHash[:])
		rawTxHex := tx_util.EncodeUnsignedTxHex(tx, chainID)

		signHex, err := s.mpcSignWithChain(ctx, addr, txHashHex, chain, splitter, EndpointSignSweep, rawTxHex)
		if err != nil {
			logFn(fmt.Sprintf("  -> %s sweep 签名失败: %v", addr, err))
			continue
		}

		signature, err := hex.DecodeString(signHex)
		if err != nil {
			continue
		}

		signedTx, err := tx_util.AppendSign(chainID, tx, signature)
		if err != nil {
			continue
		}

		txID, err := tx_util.SendRawTransaction(ctx, ethClient, signedTx)
		if err != nil {
			logFn(fmt.Sprintf("  -> %s 广播失败: %v", addr, err))
			continue
		}
		logFn(fmt.Sprintf("  -> %s 回收 %s (tx: 0x%s)", addr, tx_util.FormatWeiToETH(sendAmount), hex.EncodeToString(txID)))
	}
}

// ---- 内部工具 ----

// checkEvmNonceHealth 检查 EVM 地址的 nonce 健康状态，有 pending 交易则返回错误
func (s *GUIService) checkEvmNonceHealth(ctx context.Context, ethClient *ethclient.Client, address string) error {
	return tx_util.CheckNonceHealth(ctx, ethClient, common.HexToAddress(address))
}

// DiagnoseEvmNonce 诊断 EVM 地址的 nonce 状态（供 GUI 显示）
func (s *GUIService) DiagnoseEvmNonce(chain, address string) (*tx_util.NonceDiagnosis, error) {
	if !s.IsUnlocked() {
		return nil, fmt.Errorf("请先解锁")
	}
	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return nil, err
	}
	defer ethClient.Close()
	return tx_util.DiagnoseNonce(context.Background(), ethClient, common.HexToAddress(address))
}

// FixEvmPendingNonce 修复 EVM 地址卡住的 nonce
func (s *GUIService) FixEvmPendingNonce(ctx context.Context, chain string, logFn func(string)) error {
	if !s.IsUnlocked() {
		return fmt.Errorf("请先解锁")
	}
	walletCtx := s.mc.GetWalletContext()
	if walletCtx == nil || walletCtx.PrivateKey == nil {
		return fmt.Errorf("请先导入商户钱包")
	}
	chainConfig, err := s.mc.GetChainConfig(chain)
	if err != nil {
		return fmt.Errorf("获取链配置失败: %v", err)
	}
	chainID := big.NewInt(int64(chainConfig.ChainID))

	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return err
	}
	defer ethClient.Close()

	return tx_util.ForceResetNonce(ctx, ethClient, chainID, common.HexToAddress(walletCtx.Address), walletCtx.PrivateKey, logFn)
}

func (s *GUIService) createEthClient(chain string) (*ethclient.Client, error) {
	rpcUrl, err := s.mc.GetRpcUrl(chain)
	if err != nil {
		return nil, fmt.Errorf("获取 RPC 节点失败: %w", err)
	}
	// 带超时的连接，后端 RPC 代理首次请求可能较慢（TLS 握手 + 上游连接建立）
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := ethclient.DialContext(ctx, rpcUrl)
	if err != nil {
		// 首次连接超时时自动重试一次
		fmt.Printf("[EthClient] 首次连接 %s 失败: %v，重试中...\n", chain, err)
		ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel2()
		return ethclient.DialContext(ctx2, rpcUrl)
	}
	return client, nil
}

func (s *GUIService) createTronClient(chain string) (*tron_client.GrpcClient, error) {
	rpcUrl, err := s.mc.GetRpcUrl(chain)
	if err != nil {
		return nil, fmt.Errorf("获取 Tron RPC 节点失败: %w", err)
	}
	auth := s.mc.GetRemoteConfig().GetTronRpcAuth(chain)
	if auth != nil && (auth.ApiKey != "" || auth.Provider != "") {
		return tx_util.NewClientWithProvider(rpcUrl, auth.ApiKey, auth.Provider)
	}
	return tx_util.NewTronGrpcClient(rpcUrl)
}

// ---- Tron 批量操作方法 ----

func (s *GUIService) batchFundTrx(ctx context.Context, tronClient *tron_client.GrpcClient, walletCtx *client.WalletContext, receipts []string, managerAddress string, perReceipt, perManager int64, logFn func(string)) error {
	allTargets := append(receipts, managerAddress)
	allAmounts := make([]int64, len(receipts)+1)
	for i := range receipts {
		allAmounts[i] = perReceipt
	}
	allAmounts[len(receipts)] = perManager

	for i, addr := range allTargets {
		rawTx, err := tx_util.BuildTronSendTRXTx(tronClient, walletCtx.Address, addr, allAmounts[i])
		if err != nil {
			return fmt.Errorf("构造转账到 %s 失败: %w", addr, err)
		}
		hashBytes, err := tx_util.GetTronTxHashBytes(rawTx)
		if err != nil {
			return fmt.Errorf("获取交易哈希失败: %w", err)
		}
		signedBytes, err := tx_util.SignWithPrivateKey(walletCtx.PrivateKey, hashBytes)
		if err != nil {
			return fmt.Errorf("签名失败: %w", err)
		}
		if err := tx_util.SignTronTransaction(rawTx, hex.EncodeToString(signedBytes)); err != nil {
			return fmt.Errorf("添加签名失败: %w", err)
		}
		txID, err := tx_util.BroadcastTronTransaction(tronClient, rawTx)
		if err != nil {
			return fmt.Errorf("广播转账到 %s 失败: %w", addr, err)
		}
		logFn(fmt.Sprintf("  -> %s %s TRX (tx: %s)", addr, tx_util.FormatSUN(big.NewInt(allAmounts[i])), txID))
		time.Sleep(500 * time.Millisecond)
	}

	logFn("  等待转账确认...")
	time.Sleep(6 * time.Second)
	return nil
}

func (s *GUIService) batchApproveTron(ctx context.Context, tronClient *tron_client.GrpcClient, chain, splitter string, receipts []string, token string, amountWei *big.Int, logFn func(string)) ([]string, []string, error) {
	var txIds []string
	var succeededReceipts []string

	for _, receiptAddr := range receipts {
		approveParams := tx_util.NewApproveParams(token, splitter, amountWei)
		rawTx, hashBytes, err := tx_util.CreateTronTransferRaw(tronClient, receiptAddr, approveParams)
		if err != nil {
			logFn(fmt.Sprintf("  -> %s approve FAIL: %v", receiptAddr, err))
			continue
		}
		rawDataHex, _ := tx_util.EncodeTronRawDataHex(rawTx)

		signHex, err := s.mpcSign(ctx, receiptAddr, splitter, hex.EncodeToString(hashBytes), EndpointSignApprove, rawDataHex)
		if err != nil {
			logFn(fmt.Sprintf("  -> %s approve FAIL: %v", receiptAddr, err))
			continue
		}

		if err := tx_util.SignTronTransaction(rawTx, signHex); err != nil {
			logFn(fmt.Sprintf("  -> %s approve FAIL: %v", receiptAddr, err))
			continue
		}

		txID, err := tx_util.BroadcastTronTransaction(tronClient, rawTx)
		if err != nil {
			logFn(fmt.Sprintf("  -> %s approve FAIL: %v", receiptAddr, err))
			continue
		}

		txIds = append(txIds, txID)
		succeededReceipts = append(succeededReceipts, receiptAddr)
		logFn(fmt.Sprintf("  -> %s approve OK (tx: %s)", receiptAddr, txID))
	}

	if len(txIds) == 0 {
		return nil, nil, fmt.Errorf("所有 approve 均失败")
	}
	return txIds, succeededReceipts, nil
}

func (s *GUIService) batchAddReceiptWalletsTron(ctx context.Context, tronClient *tron_client.GrpcClient, chain, splitter, manager, token string, receipts []string, minAllowance *big.Int) (string, error) {
	addParams := tx_util.NewAddReceiptWalletsParams(splitter, token, receipts, minAllowance)
	rawTx, hashBytes, err := tx_util.CreateTronTransferRaw(tronClient, manager, addParams)
	if err != nil {
		return "", fmt.Errorf("构造 addReceiptWallets 交易失败: %w", err)
	}
	rawDataHex, _ := tx_util.EncodeTronRawDataHex(rawTx)

	signHex, err := s.mpcSignWithChain(ctx, manager, hex.EncodeToString(hashBytes), chain, splitter, EndpointSignAddWallets, rawDataHex)
	if err != nil {
		return "", fmt.Errorf("MPC 签名失败: %w", err)
	}

	if err := tx_util.SignTronTransaction(rawTx, signHex); err != nil {
		return "", fmt.Errorf("添加签名失败: %w", err)
	}

	txID, err := tx_util.BroadcastTronTransaction(tronClient, rawTx)
	if err != nil {
		return "", fmt.Errorf("广播 addReceiptWallets 交易失败: %w", err)
	}

	time.Sleep(6 * time.Second)
	return txID, nil
}

func (s *GUIService) batchSweepTrx(ctx context.Context, tronClient *tron_client.GrpcClient, chain, splitter string, addresses []string, walletCtx *client.WalletContext, logFn func(string)) {
	for _, addr := range addresses {
		rawTx, sendAmount, err := tx_util.BuildTronSweepTx(tronClient, addr, walletCtx.Address)
		if err != nil {
			logFn(fmt.Sprintf("  -> %s 跳过 (余额不足或为0)", addr))
			continue
		}

		hashBytes, err := tx_util.GetTronTxHashBytes(rawTx)
		if err != nil {
			continue
		}
		rawDataHex, _ := tx_util.EncodeTronRawDataHex(rawTx)

		signHex, err := s.mpcSignWithChain(ctx, addr, hex.EncodeToString(hashBytes), chain, splitter, EndpointSignSweep, rawDataHex)
		if err != nil {
			logFn(fmt.Sprintf("  -> %s sweep 签名失败: %v", addr, err))
			continue
		}

		if err := tx_util.SignTronTransaction(rawTx, signHex); err != nil {
			continue
		}

		txID, err := tx_util.BroadcastTronTransaction(tronClient, rawTx)
		if err != nil {
			logFn(fmt.Sprintf("  -> %s 广播失败: %v", addr, err))
			continue
		}
		logFn(fmt.Sprintf("  -> %s 回收 %s TRX (tx: %s)", addr, tx_util.FormatSUN(big.NewInt(sendAmount)), txID))
	}
}

// ---- 回收手续费 ----

// SweepGas 回收收款地址和 manager 中的原生币（ETH/TRX 等）到商户钱包
func (s *GUIService) SweepGas(ctx context.Context, splitter string, logFn func(string)) error {
	if !s.IsUnlocked() {
		return fmt.Errorf("请先解锁")
	}
	mc := s.mc
	splitWallet, err := mc.GetSplit(splitter)
	if err != nil || splitWallet == nil {
		return fmt.Errorf("查询分账合约失败: %v", err)
	}
	if splitWallet.State < 7 {
		return fmt.Errorf("分账合约尚未激活")
	}
	chain := splitWallet.Chain
	walletCtx := mc.GetWalletContext()
	managerAddress := splitWallet.SplitWalletManager

	chainConfig, err := mc.GetChainConfig(chain)
	if err != nil {
		return fmt.Errorf("获取链配置失败: %v", err)
	}

	if strings.ToLower(chainConfig.ChainType) == "tron" {
		return s.sweepGasTron(ctx, chain, splitter, managerAddress, walletCtx, logFn)
	}
	return s.sweepGasEvm(ctx, chain, splitter, managerAddress, walletCtx, chainConfig, logFn)
}

func (s *GUIService) sweepGasEvm(ctx context.Context, chain, splitter, managerAddress string, walletCtx *client.WalletContext, chainConfig *model.ChainConfig, logFn func(string)) error {
	chainID := big.NewInt(int64(chainConfig.ChainID))
	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return err
	}
	defer ethClient.Close()

	// 查询所有收款地址
	splitterAddr := common.HexToAddress(splitter)
	receiptAddrs, err := tx_util.GetAllReceiptWallets(ctx, ethClient, splitterAddr)
	if err != nil {
		return fmt.Errorf("查询收款地址失败: %v", err)
	}
	logFn(fmt.Sprintf("找到 %d 个收款地址, manager: %s", len(receiptAddrs), truncAddress(managerAddress)))

	// 回收收款地址
	var sweepAddrs []string
	var totalSwept int
	for _, addr := range receiptAddrs {
		balance, err := tx_util.GetEthBalance(ethClient, addr)
		if err != nil || balance.Sign() <= 0 {
			continue
		}
		sweepAddrs = append(sweepAddrs, addr.Hex())
	}
	if len(sweepAddrs) > 0 {
		logFn(fmt.Sprintf("回收 %d 个收款地址的 %s...", len(sweepAddrs), chainConfig.Currency))
		s.batchSweepGas(ctx, ethClient, chainID, chain, splitter, sweepAddrs, walletCtx, logFn)
		totalSwept += len(sweepAddrs)
	} else {
		logFn("收款地址余额均为 0，无需回收")
	}

	// 回收 manager
	if managerAddress != "" {
		managerAddr := common.HexToAddress(managerAddress)
		balance, err := tx_util.GetEthBalance(ethClient, managerAddr)
		if err == nil && balance.Sign() > 0 {
			logFn(fmt.Sprintf("回收 manager %s 的 %s...", truncAddress(managerAddress), chainConfig.Currency))
			s.batchSweepGas(ctx, ethClient, chainID, chain, splitter, []string{managerAddress}, walletCtx, logFn)
			totalSwept++
		} else {
			logFn("manager 余额为 0，无需回收")
		}
	}

	logFn(fmt.Sprintf("回收完成，共处理 %d 个地址", totalSwept))
	return nil
}

func (s *GUIService) sweepGasTron(ctx context.Context, chain, splitter, managerAddress string, walletCtx *client.WalletContext, logFn func(string)) error {
	tronClient, err := s.createTronClient(chain)
	if err != nil {
		return err
	}
	defer tronClient.Conn.Close()

	// 查询所有收款地址
	receiptAddrs, err := tx_util.GetTronAllReceiptWallets(tronClient, splitter, walletCtx.Address)
	if err != nil {
		return fmt.Errorf("查询收款地址失败: %v", err)
	}
	logFn(fmt.Sprintf("找到 %d 个收款地址, manager: %s", len(receiptAddrs), truncAddress(managerAddress)))

	// 回收收款地址
	var sweepAddrs []string
	for _, addr := range receiptAddrs {
		balance, err := tx_util.GetTRXBalance(tronClient, addr)
		if err != nil || balance.Sign() <= 0 {
			continue
		}
		sweepAddrs = append(sweepAddrs, addr)
	}
	if len(sweepAddrs) > 0 {
		logFn(fmt.Sprintf("回收 %d 个收款地址的 TRX...", len(sweepAddrs)))
		s.batchSweepTrx(ctx, tronClient, chain, splitter, sweepAddrs, walletCtx, logFn)
	} else {
		logFn("收款地址余额均为 0，无需回收")
	}

	// 回收 manager
	if managerAddress != "" {
		balance, err := tx_util.GetTRXBalance(tronClient, managerAddress)
		if err == nil && balance.Sign() > 0 {
			logFn(fmt.Sprintf("回收 manager %s 的 TRX...", truncAddress(managerAddress)))
			s.batchSweepTrx(ctx, tronClient, chain, splitter, []string{managerAddress}, walletCtx, logFn)
		} else {
			logFn("manager 余额为 0，无需回收")
		}
	}

	logFn("回收完成")
	return nil
}

func truncAddress(addr string) string {
	if len(addr) <= 12 {
		return addr
	}
	return addr[:6] + "..." + addr[len(addr)-4:]
}

// ---- 资金归集 ----

// ClaimReceiptERC20Tokens 分批归集 receipt wallet 中的 ERC20 代币到 split wallet
// batchSize: 每批处理的 receipt wallet 数量
func (s *GUIService) ClaimReceiptERC20Tokens(ctx context.Context, splitter, token string, batchSize int, logFn func(string)) error {
	if !s.IsUnlocked() {
		return fmt.Errorf("请先解锁")
	}
	mc := s.mc
	splitWallet, err := mc.GetSplit(splitter)
	if err != nil || splitWallet == nil {
		return fmt.Errorf("查询分账合约失败: %v", err)
	}
	if splitWallet.State < 7 {
		return fmt.Errorf("分账合约尚未激活")
	}

	walletCtx := mc.GetWalletContext()
	if walletCtx == nil || walletCtx.PrivateKey == nil {
		return fmt.Errorf("请先导入商户钱包")
	}

	chain := splitWallet.Chain
	chainConfig, err := mc.GetChainConfig(chain)
	if err != nil {
		return fmt.Errorf("获取链配置失败: %v", err)
	}

	if strings.ToLower(chainConfig.ChainType) == "tron" {
		return s.claimOnTron(ctx, chain, splitter, token, batchSize, walletCtx, logFn)
	}
	return s.claimOnEvm(ctx, chain, splitter, token, batchSize, walletCtx, logFn)
}

func (s *GUIService) claimOnEvm(ctx context.Context, chain, splitter, token string, batchSize int, walletCtx *client.WalletContext, logFn func(string)) error {
	chainConfig, err := s.mc.GetChainConfig(chain)
	if err != nil {
		return fmt.Errorf("获取链配置失败: %v", err)
	}
	chainID := big.NewInt(int64(chainConfig.ChainID))

	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return err
	}
	defer ethClient.Close()

	if err := s.checkEvmNonceHealth(ctx, ethClient, walletCtx.Address); err != nil {
		return err
	}

	splitterAddr := common.HexToAddress(splitter)
	tokenAddr := common.HexToAddress(token)
	owner := common.HexToAddress(walletCtx.Address)

	// 查询 receipt wallet 总数
	totalCount, err := tx_util.GetReceiptWalletCount(ctx, ethClient, splitterAddr)
	if err != nil {
		return fmt.Errorf("查询 receipt wallet 数量失败: %v", err)
	}
	total := totalCount.Int64()
	if total == 0 {
		logFn("合约中没有注册的 receipt wallet")
		return nil
	}

	logFn(fmt.Sprintf("合约共有 %d 个 receipt wallet，每批 %d 个", total, batchSize))

	tokens := []common.Address{tokenAddr}
	minAmounts := []*big.Int{big.NewInt(1)}

	batchNum := 0
	executedBatches := 0
	totalClaimedSum := big.NewInt(0)
	emptyConsecutive := 0

	for start := int64(0); start < total; start += int64(batchSize) {
		end := start + int64(batchSize)
		if end > total {
			end = total
		}
		batchNum++

		// 模拟调用，检查该批次是否有资金可归集
		logFn(fmt.Sprintf("[批次 %d] 模拟归集 [%d, %d)...", batchNum, start, end))
		claimed, err := tx_util.SimulateClaimReceiptERC20Tokens(ctx, ethClient, owner, splitterAddr, tokens, minAmounts, big.NewInt(start), big.NewInt(end))
		if err != nil {
			logFn(fmt.Sprintf("[批次 %d] 模拟失败: %v，跳过", batchNum, err))
			emptyConsecutive++
			if emptyConsecutive >= 2 {
				logFn("连续 2 个批次为空，后续批次跳过")
				break
			}
			continue
		}

		// 检查 totalClaimed 是否全为 0
		hasClaimable := false
		for _, c := range claimed {
			if c != nil && c.Sign() > 0 {
				hasClaimable = true
				break
			}
		}
		if !hasClaimable {
			logFn(fmt.Sprintf("[批次 %d] 无可归集资金，跳过", batchNum))
			emptyConsecutive++
			if emptyConsecutive >= 2 {
				logFn("连续 2 个批次为空，后续批次跳过")
				break
			}
			continue
		}
		emptyConsecutive = 0

		// 有资金，发送真实交易
		claimAmount := claimed[0]
		logFn(fmt.Sprintf("[批次 %d] 预计归集: %s (最小单位)，发送交易...", batchNum, claimAmount.String()))

		data, err := tx_util.BuildClaimReceiptERC20TokensData(tokens, minAmounts, big.NewInt(start), big.NewInt(end))
		if err != nil {
			return fmt.Errorf("[批次 %d] 构建 data 失败: %v", batchNum, err)
		}

		tx, err := tx_util.BuildLegacyRawTx(ctx, ethClient, *chainID, owner, splitterAddr, *big.NewInt(0), data)
		if err != nil {
			return fmt.Errorf("[批次 %d] 构造交易失败: %v", batchNum, err)
		}

		signer := types.NewLondonSigner(chainID)
		signedTx, err := types.SignTx(tx, signer, walletCtx.PrivateKey)
		if err != nil {
			return fmt.Errorf("[批次 %d] 签名失败: %v", batchNum, err)
		}

		txID, err := tx_util.SendRawTransaction(ctx, ethClient, signedTx)
		if err != nil {
			return fmt.Errorf("[批次 %d] 发送交易失败: %v", batchNum, err)
		}
		txIDHex := "0x" + hex.EncodeToString(txID)
		if link := s.GetExplorerTxUrl(chain, txIDHex); link != "" {
			logFn(fmt.Sprintf("[批次 %d] 交易已发送: %s\n  浏览器: %s", batchNum, txIDHex, link))
		} else {
			logFn(fmt.Sprintf("[批次 %d] 交易已发送: %s", batchNum, txIDHex))
		}

		if err := s.waitTxConfirmations(ctx, ethClient, []string{txIDHex}, 120*time.Second); err != nil {
			logFn(fmt.Sprintf("[批次 %d] 交易确认失败: %v，继续下一批", batchNum, err))
		} else {
			logFn(fmt.Sprintf("[批次 %d] 交易已确认", batchNum))
		}
		executedBatches++
		totalClaimedSum.Add(totalClaimedSum, claimAmount)
	}

	logFn(fmt.Sprintf("归集完成: 共扫描 %d 个批次，实际执行 %d 个，总归集 %s (最小单位)", batchNum, executedBatches, totalClaimedSum.String()))
	return nil
}

func (s *GUIService) claimOnTron(ctx context.Context, chain, splitter, token string, batchSize int, walletCtx *client.WalletContext, logFn func(string)) error {
	tronClient, err := s.createTronClient(chain)
	if err != nil {
		return err
	}
	defer tronClient.Conn.Close()

	total, err := tx_util.GetTronReceiptWalletCount(tronClient, splitter, walletCtx.Address)
	if err != nil {
		return fmt.Errorf("查询 receipt wallet 数量失败: %v", err)
	}
	if total == 0 {
		logFn("合约中没有注册的 receipt wallet")
		return nil
	}

	logFn(fmt.Sprintf("合约共有 %d 个 receipt wallet，每批 %d 个", total, batchSize))

	tokenAddrs := []string{token}
	minAmounts := []*big.Int{big.NewInt(1)}

	batchNum := 0
	executedBatches := 0
	totalClaimedSum := big.NewInt(0)
	emptyConsecutive := 0

	for start := uint64(0); start < total; start += uint64(batchSize) {
		end := start + uint64(batchSize)
		if end > total {
			end = total
		}
		batchNum++

		// 模拟调用
		logFn(fmt.Sprintf("[批次 %d] 模拟归集 [%d, %d)...", batchNum, start, end))
		claimed, err := tx_util.SimulateTronClaimReceiptERC20Tokens(tronClient, walletCtx.Address, splitter, tokenAddrs, minAmounts, start, end)
		if err != nil {
			logFn(fmt.Sprintf("[批次 %d] 模拟失败: %v，跳过", batchNum, err))
			emptyConsecutive++
			if emptyConsecutive >= 2 {
				logFn("连续 2 个批次为空，后续批次跳过")
				break
			}
			continue
		}

		hasClaimable := false
		for _, c := range claimed {
			if c != nil && c.Sign() > 0 {
				hasClaimable = true
				break
			}
		}
		if !hasClaimable {
			logFn(fmt.Sprintf("[批次 %d] 无可归集资金，跳过", batchNum))
			emptyConsecutive++
			if emptyConsecutive >= 2 {
				logFn("连续 2 个批次为空，后续批次跳过")
				break
			}
			continue
		}
		emptyConsecutive = 0

		claimAmount := claimed[0]
		logFn(fmt.Sprintf("[批次 %d] 预计归集: %s (最小单位)，发送交易...", batchNum, claimAmount.String()))

		calldata, err := tx_util.BuildTronClaimData(tokenAddrs, minAmounts, start, end)
		if err != nil {
			return fmt.Errorf("[批次 %d] 构建 calldata 失败: %v", batchNum, err)
		}
		rawTx, hashBytes, err := tx_util.CreateTronTxWithData(tronClient, walletCtx.Address, splitter, calldata)
		if err != nil {
			return fmt.Errorf("[批次 %d] 构造交易失败: %v", batchNum, err)
		}

		signedBytes, err := tx_util.SignWithPrivateKey(walletCtx.PrivateKey, hashBytes)
		if err != nil {
			return fmt.Errorf("[批次 %d] 签名失败: %v", batchNum, err)
		}
		if err := tx_util.SignTronTransaction(rawTx, hex.EncodeToString(signedBytes)); err != nil {
			return fmt.Errorf("[批次 %d] 添加签名失败: %v", batchNum, err)
		}

		txID, err := tx_util.BroadcastTronTransaction(tronClient, rawTx)
		if err != nil {
			return fmt.Errorf("[批次 %d] 广播交易失败: %v", batchNum, err)
		}
		logFn(fmt.Sprintf("[批次 %d] 交易已发送: %s", batchNum, txID))

		time.Sleep(6 * time.Second)
		logFn(fmt.Sprintf("[批次 %d] 交易已确认", batchNum))
		executedBatches++
		totalClaimedSum.Add(totalClaimedSum, claimAmount)
	}

	logFn(fmt.Sprintf("归集完成: 共扫描 %d 个批次，实际执行 %d 个，总归集 %s (最小单位)", batchNum, executedBatches, totalClaimedSum.String()))
	return nil
}

// ---- 资金提现 ----

// ReleaseERC20Tokens 提现 split wallet 中的 ERC20 代币到 payee 的提现地址
func (s *GUIService) ReleaseERC20Tokens(ctx context.Context, splitter, token string, logFn func(string)) error {
	if !s.IsUnlocked() {
		return fmt.Errorf("请先解锁")
	}
	mc := s.mc
	splitWallet, err := mc.GetSplit(splitter)
	if err != nil || splitWallet == nil {
		return fmt.Errorf("查询分账合约失败: %v", err)
	}
	if splitWallet.State < 7 {
		return fmt.Errorf("分账合约尚未激活")
	}

	walletCtx := mc.GetWalletContext()
	if walletCtx == nil || walletCtx.PrivateKey == nil {
		return fmt.Errorf("请先导入商户钱包")
	}

	chain := splitWallet.Chain
	chainConfig, err := mc.GetChainConfig(chain)
	if err != nil {
		return fmt.Errorf("获取链配置失败: %v", err)
	}

	if strings.ToLower(chainConfig.ChainType) == "tron" {
		return s.releaseOnTron(ctx, chain, splitter, token, walletCtx, logFn)
	}
	return s.releaseOnEvm(ctx, chain, splitter, token, walletCtx, logFn)
}

func (s *GUIService) releaseOnEvm(ctx context.Context, chain, splitter, token string, walletCtx *client.WalletContext, logFn func(string)) error {
	chainConfig, err := s.mc.GetChainConfig(chain)
	if err != nil {
		return fmt.Errorf("获取链配置失败: %v", err)
	}
	chainID := big.NewInt(int64(chainConfig.ChainID))

	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return err
	}
	defer ethClient.Close()

	if err := s.checkEvmNonceHealth(ctx, ethClient, walletCtx.Address); err != nil {
		return err
	}

	splitterAddr := common.HexToAddress(splitter)
	tokenAddr := common.HexToAddress(token)
	owner := common.HexToAddress(walletCtx.Address)

	// 查询可提取余额
	balance, err := tx_util.GetBalanceERC20(ctx, ethClient, splitterAddr, tokenAddr, owner)
	if err != nil {
		logFn(fmt.Sprintf("查询可提取余额失败: %v", err))
	} else {
		logFn(fmt.Sprintf("可提取余额: %s (wei)", balance.String()))
	}

	tokens := []common.Address{tokenAddr}
	data, err := tx_util.BuildReleaseERC20TokensData(tokens, owner)
	if err != nil {
		return fmt.Errorf("构建 releaseERC20Tokens data 失败: %v", err)
	}

	tx, err := tx_util.BuildLegacyRawTx(ctx, ethClient, *chainID, owner, splitterAddr, *big.NewInt(0), data)
	if err != nil {
		return fmt.Errorf("构造 release 交易失败: %v", err)
	}

	signer := types.NewLondonSigner(chainID)
	signedTx, err := types.SignTx(tx, signer, walletCtx.PrivateKey)
	if err != nil {
		return fmt.Errorf("签名失败: %v", err)
	}

	txID, err := tx_util.SendRawTransaction(ctx, ethClient, signedTx)
	if err != nil {
		return fmt.Errorf("发送 release 交易失败: %v", err)
	}
	txIDHex := "0x" + hex.EncodeToString(txID)
	logFn(fmt.Sprintf("release 交易已发送: %s", txIDHex))

	if err := s.waitTxConfirmations(ctx, ethClient, []string{txIDHex}, 120*time.Second); err != nil {
		return fmt.Errorf("release 交易确认失败: %v", err)
	}
	logFn("提现完成")
	return nil
}

func (s *GUIService) releaseOnTron(ctx context.Context, chain, splitter, token string, walletCtx *client.WalletContext, logFn func(string)) error {
	tronClient, err := s.createTronClient(chain)
	if err != nil {
		return err
	}
	defer tronClient.Conn.Close()

	// 查询可提取余额
	balance, err := tx_util.GetTronBalanceERC20(tronClient, splitter, token, walletCtx.Address, walletCtx.Address)
	if err != nil {
		logFn(fmt.Sprintf("查询可提取余额失败: %v", err))
	} else {
		logFn(fmt.Sprintf("可提取余额: %s (最小单位)", balance.String()))
	}

	calldata, err := tx_util.BuildTronReleaseData([]string{token}, walletCtx.Address)
	if err != nil {
		return fmt.Errorf("构建 release calldata 失败: %v", err)
	}
	rawTx, hashBytes, err := tx_util.CreateTronTxWithData(tronClient, walletCtx.Address, splitter, calldata)
	if err != nil {
		return fmt.Errorf("构造 release 交易失败: %v", err)
	}

	signedBytes, err := tx_util.SignWithPrivateKey(walletCtx.PrivateKey, hashBytes)
	if err != nil {
		return fmt.Errorf("签名失败: %v", err)
	}
	if err := tx_util.SignTronTransaction(rawTx, hex.EncodeToString(signedBytes)); err != nil {
		return fmt.Errorf("添加签名失败: %v", err)
	}

	txID, err := tx_util.BroadcastTronTransaction(tronClient, rawTx)
	if err != nil {
		return fmt.Errorf("广播 release 交易失败: %v", err)
	}
	logFn(fmt.Sprintf("release 交易已发送: %s", txID))

	time.Sleep(6 * time.Second)
	logFn("提现完成")
	return nil
}

// ---- 查询余额 (用于 GUI 显示) ----

// QueryCollectableBalance 查询所有 receipt wallet 中指定 token 的可归集余额总和
func (s *GUIService) QueryCollectableBalance(splitter, token string) (string, error) {
	if !s.IsUnlocked() {
		return "", fmt.Errorf("请先解锁")
	}
	mc := s.mc
	splitWallet, err := mc.GetSplit(splitter)
	if err != nil || splitWallet == nil {
		return "", fmt.Errorf("查询分账合约失败: %v", err)
	}

	walletCtx := mc.GetWalletContext()
	if walletCtx == nil {
		return "", fmt.Errorf("请先导入商户钱包")
	}

	chain := splitWallet.Chain
	chainConfig, err := mc.GetChainConfig(chain)
	if err != nil {
		return "", fmt.Errorf("获取链配置失败: %v", err)
	}

	if strings.ToLower(chainConfig.ChainType) == "tron" {
		tronClient, err := s.createTronClient(chain)
		if err != nil {
			return "", err
		}
		defer tronClient.Conn.Close()

		balance, err := tx_util.GetTronCollectableBalance(tronClient, splitter, token, walletCtx.Address)
		if err != nil {
			return "", err
		}
		return balance.String(), nil
	}

	ctx := context.Background()
	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return "", err
	}
	defer ethClient.Close()

	splitterAddr := common.HexToAddress(splitter)
	tokenAddr := common.HexToAddress(token)

	balance, err := tx_util.GetCollectableBalance(ctx, ethClient, splitterAddr, tokenAddr)
	if err != nil {
		return "", err
	}
	return balance.String(), nil
}

// QueryReleasableBalance 查询 payee 在 split wallet 中某 token 的可提现余额
func (s *GUIService) QueryReleasableBalance(splitter, token string) (string, error) {
	if !s.IsUnlocked() {
		return "", fmt.Errorf("请先解锁")
	}
	mc := s.mc
	splitWallet, err := mc.GetSplit(splitter)
	if err != nil || splitWallet == nil {
		return "", fmt.Errorf("查询分账合约失败: %v", err)
	}

	walletCtx := mc.GetWalletContext()
	if walletCtx == nil {
		return "", fmt.Errorf("请先导入商户钱包")
	}

	chain := splitWallet.Chain
	chainConfig, err := mc.GetChainConfig(chain)
	if err != nil {
		return "", fmt.Errorf("获取链配置失败: %v", err)
	}

	if strings.ToLower(chainConfig.ChainType) == "tron" {
		tronClient, err := s.createTronClient(chain)
		if err != nil {
			return "", err
		}
		defer tronClient.Conn.Close()

		balance, err := tx_util.GetTronBalanceERC20(tronClient, splitter, token, walletCtx.Address, walletCtx.Address)
		if err != nil {
			return "", err
		}
		return balance.String(), nil
	}

	ctx := context.Background()
	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return "", err
	}
	defer ethClient.Close()

	splitterAddr := common.HexToAddress(splitter)
	tokenAddr := common.HexToAddress(token)
	owner := common.HexToAddress(walletCtx.Address)

	balance, err := tx_util.GetBalanceERC20(ctx, ethClient, splitterAddr, tokenAddr, owner)
	if err != nil {
		return "", err
	}
	return balance.String(), nil
}

// QueryReceiptWalletCount 查询合约中注册的 receipt wallet 总数
func (s *GUIService) QueryReceiptWalletCount(splitter string) (uint64, error) {
	if !s.IsUnlocked() {
		return 0, fmt.Errorf("请先解锁")
	}
	mc := s.mc
	splitWallet, err := mc.GetSplit(splitter)
	if err != nil || splitWallet == nil {
		return 0, fmt.Errorf("查询分账合约失败: %v", err)
	}

	walletCtx := mc.GetWalletContext()
	if walletCtx == nil {
		return 0, fmt.Errorf("请先导入商户钱包")
	}

	chain := splitWallet.Chain
	chainConfig, err := mc.GetChainConfig(chain)
	if err != nil {
		return 0, fmt.Errorf("获取链配置失败: %v", err)
	}

	ctx := context.Background()

	if strings.ToLower(chainConfig.ChainType) == "tron" {
		tronClient, err := s.createTronClient(chain)
		if err != nil {
			return 0, err
		}
		defer tronClient.Conn.Close()
		return tx_util.GetTronReceiptWalletCount(tronClient, splitter, walletCtx.Address)
	}

	ethClient, err := s.createEthClient(chain)
	if err != nil {
		return 0, err
	}
	defer ethClient.Close()

	splitterAddr := common.HexToAddress(splitter)
	count, err := tx_util.GetReceiptWalletCount(ctx, ethClient, splitterAddr)
	if err != nil {
		return 0, err
	}
	return count.Uint64(), nil
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func zeroPrivateKey(key *ecdsa.PrivateKey) {
	if key != nil && key.D != nil {
		key.D.SetInt64(0)
	}
}

func toSplitWalletInfo(w model.SplitWallet) SplitWalletInfo {
	return SplitWalletInfo{
		Address:            w.Address,
		Chain:              w.Chain,
		Merchant:           w.Merchant,
		Alias:              w.Alias,
		SplitWalletManager: w.SplitWalletManager,
		State:              w.State,
		ActivateTxID:       w.ActivateTxID,
		ProxyAdmin:         w.ProxyAdmin,
	}
}
