package client

import (
	"context"
	"fmt"
	"hashnut-mpc-client/client/message"
	"hashnut-mpc-client/storage"
	db_model "hashnut-mpc-client/storage/dal/model"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
)

type MerchantClient struct {
	payServerURL string
	password     string
	httpClient   *http.Client
	tssCli       *TssClient
	storageMgr   *storage.StorageMgr
	walletMgr    *WalletMgr
	splitMgr     *SplitMgr
	remoteConfig *RemoteConfigMgr
}

// MerchantReqBody 表示HTTP请求的Body部分
type MerchantReqBody struct {
	Chain       string             `json:"chain"`
	Merchant    string             `json:"merchant"`
	SplitWallet string             `json:"splitWallet"`
	SID         string             `json:"sid"`
	UID         string             `json:"uid"`
	Method      string             `json:"method"`
	MpcMsg      message.MpcMessage `json:"mpcMsg"`

	// sign 端点新增字段（keygen 不需要，omitempty 避免传空值）
	SignerAddress string `json:"signerAddress,omitempty"`
	RawTxData     string `json:"rawTxData,omitempty"`
	MessageHash   string `json:"messageHash,omitempty"`
}

func NewMerchantClient(payURL string) *MerchantClient {
	storageMgr, err := storage.NewStorageMgr("./keys.db")
	if err != nil {
		panic(fmt.Errorf("get cache mgr failed: %v\n", err))
	}

	gormDb := storageMgr.GetDB()
	return &MerchantClient{
		httpClient:   &http.Client{Timeout: 60 * time.Second},
		payServerURL: strings.TrimSuffix(payURL, "/"),
		storageMgr:   storageMgr,
		walletMgr:    NewWalletMgr(gormDb),
		splitMgr:     NewSplitMgr(gormDb),
		remoteConfig: NewRemoteConfigMgr(),
		tssCli:       NewTssClient(gormDb),
	}
}

func (mc *MerchantClient) Start(ctx context.Context) error {
	// 挑战-响应认证：验证后端身份
	if err := mc.AuthenticateServer(ctx); err != nil {
		return fmt.Errorf("后端身份验证失败: %w", err)
	}

	// 从后端拉取链配置和 RPC 配置
	if err := mc.remoteConfig.LoadFromServer(mc); err != nil {
		fmt.Printf("从后端拉取配置失败（将使用本地缓存）: %v\n", err)
	}

	// 注入远程配置到 WalletMgr，使 getChainType 优先从内存查询
	mc.walletMgr.SetRemoteConfig(mc.remoteConfig)

	// 注入密码获取函数到 TssClient，用于加密/解密 MPC 密钥份额
	mc.tssCli.SetPasswordFunc(func() string { return mc.walletMgr.GetPassword() })

	// 使用 InitContext 加载默认链 + 默认钱包
	if err := mc.walletMgr.InitContext(); err != nil {
		return fmt.Errorf("初始化钱包上下文失败: %v", err)
	}

	walletCtx := mc.walletMgr.GetWalletCtx()
	if walletCtx.Address != "" {
		fmt.Printf("当前默认链: %s (%s)\n", walletCtx.Chain, walletCtx.ChainType)
		fmt.Printf("当前默认商户钱包地址: %s\n", walletCtx.Address)
		if err := mc.FetchSplitWallets(ctx, walletCtx.Chain); err != nil {
			fmt.Printf("Warning: 同步分账合约失败: %v\n", err)
		}
	}
	return nil
}

// ---- Config / Getters ----

func (mc *MerchantClient) GetDefaultChain() (string, error) {
	return mc.walletMgr.GetDefaultChain()
}

func (mc *MerchantClient) SetDefaultChain(chain string) error {
	if err := mc.walletMgr.SetDefaultChain(chain); err != nil {
		return err
	}
	return mc.walletMgr.InitContext()
}

func (mc *MerchantClient) GetDefaultWallet() (string, error) {
	return mc.walletMgr.GetDefaultWallet()
}

func (mc *MerchantClient) SetDefaultWallet(currentWallet string) error {
	if err := mc.walletMgr.SetDefaultWallet(currentWallet); err != nil {
		return err
	}
	return mc.walletMgr.InitContext()
}

func (mc *MerchantClient) GetWalletContext() *WalletContext {
	return mc.walletMgr.GetWalletCtx()
}

func (mc *MerchantClient) GetDB() *gorm.DB {
	return mc.storageMgr.GetDB()
}

func (mc *MerchantClient) ReloadWalletContext() error {
	return mc.walletMgr.InitContext()
}

func (mc *MerchantClient) GetStorageMgr() *storage.StorageMgr {
	return mc.storageMgr
}

func (mc *MerchantClient) GetChainConfig(chain string) (*db_model.ChainConfig, error) {
	return mc.remoteConfig.GetChainConfig(chain)
}

func (mc *MerchantClient) GetRpcUrl(chain string) (string, error) {
	return mc.remoteConfig.GetRpcUrl(chain)
}

func (mc *MerchantClient) GetRemoteConfig() *RemoteConfigMgr {
	return mc.remoteConfig
}

// ---- Password / Wallet Storage (delegate to WalletMgr) ----

func (mc *MerchantClient) SetPassword(password string) {
	mc.walletMgr.SetPassword(password)
}

func (mc *MerchantClient) GetPassword() string {
	return mc.walletMgr.GetPassword()
}

func (mc *MerchantClient) GetPasswordAuth() (salt, hash []byte, err error) {
	return mc.walletMgr.GetPasswordAuth()
}

func (mc *MerchantClient) SavePasswordAuth(salt []byte, key []byte) error {
	return mc.walletMgr.SavePasswordAuth(salt, key)
}

func (mc *MerchantClient) SaveMerchantWallet(merchantAddress, chain string, encKeyJSON []byte) error {
	return mc.walletMgr.SaveMerchantWallet(merchantAddress, chain, encKeyJSON)
}

func (mc *MerchantClient) GetAllMerchantWallets() ([]db_model.MerchantWallet, error) {
	return mc.walletMgr.GetAllMerchantWallets()
}

// ---- Split Wallet Storage (delegate to SplitMgr) ----

func (mc *MerchantClient) GetAllSplitWallets() ([]db_model.SplitWallet, error) {
	return mc.splitMgr.GetAllSplitWallets()
}

func (mc *MerchantClient) GetReceiptsBySplitter(splitter string) ([]string, error) {
	return mc.splitMgr.GetReceiptsBySplitter(splitter)
}

func (mc *MerchantClient) GetSplit(split string) (*db_model.SplitWallet, error) {
	return mc.splitMgr.GetSplit(split)
}

func (mc *MerchantClient) AddSplit(chain, split string) error {
	walletCtx := mc.walletMgr.GetWalletCtx()
	return mc.splitMgr.AddSplit(chain, split, walletCtx.Address)
}
