package client

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"hashnut-mpc-client/storage/dal/model"
	"hashnut-mpc-client/util/encrypt_util"
	"hashnut-mpc-client/util/tx_util"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type WalletContext struct {
	Chain      string // 当前具体链: "ETH", "POLYGON", "BSC", "TRON"
	ChainType  string // 链类型: "evm", "tron"
	Address    string
	PrivateKey *ecdsa.PrivateKey
}

// WalletMgr 管理商户钱包
type WalletMgr struct {
	password     string
	db           *gorm.DB
	walletCtx    *WalletContext
	remoteConfig *RemoteConfigMgr
}

// NewWalletMgr 创建钱包管理器实例
func NewWalletMgr(gormDb *gorm.DB) *WalletMgr {
	return &WalletMgr{
		db:        gormDb,
		walletCtx: &WalletContext{},
	}
}

// SetRemoteConfig 注入远程配置管理器
func (mgr *WalletMgr) SetRemoteConfig(rc *RemoteConfigMgr) {
	mgr.remoteConfig = rc
}

func (mgr *WalletMgr) GetDB() *gorm.DB {
	return mgr.db
}

// SwitchWalletCtx 切换钱包上下文
func (mgr *WalletMgr) SwitchWalletCtx(wCtx *WalletContext) {
	mgr.walletCtx = wCtx
}

// SetPassword 设置密码
func (mgr *WalletMgr) SetPassword(password string) {
	mgr.password = password
}

// GetPassword 获取密码
func (mgr *WalletMgr) GetPassword() string {
	return mgr.password
}

// GetPasswordAuth 从数据库读取盐和哈希（仅 id=1 的记录）
func (mgr *WalletMgr) GetPasswordAuth() (salt, hash []byte, err error) {
	var auth model.PasswordAuth
	err = mgr.db.Where("id = ?", 1).First(&auth).Error
	if err != nil {
		return nil, nil, err
	}
	return auth.Salt, auth.Hash, nil
}

// SavePasswordAuth 保存或更新密码验证记录（id=1）
func (mgr *WalletMgr) SavePasswordAuth(salt, hash []byte) error {
	auth := &model.PasswordAuth{
		ID:        1,
		Salt:      salt,
		Hash:      hash,
		CreatedAt: time.Now(),
	}
	return mgr.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"salt", "hash", "created_at"}),
	}).Create(auth).Error
}

// ============ App State (default_chain) ============

// GetDefaultChain 从 app_state 读取默认链
func (mgr *WalletMgr) GetDefaultChain() (string, error) {
	var state model.AppState
	err := mgr.db.Where("key = ?", "default_chain").First(&state).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "ETH", nil // 默认 ETH
		}
		return "", fmt.Errorf("查询默认链失败: %w", err)
	}
	return state.Value, nil
}

// setDefaultChainInDB 持久化默认链到 app_state
func (mgr *WalletMgr) setDefaultChainInDB(chain string) error {
	state := &model.AppState{
		Key:       "default_chain",
		Value:     chain,
		UpdatedAt: time.Now(),
	}
	return mgr.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(state).Error
}

// ============ Chain Config ============

// getChainType 从 RemoteConfigMgr 查询链类型，fallback 到本地 chain_config 表
func (mgr *WalletMgr) getChainType(chain string) (string, error) {
	// 优先从远程配置（内存）查询
	if mgr.remoteConfig != nil {
		cfg, err := mgr.remoteConfig.GetChainConfig(chain)
		if err == nil {
			return cfg.ChainType, nil
		}
	}
	// fallback: 从本地 SQLite chain_config 表查询
	var config model.ChainConfig
	err := mgr.db.Where("chain = ?", chain).First(&config).Error
	if err != nil {
		return "", fmt.Errorf("查询链配置失败 (chain=%s): %w", chain, err)
	}
	return config.ChainType, nil
}

// ============ Default Wallet (per chain_type) ============

// GetDefaultWalletForChainType 获取指定链类型的默认钱包地址
func (mgr *WalletMgr) GetDefaultWalletForChainType(chainType string) (string, error) {
	// 1. 查找该链类型下 is_default=1 的钱包
	var defaultWallet model.MerchantWallet
	err := mgr.db.Where("chain_type = ? AND is_default = ?", chainType, 1).First(&defaultWallet).Error
	if err == nil {
		return defaultWallet.Address, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("查询默认地址失败: %w", err)
	}

	// 2. 没有默认，取该链类型下最新创建的
	var latestWallet model.MerchantWallet
	err = mgr.db.Where("chain_type = ?", chainType).Order("created_at DESC").First(&latestWallet).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("没有 %s 类型的商户钱包，请先导入私钥", chainType)
	}
	if err != nil {
		return "", fmt.Errorf("查询最新地址失败: %w", err)
	}

	// 3. 自动设为默认
	if err := mgr.setDefaultAddrInDB(latestWallet.Address, chainType); err != nil {
		return "", fmt.Errorf("自动设置默认地址失败: %w", err)
	}
	return latestWallet.Address, nil
}

// GetDefaultWallet 返回当前链类型的默认商户钱包地址（兼容旧调用）
func (mgr *WalletMgr) GetDefaultWallet() (string, error) {
	// 获取当前链
	chain, err := mgr.GetDefaultChain()
	if err != nil {
		return "", err
	}
	chainType, err := mgr.getChainType(chain)
	if err != nil {
		return "", err
	}
	return mgr.GetDefaultWalletForChainType(chainType)
}

// setDefaultAddrInDB 在同一 chain_type 内原子地将指定地址设为默认
func (mgr *WalletMgr) setDefaultAddrInDB(addr, chainType string) error {
	tx := mgr.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 1. 将所有地址的 is_default 置为 false（全局只保留一个默认钱包）
	if err := tx.Model(&model.MerchantWallet{}).
		Where("1 = 1").
		Update("is_default", false).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("reset all defaults failed: %w", err)
	}

	// 2. 将目标地址置为 true
	result := tx.Model(&model.MerchantWallet{}).
		Where("address = ?", addr).
		Updates(map[string]interface{}{
			"is_default": true,
			"updated_at": time.Now(),
		})
	if result.Error != nil {
		tx.Rollback()
		return fmt.Errorf("set default for %s failed: %w", addr, result.Error)
	}
	if result.RowsAffected == 0 {
		tx.Rollback()
		return fmt.Errorf("地址 %s 不存在", addr)
	}

	return tx.Commit().Error
}

// ============ Chain + Wallet 联动切换 ============

// SetDefaultChain 切换默认链，如果链类型变化则联动切换钱包
func (mgr *WalletMgr) SetDefaultChain(chain string) error {
	// 1. 查询目标链的链类型
	newChainType, err := mgr.getChainType(chain)
	if err != nil {
		return err
	}

	currentChainType := mgr.walletCtx.ChainType

	// 2. 持久化默认链
	if err := mgr.setDefaultChainInDB(chain); err != nil {
		return fmt.Errorf("保存默认链失败: %w", err)
	}

	// 3. 更新上下文中的链信息
	mgr.walletCtx.Chain = chain
	mgr.walletCtx.ChainType = newChainType

	// 4. 如果链类型没变（如 eth→polygon），地址和私钥不变，直接返回
	if currentChainType == newChainType && mgr.walletCtx.PrivateKey != nil {
		return nil
	}

	// 5. 链类型变了（如 polygon→tron），自动切换到目标类型的默认钱包
	walletAddr, err := mgr.GetDefaultWalletForChainType(newChainType)
	if err != nil {
		return fmt.Errorf("切换到 %s 类型的默认钱包失败: %w", newChainType, err)
	}

	privKey, err := mgr.getMerchantPrivKey(walletAddr)
	if err != nil {
		return fmt.Errorf("解锁私钥失败: %w", err)
	}

	mgr.walletCtx.Address = walletAddr
	mgr.walletCtx.PrivateKey = privKey
	return nil
}

// SetDefaultWallet 切换默认钱包地址，解锁私钥；如果跨链类型则联动切换链
func (mgr *WalletMgr) SetDefaultWallet(currentWallet string) error {
	// 1. 检查地址是否存在
	merchantWallet, err := mgr.GetMerchantWallet(currentWallet)
	if err != nil {
		return err
	}
	if merchantWallet == nil {
		return fmt.Errorf("设置默认地址失败，地址不存在")
	}

	// 2. 解锁私钥
	privKey, err := mgr.getMerchantPrivKey(currentWallet)
	if err != nil {
		return fmt.Errorf("解锁私钥失败: %v", err)
	}

	// 3. 更新数据库默认地址
	if err := mgr.setDefaultAddrInDB(currentWallet, merchantWallet.ChainType); err != nil {
		return fmt.Errorf("设置默认地址失败: %v", err)
	}

	// 4. 如果链类型变了，联动切换链到目标类型的默认链
	if mgr.walletCtx.ChainType != merchantWallet.ChainType {
		defaultChain := mgr.getDefaultChainForType(merchantWallet.ChainType)
		if err := mgr.setDefaultChainInDB(defaultChain); err != nil {
			return fmt.Errorf("切换默认链失败: %v", err)
		}
		mgr.walletCtx.Chain = defaultChain
	}

	// 5. 更新上下文
	mgr.walletCtx.ChainType = merchantWallet.ChainType
	mgr.walletCtx.PrivateKey = privKey
	mgr.walletCtx.Address = currentWallet

	return nil
}

// getDefaultChainForType 根据链类型返回该类型下的默认链名称
func (mgr *WalletMgr) getDefaultChainForType(chainType string) string {
	switch chainType {
	case "evm":
		// 尝试保持当前链（如果当前也是 evm）
		if tx_util.IsEvm(mgr.walletCtx.Chain) {
			return mgr.walletCtx.Chain
		}
		return "ETH"
	case "tron":
		return "TRON"
	default:
		return "ETH"
	}
}

// ============ 启动初始化 ============

// InitContext 启动时加载默认链 + 默认钱包，构建完整的 WalletContext
func (mgr *WalletMgr) InitContext() error {
	// 1. 加载默认链
	chain, err := mgr.GetDefaultChain()
	if err != nil {
		return err
	}

	// 2. 查询链类型
	chainType, err := mgr.getChainType(chain)
	if err != nil {
		return err
	}

	mgr.walletCtx.Chain = chain
	mgr.walletCtx.ChainType = chainType

	// 3. 加载该链类型的默认钱包
	walletAddr, err := mgr.GetDefaultWalletForChainType(chainType)
	if err != nil {
		// 该链类型下没有钱包，不算致命错误
		fmt.Printf("当前链类型 %s 下没有钱包，请先导入私钥\n", chainType)
		return nil
	}

	// 4. 解锁私钥
	privKey, err := mgr.getMerchantPrivKey(walletAddr)
	if err != nil {
		return fmt.Errorf("解锁私钥失败: %w", err)
	}

	mgr.walletCtx.Address = walletAddr
	mgr.walletCtx.PrivateKey = privKey
	return nil
}

func (mgr *WalletMgr) GetWalletCtx() *WalletContext {
	return mgr.walletCtx
}

// ============ CRUD ============

// GetMerchantWallet 读取商户钱包记录
func (mgr *WalletMgr) GetMerchantWallet(merchantAddress string) (*model.MerchantWallet, error) {
	var wallet model.MerchantWallet
	err := mgr.db.Where("address = ?", merchantAddress).First(&wallet).Error
	return &wallet, err
}

// SaveMerchantWallet 保存或更新商户钱包加密私钥
func (mgr *WalletMgr) SaveMerchantWallet(merchantAddress, chainType string, encKeyJSON []byte) error {
	wallet := &model.MerchantWallet{
		Address:   merchantAddress,
		ChainType: chainType,
		EncKey:    string(encKeyJSON),
		UpdatedAt: time.Now(),
	}
	return mgr.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "address"}},
		DoUpdates: clause.AssignmentColumns([]string{"chain_type", "enc_key", "updated_at"}),
	}).Create(wallet).Error
}

// GetAllMerchantWallets 查询所有已存储的商户钱包地址及链类型
func (mgr *WalletMgr) GetAllMerchantWallets() ([]model.MerchantWallet, error) {
	var wallets []model.MerchantWallet
	err := mgr.db.Model(&model.MerchantWallet{}).
		Select("address", "chain_type", "is_default").
		Find(&wallets).Error
	if err != nil {
		return nil, err
	}
	return wallets, nil
}

func (mgr *WalletMgr) getMerchantPrivKey(merchantAddress string) (*ecdsa.PrivateKey, error) {
	merchantWallet, err := mgr.GetMerchantWallet(merchantAddress)
	if err != nil {
		return nil, err
	}

	var encKey encrypt_util.EncryptedPrivateKey
	if err = json.Unmarshal([]byte(merchantWallet.EncKey), &encKey); err != nil {
		return nil, err
	}

	privKeyBytes, err := encrypt_util.Decrypt(&encKey, mgr.GetPassword())
	if err != nil {
		return nil, err
	}

	privateKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
