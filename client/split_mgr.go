package client

import (
	"errors"
	"fmt"
	req_model "hashnut-mpc-client/model"
	"hashnut-mpc-client/storage/dal/model"
	"strings"
	"time"

	"gorm.io/gorm"
)

// SplitMgr 管理商户钱包
type SplitMgr struct {
	db *gorm.DB
}

// NewSplitMgr 创建钱包管理器实例
func NewSplitMgr(db *gorm.DB) *SplitMgr {
	return &SplitMgr{db: db}
}

// GetAllSplitWallets 查询 split_wallet 表里面所有的分账合约信息
func (mgr *SplitMgr) GetAllSplitWallets() ([]model.SplitWallet, error) {
	var wallets []model.SplitWallet
	// 使用 Find 查询所有记录
	if err := mgr.db.Find(&wallets).Error; err != nil {
		return nil, fmt.Errorf("query all split wallets failed: %w", err)
	}
	return wallets, nil
}

// GetSplit 根据 address 获取 split_wallet 里面的分账合约信息
func (mgr *SplitMgr) GetSplit(address string) (*model.SplitWallet, error) {
	var wallet model.SplitWallet
	address = normalizeAddress(address)
	// 使用 First 查询单条记录（按主键 address）
	err := mgr.db.Where("address = ?", address).First(&wallet).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 记录不存在，返回 nil, nil 或自定义错误，根据业务需求选择
			return nil, nil
		}
		return nil, fmt.Errorf("query split wallet by address %s failed: %w", address, err)
	}
	return &wallet, nil
}

// AddSplit 添加分账合约
func (mgr *SplitMgr) AddSplit(chain, address, merchant string) error {
	return mgr.AddSplitWithManager(chain, address, merchant, "")
}

func (mgr *SplitMgr) AddSplitWithManager(chain, address, merchant, splitWalletManager string) error {
	address = normalizeAddress(address)
	merchant = normalizeAddress(merchant)
	splitWalletManager = normalizeAddress(splitWalletManager)
	wallet := &model.SplitWallet{
		Address:            address,
		Chain:              chain,
		Merchant:           merchant,
		SplitWalletManager: splitWalletManager,
		State:              0,
	}
	// 使用 Create 插入新记录。若主键已存在，会返回错误。
	if err := mgr.db.Create(wallet).Error; err != nil {
		return fmt.Errorf("create split wallet failed: %w", err)
	}
	return nil
}

// SyncSplitWallets 将从 proxy 获取的分账合约同步到本地数据库，已存在的跳过，返回新增数量
func (mgr *SplitMgr) SyncSplitWallets(records []req_model.SplitWalletDeployDetail, merchant string) (int, error) {
	synced := 0
	for _, r := range records {
		if r.ContractAddress == "" {
			continue
		}
		contractAddress := normalizeAddress(r.ContractAddress)
		// 检查是否已存在
		existing, err := mgr.GetSplit(contractAddress)
		if err != nil {
			return synced, fmt.Errorf("查询分账合约 %s 失败: %w", contractAddress, err)
		}
		if existing != nil {
			manager := normalizeAddress(r.SplitWalletManager)
			updates := map[string]interface{}{
				"state":          r.State,
				"alias":          r.ContractAlias,
				"activate_tx_id": r.ActivateTxID,
				"proxy_admin":    normalizeAddress(r.ProxyAdmin),
				"updated_at":     time.Now(),
			}
			if manager != "" {
				updates["split_wallet_manager"] = manager
			}
			if err := mgr.db.Model(&model.SplitWallet{}).Where("address = ?", contractAddress).Updates(updates).Error; err != nil {
				return synced, fmt.Errorf("更新分账合约 %s 状态失败: %w", contractAddress, err)
			}
			continue
		}
		// 插入新记录
		if err := mgr.AddSplitWithManager(r.Chain, contractAddress, merchant, r.SplitWalletManager); err != nil {
			return synced, fmt.Errorf("添加分账合约 %s 失败: %w", contractAddress, err)
		}
		if err := mgr.db.Model(&model.SplitWallet{}).Where("address = ?", contractAddress).Updates(map[string]interface{}{
			"state":          r.State,
			"alias":          r.ContractAlias,
			"activate_tx_id": r.ActivateTxID,
			"proxy_admin":    normalizeAddress(r.ProxyAdmin),
			"updated_at":     time.Now(),
		}).Error; err != nil {
			return synced, fmt.Errorf("更新分账合约 %s 状态失败: %w", contractAddress, err)
		}
		synced++
	}
	return synced, nil
}

func normalizeAddress(address string) string {
	if strings.HasPrefix(address, "0x") || strings.HasPrefix(address, "0X") {
		return strings.ToLower(address)
	}
	return address
}

// GetReceiptsBySplitter 获取指定 splitter 下所有收款地址
func (mgr *SplitMgr) GetReceiptsBySplitter(splitter string) ([]string, error) {
	splitter = normalizeAddress(splitter)
	var addresses []string
	err := mgr.db.Model(&model.ReceiptAddress{}).
		Where("splitter = ?", splitter).
		Select("address").
		Order("created_at DESC").
		Find(&addresses).Error
	if err != nil {
		return nil, err
	}
	return addresses, nil
}

// GetAllReceipts 获取所有的收款地址列表
func (mgr *SplitMgr) GetAllReceipts() ([]string, error) {
	if mgr.db == nil {
		return nil, errors.New("database not initialized")
	}

	var addresses []string
	// 直接查询 address 字段并按 created_at 倒序
	err := mgr.db.Model(&model.ReceiptAddress{}).
		Select("address").
		Order("created_at DESC").
		Find(&addresses).Error
	if err != nil {
		return nil, err
	}
	return addresses, nil
}
