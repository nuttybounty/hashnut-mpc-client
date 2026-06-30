package model

import (
	"time"
)

const TableNameSplitWalletManager = "split_wallet_manager"

type SplitWalletManager struct {
	Splitter       string    `gorm:"column:splitter;type:TEXT;primaryKey" json:"splitter"`
	Chain          string    `gorm:"column:chain;type:TEXT" json:"chain"`
	Merchant       string    `gorm:"column:merchant;type:TEXT" json:"merchant"`
	ManagerAddress string    `gorm:"column:manager_address;type:TEXT" json:"manager_address"`
	KeyFromData    []byte    `gorm:"column:key_from_data;type:BLOB" json:"key_from_data"`
	PubKeyData     []byte    `gorm:"column:pub_key_data;type:BLOB" json:"pub_key_data"`
	CreatedAt      time.Time `gorm:"column:created_at;type:TIMESTAMP" json:"created_at"`
}

func (*SplitWalletManager) TableName() string {
	return TableNameSplitWalletManager
}
