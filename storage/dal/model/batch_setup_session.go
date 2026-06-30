package model

import "time"

type BatchSetupSession struct {
	ID            int64     `gorm:"primaryKey;autoIncrement"`
	Splitter      string    `gorm:"not null"`
	Token         string    `gorm:"not null"`
	Amount        string    `gorm:"not null"`
	Count         int       `gorm:"not null"`
	State         string    `gorm:"not null;default:INIT"`
	ReceiptAddrs  string    `gorm:"type:text"`       // JSON array
	ApproveTxIds  string    `gorm:"type:text"`       // JSON array
	ActivateTxId  string    `gorm:"type:varchar(128)"`
	ErrorMsg      string    `gorm:"type:text"`
	CreatedAt     time.Time `gorm:"autoCreateTime"`
	UpdatedAt     time.Time `gorm:"autoUpdateTime"`
}

func (BatchSetupSession) TableName() string {
	return "batch_setup_session"
}
