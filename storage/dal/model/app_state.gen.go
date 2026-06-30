package model

import (
	"time"
)

const TableNameAppState = "app_state"

// AppState mapped from table <app_state>
type AppState struct {
	Key       string    `gorm:"column:key;type:TEXT;primaryKey" json:"key"`
	Value     string    `gorm:"column:value;type:TEXT" json:"value"`
	UpdatedAt time.Time `gorm:"column:updated_at;type:TIMESTAMP" json:"updated_at"`
}

// TableName AppState's table name
func (*AppState) TableName() string {
	return TableNameAppState
}
