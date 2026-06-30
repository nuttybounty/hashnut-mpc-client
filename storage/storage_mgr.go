package storage

import (
	"fmt"
	"log"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"hashnut-mpc-client/storage/dal/model"
)

// StorageMgr 管理数据库连接和初始化
type StorageMgr struct {
	db *gorm.DB
}

// GetDB 返回底层的 *gorm.DB，供业务层使用
func (m *StorageMgr) GetDB() *gorm.DB {
	return m.db
}

// NewStorageMgr 创建并初始化 StorageMgr
// dbPath: SQLite 数据库文件路径（例如 "data.db"）
func NewStorageMgr(dbPath string) (*StorageMgr, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open database failed: %w", err)
	}

	// 启用外键约束（SQLite 默认关闭）
	if err := db.Exec("PRAGMA foreign_keys = ON;").Error; err != nil {
		return nil, fmt.Errorf("enable foreign keys failed: %w", err)
	}

	mgr := &StorageMgr{db: db}
	if err := mgr.init(); err != nil {
		return nil, err
	}
	return mgr, nil
}

// init 执行数据库初始化和默认数据插入
func (m *StorageMgr) init() error {
	// 1. 创建表（如果不存在）——直接执行原始 SQL 以确保外键约束
	if err := m.createTables(); err != nil {
		return err
	}
	if err := m.ensureColumns(); err != nil {
		return err
	}

	// 2. 插入默认数据（按主键检查，避免重复）
	if err := m.insertDefaultData(); err != nil {
		return err
	}

	log.Println("database initialized successfully")
	return nil
}

func (m *StorageMgr) ensureColumns() error {
	// 兼容旧表：如果有 receipt_wallet_manager 列但没有 split_wallet_manager 列，则添加新列
	if !m.hasColumn("split_wallet", "split_wallet_manager") {
		if err := m.db.Exec(`ALTER TABLE split_wallet ADD COLUMN split_wallet_manager TEXT;`).Error; err != nil {
			return fmt.Errorf("add split_wallet.split_wallet_manager failed: %w", err)
		}
		// 迁移旧数据
		if m.hasColumn("split_wallet", "receipt_wallet_manager") {
			m.db.Exec(`UPDATE split_wallet SET split_wallet_manager = receipt_wallet_manager WHERE split_wallet_manager IS NULL AND receipt_wallet_manager IS NOT NULL;`)
		}
	}
	if !m.hasColumn("split_wallet", "state") {
		if err := m.db.Exec(`ALTER TABLE split_wallet ADD COLUMN state INTEGER DEFAULT 0;`).Error; err != nil {
			return fmt.Errorf("add split_wallet.state failed: %w", err)
		}
	}
	if !m.hasColumn("split_wallet", "activate_tx_id") {
		if err := m.db.Exec(`ALTER TABLE split_wallet ADD COLUMN activate_tx_id TEXT;`).Error; err != nil {
			return fmt.Errorf("add split_wallet.activate_tx_id failed: %w", err)
		}
	}
	if !m.hasColumn("split_wallet", "proxy_admin") {
		if err := m.db.Exec(`ALTER TABLE split_wallet ADD COLUMN proxy_admin TEXT;`).Error; err != nil {
			return fmt.Errorf("add split_wallet.proxy_admin failed: %w", err)
		}
	}
	if !m.hasColumn("split_wallet", "alias") {
		if err := m.db.Exec(`ALTER TABLE split_wallet ADD COLUMN alias TEXT DEFAULT '';`).Error; err != nil {
			return fmt.Errorf("add split_wallet.alias failed: %w", err)
		}
	}
	return nil
}

func (m *StorageMgr) hasColumn(tableName, columnName string) bool {
	rows, err := m.db.Raw(fmt.Sprintf("PRAGMA table_info(%s);", tableName)).Rows()
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name string
		var typ string
		var notNull int
		var defaultValue interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return false
		}
		if name == columnName {
			return true
		}
	}
	return false
}

// createTables 执行原始建表 SQL（包含外键约束）
func (m *StorageMgr) createTables() error {
	// 这些 SQL 应与 gen.go 中保持一致
	sqls := []string{
		`CREATE TABLE IF NOT EXISTS password_auth (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			salt BLOB NOT NULL,
			hash BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS rpc_endpoint (
			chain TEXT NOT NULL PRIMARY KEY,
			endpoint TEXT NOT NULL,
			api_key TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS chain_config (
			chain TEXT NOT NULL PRIMARY KEY,
			chain_id INTEGER NOT NULL,
			chain_type TEXT NOT NULL,
			currency TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS token_config (
			symbol TEXT NOT NULL PRIMARY KEY,
			chain TEXT NOT NULL,
			contract TEXT NOT NULL,
			name TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS merchant_wallet (
			address TEXT PRIMARY KEY,
			chain_type TEXT,
			enc_key TEXT,
			is_default BOOLEAN DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS split_wallet (
			address TEXT PRIMARY KEY,
				chain TEXT,
				merchant TEXT,
				split_wallet_manager TEXT,
				state INTEGER DEFAULT 0,
				activate_tx_id TEXT,
				proxy_admin TEXT,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (merchant) REFERENCES merchant_wallet(address) ON DELETE CASCADE
			);`,

		`CREATE TABLE IF NOT EXISTS receipt_address (
			address TEXT PRIMARY KEY,
			splitter TEXT NOT NULL,
			chain TEXT,
			curve TEXT,
			key_from_data BLOB,
			pub_key_data BLOB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (splitter) REFERENCES split_wallet(address) ON DELETE CASCADE
		);`,

		`CREATE INDEX IF NOT EXISTS idx_receipt_splitter ON receipt_address(splitter);`,

		`CREATE TABLE IF NOT EXISTS split_wallet_manager (
			splitter TEXT NOT NULL PRIMARY KEY,
			chain TEXT NOT NULL,
			merchant TEXT NOT NULL,
			manager_address TEXT NOT NULL,
			key_from_data BLOB,
			pub_key_data BLOB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (merchant) REFERENCES merchant_wallet(address) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS app_state (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS batch_setup_session (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			splitter TEXT NOT NULL,
			token TEXT NOT NULL,
			amount TEXT NOT NULL,
			count INTEGER NOT NULL,
			state TEXT NOT NULL DEFAULT 'INIT',
			receipt_addrs TEXT,
			approve_tx_ids TEXT,
			activate_tx_id TEXT,
			error_msg TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE INDEX IF NOT EXISTS idx_batch_setup_splitter ON batch_setup_session(splitter, state);`,
	}

	for _, sql := range sqls {
		if err := m.db.Exec(sql).Error; err != nil {
			return fmt.Errorf("execute sql failed: %s\nerror: %w", sql, err)
		}
	}
	return nil
}

// insertDefaultData 插入默认配置（根据主键检查，避免重复）
// 链配置、Token 配置、RPC 配置已改为从后端拉取，不再写入本地数据库
func (m *StorageMgr) insertDefaultData() error {
	// 插入默认 app_state（本地偏好设置）
	defaultStates := []model.AppState{
		{Key: "default_chain", Value: "ETH"},
	}
	for _, state := range defaultStates {
		if err := m.db.Where(model.AppState{Key: state.Key}).FirstOrCreate(&state).Error; err != nil {
			return fmt.Errorf("failed to upsert app_state for %s: %w", state.Key, err)
		}
	}
	log.Println("app_state default records ensured")

	return nil
}
