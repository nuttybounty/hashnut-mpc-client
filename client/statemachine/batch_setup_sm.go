package statemachine

import (
	"encoding/json"
	"fmt"
	"hashnut-mpc-client/storage/dal/model"
	"time"

	"github.com/qmuntal/stateless"
	"gorm.io/gorm"
)

// ---- Batch Setup 状态 ----

const (
	BSStateInit         = "INIT"
	BSStateKeygen       = "KEYGEN"
	BSStateFundGas      = "FUND_GAS"
	BSStateApprove      = "APPROVE"
	BSStateWaitConfirm  = "WAIT_CONFIRM"
	BSStateActivate     = "ACTIVATE"     // addReceiptWallets
	BSStateSweep        = "SWEEP"
	BSStateRegister     = "REGISTER"
	BSStateComplete     = "COMPLETE"
	BSStateFailed       = "FAILED"
)

// ---- Batch Setup 触发器 ----

const (
	TriggerStart         = "TriggerStart"
	TriggerKeygenDone    = "TriggerKeygenDone"
	TriggerFundDone      = "TriggerFundDone"
	TriggerApproveDone   = "TriggerApproveDone"
	TriggerConfirmDone   = "TriggerConfirmDone"
	TriggerActivateDone  = "TriggerActivateDone"
	TriggerSweepDone     = "TriggerSweepDone"
	TriggerRegisterDone  = "TriggerRegisterDone"
	TriggerFail          = "TriggerFail"
)

// NewBatchSetupSM 创建 Batch Setup 状态机，初始状态从参数传入
func NewBatchSetupSM(initialState string) *stateless.StateMachine {
	sm := stateless.NewStateMachine(initialState)

	sm.Configure(BSStateInit).Permit(TriggerStart, BSStateKeygen).Permit(TriggerFail, BSStateFailed)
	sm.Configure(BSStateKeygen).Permit(TriggerKeygenDone, BSStateFundGas).Permit(TriggerFail, BSStateFailed)
	sm.Configure(BSStateFundGas).Permit(TriggerFundDone, BSStateApprove).Permit(TriggerFail, BSStateFailed)
	sm.Configure(BSStateApprove).Permit(TriggerApproveDone, BSStateWaitConfirm).Permit(TriggerFail, BSStateFailed)
	sm.Configure(BSStateWaitConfirm).Permit(TriggerConfirmDone, BSStateActivate).Permit(TriggerFail, BSStateFailed)
	sm.Configure(BSStateActivate).Permit(TriggerActivateDone, BSStateSweep).Permit(TriggerFail, BSStateFailed)
	sm.Configure(BSStateSweep).Permit(TriggerSweepDone, BSStateRegister).Permit(TriggerFail, BSStateFailed)
	sm.Configure(BSStateRegister).Permit(TriggerRegisterDone, BSStateComplete).Permit(TriggerFail, BSStateFailed)

	return sm
}

// ---- Batch Setup Session Manager ----

type BatchSetupMgr struct {
	db *gorm.DB
}

func NewBatchSetupMgr(db *gorm.DB) *BatchSetupMgr {
	return &BatchSetupMgr{db: db}
}

// CreateSession 创建新的 batch setup session
func (m *BatchSetupMgr) CreateSession(splitter, token, amount string, count int) (*model.BatchSetupSession, error) {
	session := &model.BatchSetupSession{
		Splitter:  splitter,
		Token:     token,
		Amount:    amount,
		Count:     count,
		State:     BSStateInit,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := m.db.Create(session).Error; err != nil {
		return nil, fmt.Errorf("create batch setup session failed: %w", err)
	}
	return session, nil
}

// FindPendingSession 查找未完成的 session（非 COMPLETE 和非 FAILED）
func (m *BatchSetupMgr) FindPendingSession(splitter, token string, count int) *model.BatchSetupSession {
	var session model.BatchSetupSession
	err := m.db.Where("splitter = ? AND token = ? AND count = ? AND state NOT IN (?, ?)",
		splitter, token, count, BSStateComplete, BSStateFailed).
		Order("created_at DESC").
		First(&session).Error
	if err != nil {
		return nil
	}
	return &session
}

// TransitionTo 校验状态转换并持久化
func (m *BatchSetupMgr) TransitionTo(session *model.BatchSetupSession, trigger string) error {
	sm := NewBatchSetupSM(session.State)
	if err := sm.Fire(trigger); err != nil {
		return fmt.Errorf("state transition rejected: current=%s trigger=%s: %w", session.State, trigger, err)
	}
	newState := fmt.Sprintf("%v", sm.MustState())
	session.State = newState
	session.UpdatedAt = time.Now()
	return m.db.Model(session).Updates(map[string]interface{}{
		"state":      session.State,
		"updated_at": session.UpdatedAt,
	}).Error
}

// MarkFailed 标记为失败
func (m *BatchSetupMgr) MarkFailed(session *model.BatchSetupSession, errMsg string) error {
	session.State = BSStateFailed
	session.ErrorMsg = errMsg
	session.UpdatedAt = time.Now()
	return m.db.Model(session).Updates(map[string]interface{}{
		"state":      session.State,
		"error_msg":  session.ErrorMsg,
		"updated_at": session.UpdatedAt,
	}).Error
}

// SaveReceiptAddrs 保存生成的收款地址列表
func (m *BatchSetupMgr) SaveReceiptAddrs(session *model.BatchSetupSession, addrs []string) error {
	data, _ := json.Marshal(addrs)
	session.ReceiptAddrs = string(data)
	session.UpdatedAt = time.Now()
	return m.db.Model(session).Updates(map[string]interface{}{
		"receipt_addrs": session.ReceiptAddrs,
		"updated_at":    session.UpdatedAt,
	}).Error
}

// SaveApproveTxIds 保存 approve 交易 ID 列表
func (m *BatchSetupMgr) SaveApproveTxIds(session *model.BatchSetupSession, txIds []string) error {
	data, _ := json.Marshal(txIds)
	session.ApproveTxIds = string(data)
	session.UpdatedAt = time.Now()
	return m.db.Model(session).Updates(map[string]interface{}{
		"approve_tx_ids": session.ApproveTxIds,
		"updated_at":     session.UpdatedAt,
	}).Error
}

// SaveActivateTxId 保存 addReceiptWallets 交易 ID
func (m *BatchSetupMgr) SaveActivateTxId(session *model.BatchSetupSession, txId string) error {
	session.ActivateTxId = txId
	session.UpdatedAt = time.Now()
	return m.db.Model(session).Updates(map[string]interface{}{
		"activate_tx_id": session.ActivateTxId,
		"updated_at":     session.UpdatedAt,
	}).Error
}

// GetReceiptAddrs 从 session 解析收款地址列表
func (m *BatchSetupMgr) GetReceiptAddrs(session *model.BatchSetupSession) []string {
	if session.ReceiptAddrs == "" {
		return nil
	}
	var addrs []string
	_ = json.Unmarshal([]byte(session.ReceiptAddrs), &addrs)
	return addrs
}

// GetApproveTxIds 从 session 解析 approve 交易 ID 列表
func (m *BatchSetupMgr) GetApproveTxIds(session *model.BatchSetupSession) []string {
	if session.ApproveTxIds == "" {
		return nil
	}
	var txIds []string
	_ = json.Unmarshal([]byte(session.ApproveTxIds), &txIds)
	return txIds
}
