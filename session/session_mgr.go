package session

import (
	"hashnut-mpc-client/ctx/ecdsa_ctx"
	"sync"
)

type SessionMgr struct {
	sync.RWMutex
	KGSessions   map[int64]*ecdsa_ctx.KGContext
	SignSessions map[int64]*ecdsa_ctx.SignContext
}

func NewSessionMgr() *SessionMgr {
	return &SessionMgr{
		KGSessions:   make(map[int64]*ecdsa_ctx.KGContext),
		SignSessions: make(map[int64]*ecdsa_ctx.SignContext),
	}
}

func (sm *SessionMgr) GetKGSession(sessionID int64) (*ecdsa_ctx.KGContext, bool) {
	sm.RLock()
	defer sm.RUnlock()
	session, exists := sm.KGSessions[sessionID]
	return session, exists
}

func (sm *SessionMgr) SetKGSession(sessionID int64, kgCtx *ecdsa_ctx.KGContext) {
	sm.Lock()
	defer sm.Unlock()
	sm.KGSessions[sessionID] = kgCtx
}

func (sm *SessionMgr) GetSignSession(sessionID int64) (*ecdsa_ctx.SignContext, bool) {
	sm.RLock()
	defer sm.RUnlock()
	session, exists := sm.SignSessions[sessionID]
	return session, exists
}

func (sm *SessionMgr) SetSignSession(sessionID int64, signCtx *ecdsa_ctx.SignContext) {
	sm.Lock()
	defer sm.Unlock()
	sm.SignSessions[sessionID] = signCtx
}
