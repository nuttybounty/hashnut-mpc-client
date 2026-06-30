package message

import (
	"encoding/json"
	"fmt"

	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/tss"
)

// MessageType 消息类型枚举
type MessageType string

const (
	MessageTypeKeyGenStep1      MessageType = "keyGenStep1"
	MessageTypeKeyGenStep2      MessageType = "keyGenStep2"
	MessageTypeKeyGenVerifyBind MessageType = "keyGenVerifyBind"
	MessageTypeGetAddress       MessageType = "getAddress"

	MessageTypeSignInit  MessageType = "signInit"
	MessageTypeSignStep1 MessageType = "signStep1"
	MessageTypeSignStep2 MessageType = "signStep2"
)

// MessageContent 消息内容接口，所有消息类型都需要实现
type MessageContent interface {
	// Type 获取消息类型
	Type() MessageType
	// Validate 验证消息内容
	Validate() error
}

// MpcMessage 表示 mpcMsg 对象，可以包含不同类型的消息
type MpcMessage struct {
	Type          MessageType     `json:"type"`    // 消息类型
	Content       json.RawMessage `json:"content"` // 消息内容（原始JSON）
	ParsedContent MessageContent  `json:"-"`       // 解析后的消息内容（内部使用，不序列化）
}

// ------------------ KeyGenStep1Msg ------------------
type KeyGenStep1Msg struct {
	Message  *tss.Message `json:"message"`
	Splitter string       `json:"splitter,omitempty"` // split wallet 地址，传递给 MPC Server 用于 PreParams 复用
}

func (m KeyGenStep1Msg) Type() MessageType { return MessageTypeKeyGenStep1 }
func (m KeyGenStep1Msg) Validate() error {
	if m.Message == nil {
		return fmt.Errorf("message is nil")
	}
	return nil
}

// ------------------ KeyGenStep2Msg ------------------
type KeyGenStep2Msg struct {
	Message *tss.Message `json:"message"`
}

func (m KeyGenStep2Msg) Type() MessageType { return MessageTypeKeyGenStep2 }
func (m KeyGenStep2Msg) Validate() error {
	if m.Message == nil {
		return fmt.Errorf("message is nil")
	}
	return nil
}

// ------------------ KeyGenVerifyBindMsg ------------------
type KeyGenVerifyBindMsg struct {
	PublicKey struct {
		X string `json:"X"`
		Y string `json:"Y"`
	} `json:"PublicKey"`
	Chain          string       `json:"Chain"`
	ChainCode      string       `json:"ChainCode"`
	P1DataId       int          `json:"P1DataId"`
	P1PreSignParam *tss.Message `json:"P1PreSignParam"`
}

func (m KeyGenVerifyBindMsg) Type() MessageType { return MessageTypeKeyGenVerifyBind }
func (m KeyGenVerifyBindMsg) Validate() error {
	if m.PublicKey.X == "" || m.PublicKey.Y == "" {
		return fmt.Errorf("public key missing")
	}
	if len(m.ChainCode) == 0 {
		return fmt.Errorf("chainCode missing")
	}
	if m.P1PreSignParam == nil {
		return fmt.Errorf("p1PreSignParam missing")
	}
	return nil
}

// ------------------ GetAddressMsg ------------------
type GetAddressMsg struct {
	Address string `json:"address"`
}

func (m GetAddressMsg) Type() MessageType { return MessageTypeGetAddress }
func (m GetAddressMsg) Validate() error {
	if m.Address == "" {
		return fmt.Errorf("address is required")
	}
	return nil
}

// ------------------ SignInitMsg ------------------
type SignInitMsg struct {
	Address string `json:"address"`
	Message string `json:"message"` // 待签名的哈希（十六进制字符串）
}

func (m SignInitMsg) Type() MessageType { return MessageTypeSignInit }
func (m SignInitMsg) Validate() error {
	if m.Address == "" {
		return fmt.Errorf("address required")
	}
	if m.Message == "" {
		return fmt.Errorf("message required")
	}
	return nil
}

// ------------------ SignStep1Msg ------------------
type SignStep1Msg struct {
	Address    string `json:"address"`
	Commitment string `json:"commitment"` // 来自 P1Context.Step1()
}

func (m SignStep1Msg) Type() MessageType { return MessageTypeSignStep1 }
func (m SignStep1Msg) Validate() error {
	if m.Address == "" {
		return fmt.Errorf("address required")
	}
	if m.Commitment == "" {
		return fmt.Errorf("commitment required")
	}
	return nil
}

// ------------------ SignStep2Msg ------------------
type SignStep2Msg struct {
	Address string              `json:"address"`
	CmtD    *commitment.Witness `json:"cmt_d"`
	P1Proof *schnorr.Proof      `json:"p1_proof"`
}

func (m SignStep2Msg) Type() MessageType { return MessageTypeSignStep2 }
func (m SignStep2Msg) Validate() error {
	if m.Address == "" {
		return fmt.Errorf("address required")
	}
	if m.CmtD == nil {
		return fmt.Errorf("cmtD required")
	}
	if m.P1Proof == nil {
		return fmt.Errorf("p1Proof required")
	}
	return nil
}

// Parse 将 MpcMessage 解析为具体的 MessageContent
func (m *MpcMessage) Parse() (MessageContent, error) {
	// 如果已经解析过，直接返回缓存的结果
	if m.ParsedContent != nil {
		return m.ParsedContent, nil
	}

	var content MessageContent
	var err error

	switch m.Type {
	case MessageTypeKeyGenStep1:
		var msg KeyGenStep1Msg
		err = json.Unmarshal(m.Content, &msg)
		content = msg
	case MessageTypeKeyGenStep2:
		var msg KeyGenStep2Msg
		err = json.Unmarshal(m.Content, &msg)
		content = msg
	case MessageTypeKeyGenVerifyBind:
		var msg KeyGenVerifyBindMsg
		err = json.Unmarshal(m.Content, &msg)
		content = msg
	case MessageTypeGetAddress:
		var msg GetAddressMsg
		err = json.Unmarshal(m.Content, &msg)
		content = msg
	case MessageTypeSignInit:
		var msg SignInitMsg
		err = json.Unmarshal(m.Content, &msg)
		content = msg
	case MessageTypeSignStep1:
		var msg SignStep1Msg
		err = json.Unmarshal(m.Content, &msg)
		content = msg
	case MessageTypeSignStep2:
		var msg SignStep2Msg
		err = json.Unmarshal(m.Content, &msg)
		content = msg
	default:
		return nil, fmt.Errorf("unknown message type: %s", m.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", m.Type, err)
	}

	// 缓存解析结果
	m.ParsedContent = content
	return content, nil
}
