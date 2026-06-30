package client

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	tsssign "github.com/okx/threshold-lib/tss/ecdsa/sign"
	"github.com/okx/threshold-lib/tss/key/dkg"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"hashnut-mpc-client/client/message"
	"hashnut-mpc-client/ctx/ecdsa_ctx"
	"hashnut-mpc-client/model"
	"hashnut-mpc-client/session"
	db_model "hashnut-mpc-client/storage/dal/model"
	"hashnut-mpc-client/util/ecdsa_util"
	"time"
)

type TssClient struct {
	db         *gorm.DB             // 缓存管理器
	sessionMgr *session.SessionMgr  // 会话管理器
	getPassword func() string       // 获取用户密码（用于加密 key_from_data）
}

func NewTssClient(gormDb *gorm.DB) *TssClient {
	return &TssClient{
		db:         gormDb,
		sessionMgr: session.NewSessionMgr(),
	}
}

// SetPasswordFunc 注入密码获取函数
func (ts *TssClient) SetPasswordFunc(fn func() string) {
	ts.getPassword = fn
}

func (ts *TssClient) GetKGCtx(sessionID int64) (*ecdsa_ctx.KGContext, bool) {
	return ts.sessionMgr.GetKGSession(sessionID)
}

func (ts *TssClient) setKGCtx(sessionID int64, kgCtx *ecdsa_ctx.KGContext) {
	ts.sessionMgr.SetKGSession(sessionID, kgCtx)
}

// ---------- KeyGen Step1 ----------
func (ts *TssClient) PrepareKGStep1(sessionID int64, chain string, splitter ...string) (*message.KeyGenStep1Msg, error) {
	kgCtx := &ecdsa_ctx.KGContext{
		SessionID: sessionID,
		Chain:     chain,
	}
	if len(splitter) > 0 {
		kgCtx.Splitter = splitter[0]
	}
	kgCtx.Setup = dkg.NewSetUp(1, 2, secp256k1.S256())
	step1Messages, err := kgCtx.Setup.DKGStep1()
	if err != nil {
		return nil, fmt.Errorf("p1 step1 failed: %w", err)
	}
	// 立即存入 session，后续 Handle 需要使用
	ts.sessionMgr.SetKGSession(sessionID, kgCtx)

	return &message.KeyGenStep1Msg{
		Message:  step1Messages[2],
		Splitter: kgCtx.Splitter,
	}, nil
}

func (ts *TssClient) HandleKGStep1Response(sessionID int64, mpcRespBody json.RawMessage) error {
	kgCtx, exists := ts.sessionMgr.GetKGSession(sessionID)
	if !exists {
		return fmt.Errorf("session not found: %d", sessionID)
	}
	fmt.Printf("keygen handle response from mpc server p2 %v \n", string(mpcRespBody))
	var mpcResp model.MpcRsp
	if err := json.Unmarshal(mpcRespBody, &mpcResp); err != nil {
		return fmt.Errorf("解析 MPC Server 响应失败: %w", err)
	}
	if mpcResp.Code != 0 {
		return fmt.Errorf("MPC Server 返回错误: %s", mpcResp.Msg)
	}

	fmt.Printf("keygen handle response from p2 %v", string(mpcResp.Data))
	var p2Msg tss.Message
	if err := json.Unmarshal(mpcResp.Data, &p2Msg); err != nil {
		return fmt.Errorf("failed to parse P2 response: %w", err)
	}
	kgCtx.Step1Msg = &p2Msg
	ts.sessionMgr.SetKGSession(sessionID, kgCtx)
	fmt.Printf("step1 completed. received p2 step1 message:\n%v\n", p2Msg)
	return nil
}

// ---------- KeyGen Step2 ----------
func (ts *TssClient) PrepareKGStep2(sessionID int64) (*message.KeyGenStep2Msg, error) {
	kgCtx, exists := ts.sessionMgr.GetKGSession(sessionID)
	if !exists {
		return nil, fmt.Errorf("session not found: %d", sessionID)
	}
	step2Messages, err := kgCtx.Setup.DKGStep2([]*tss.Message{kgCtx.Step1Msg})
	if err != nil {
		return nil, fmt.Errorf("p1 step2 dkg setup failed: %w", err)
	}
	return &message.KeyGenStep2Msg{
		Message: step2Messages[2],
	}, nil
}

// KGStep2RspData KGStep2 响应，包含 DKG 消息和从池中分配的 PreParams
type KGStep2RspData struct {
	Message   *tss.Message        `json:"message"`
	PreParams *keygen.PreParams   `json:"preParams"`
}

// HandleKGStep2Response 处理 P2 的 step2 响应，执行 DKGStep3 并生成 verifyBind 消息
func (ts *TssClient) HandleKGStep2Response(sessionID int64, mpcRspBody json.RawMessage) (*ecdsa_ctx.KGContext, *message.KeyGenVerifyBindMsg, error) {
	kgCtx, exists := ts.sessionMgr.GetKGSession(sessionID)
	if !exists {
		return nil, nil, fmt.Errorf("session not found: %d", sessionID)
	}

	fmt.Printf("keygen handle response from mpc server p2 %v\n", string(mpcRspBody))
	var mpcResp model.MpcRsp
	if err := json.Unmarshal(mpcRspBody, &mpcResp); err != nil {
		return nil, nil, fmt.Errorf("解析 MPC Server 响应失败: %w", err)
	}

	// 解析新的 KGStep2 响应格式（包含 message + preParams）
	var step2Rsp KGStep2RspData
	if err := json.Unmarshal(mpcResp.Data, &step2Rsp); err != nil {
		return nil, nil, fmt.Errorf("failed to parse p2 step2 response: %w", err)
	}
	if step2Rsp.Message == nil {
		return nil, nil, fmt.Errorf("p2 step2 response missing message")
	}
	if step2Rsp.PreParams == nil {
		return nil, nil, fmt.Errorf("p2 step2 response missing preParams")
	}

	kgCtx.Step2Msg = step2Rsp.Message

	step3Data, err := kgCtx.Setup.DKGStep3([]*tss.Message{step2Rsp.Message})
	if err != nil {
		return nil, nil, fmt.Errorf("p1 step3 dkg setup failed: %w", err)
	}
	kgCtx.Step3Data = step3Data

	// 使用从 Server 分配的 PreParams
	keyFrom := &ecdsa_ctx.ECDSAKeyFrom{}
	keyFrom.NewEcdsaKey(step2Rsp.PreParams)
	keyFrom.KeyStep3Data = step3Data
	kgCtx.KeyFrom = keyFrom

	// 构造验证绑定消息（包含 Paillier 密钥生成 + P1 ZKP 证明生成）
	t0 := time.Now()
	tssMsg, err := kgCtx.KeyFrom.KeyGenRequestMessage(2, step2Rsp.PreParams)
	fmt.Printf("client: KeyGenRequestMessage (paillier keygen + P1 proofs) took %v\n", time.Since(t0))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create verify bind message: %w", err)
	}
	verifyMsg := &message.KeyGenVerifyBindMsg{
		PublicKey: struct {
			X string `json:"X"`
			Y string `json:"Y"`
		}{
			X: kgCtx.Step3Data.PublicKey.X.String(),
			Y: kgCtx.Step3Data.PublicKey.Y.String(),
		},
		Chain:          kgCtx.Chain,
		ChainCode:      kgCtx.Step3Data.ChainCode,
		P1DataId:       1,
		P1PreSignParam: tssMsg,
	}
	return kgCtx, verifyMsg, nil
}

// ---------- KeyGen VerifyBind ----------
func (ts *TssClient) HandleKGVerifyBindResponse(sessionID int64, mpcRespBody json.RawMessage) (string, *ecdsa_ctx.ECDSAKeyFrom, error) {
	kgCtx, exists := ts.sessionMgr.GetKGSession(sessionID)
	if !exists {
		return "", nil, fmt.Errorf("session not found: %d", sessionID)
	}
	var mpcResp model.MpcRsp
	if err := json.Unmarshal(mpcRespBody, &mpcResp); err != nil {
		return "", nil, fmt.Errorf("解析 MPC Server 响应失败: %w", err)
	}
	var result model.KGVerifyBindRsp
	if err := json.Unmarshal(mpcResp.Data, &result); err != nil {
		return "", nil, fmt.Errorf("failed to parse verification result: %w", err)
	}
	fmt.Printf("kg verify bind response %v\n", result)
	if !result.Verified {
		return "", nil, fmt.Errorf("keygen final verify failed: public key or chaincode mismatch")
	}
	kgCtx.KGResult = &result
	ts.sessionMgr.SetKGSession(sessionID, kgCtx)

	return result.Address, kgCtx.KeyFrom, nil
}

// ---------- GetAddress ----------
func (ts *TssClient) PrepareGetAddress(address string) (*message.GetAddressMsg, error) {
	return &message.GetAddressMsg{
		Address: address,
	}, nil
}

func (ts *TssClient) HandleGetAddressResponse(mpcRespBody json.RawMessage) (*ecdsa.PublicKey, error) {

	var mpcResp model.MpcRsp
	if err := json.Unmarshal(mpcRespBody, &mpcResp); err != nil {
		return nil, fmt.Errorf("parse MPC response failed: %w", err)
	}
	var rsp model.KGGetAddressRsp
	if err := json.Unmarshal(mpcResp.Data, &rsp); err != nil {
		return nil, fmt.Errorf("parse get-address response failed: %w", err)
	}
	pubKey, err := ecdsa_util.HexToECDSAPubKey(rsp.PubKey)
	if err != nil {
		return nil, fmt.Errorf("decode public key failed: %w", err)
	}
	return pubKey, nil
}

func (ts *TssClient) GetSignCtx(sessionID int64) (*ecdsa_ctx.SignContext, bool) {
	return ts.sessionMgr.GetSignSession(sessionID)
}

func (ts *TssClient) setSignCtx(sessionID int64, signCtx *ecdsa_ctx.SignContext) {
	ts.sessionMgr.SetSignSession(sessionID, signCtx)
}

// ---------- SignInit ----------
// PrepareSignInit 准备签名初始化消息，创建会话并返回请求内容
func (ts *TssClient) PrepareSignInit(sessionID int64, chain, address, messageHash string) (*message.SignInitMsg, error) {
	// 1. 从数据库获取密钥分片和公钥
	fromKey, exist, err := ts.GetKeyFrom(address)
	if err != nil {
		return nil, fmt.Errorf("load key from error: %w", err)
	}
	if !exist || fromKey == nil {
		return nil, fmt.Errorf("key from not found for address: %s", address)
	}

	pubKey, exists, err := ts.GetPubKey(address)
	if err != nil {
		return nil, fmt.Errorf("load public key error: %w", err)
	}
	if !exists || pubKey == nil {
		return nil, fmt.Errorf("public key not found for address: %s", address)
	}

	// 2. 创建 P1 上下文
	p1Ctx := tsssign.NewP1(pubKey, messageHash, fromKey.PaillierPrivateKey)
	signCtx := &ecdsa_ctx.SignContext{
		SessionID: sessionID,
		Chain:     chain,
		Address:   address,
		Message:   messageHash,
		P1Context: p1Ctx,
		PubKey:    pubKey,
		KeyFrom:   fromKey,
	}

	// 3. 存入会话管理器
	ts.sessionMgr.SetSignSession(sessionID, signCtx)

	return &message.SignInitMsg{
		Address: address,
		Message: messageHash,
	}, nil
}

// HandleSignInitResponse 处理 MPC Server 对 SignInit 的响应
func (ts *TssClient) HandleSignInitResponse(sessionID int64, mpcRespBody json.RawMessage) error {
	var mpcResp model.MpcRsp
	if err := json.Unmarshal(mpcRespBody, &mpcResp); err != nil {
		return fmt.Errorf("parse MPC response failed: %w", err)
	}
	if mpcResp.Code != 0 {
		return fmt.Errorf("MPC error: %s", mpcResp.Msg)
	}
	// 此处无额外数据需要处理，只需确认成功
	return nil
}

// ---------- SignStep1 ----------
// PrepareSignStep1 准备 step1 消息
func (ts *TssClient) PrepareSignStep1(sessionID int64) (*message.SignStep1Msg, error) {
	signCtx, exists := ts.sessionMgr.GetSignSession(sessionID)
	if !exists {
		return nil, fmt.Errorf("sign session not found: %d", sessionID)
	}
	step1, err := signCtx.P1Context.Step1()
	if err != nil {
		return nil, fmt.Errorf("p1 step1 failed: %w", err)
	}
	return &message.SignStep1Msg{
		Address:    signCtx.Address,
		Commitment: (*step1).String(),
	}, nil
}

// HandleSignStep1Response 处理 MPC Server 对 step1 的响应
func (ts *TssClient) HandleSignStep1Response(sessionID int64, mpcRespBody json.RawMessage) error {
	// 1. 解析外层 MPC 响应
	var mpcResp model.MpcRsp
	if err := json.Unmarshal(mpcRespBody, &mpcResp); err != nil {
		return fmt.Errorf("parse MPC response failed: %w", err)
	}
	if mpcResp.Code != 0 {
		return fmt.Errorf("MPC error: %s", mpcResp.Msg)
	}

	// 2. 解析内层数据为 SignStep1Rsp
	var step1Resp model.SignStep1Rsp
	if err := json.Unmarshal(mpcResp.Data, &step1Resp); err != nil {
		return fmt.Errorf("parse step1 response data failed: %w", err)
	}

	// 3. 更新会话
	signCtx, exists := ts.sessionMgr.GetSignSession(sessionID)
	if !exists {
		return fmt.Errorf("sign session not found: %d", sessionID)
	}
	signCtx.Step1Msg = &step1Resp
	ts.sessionMgr.SetSignSession(sessionID, signCtx)
	return nil
}

// ---------- SignStep2 ----------
// PrepareSignStep2 准备 step2 消息
func (ts *TssClient) PrepareSignStep2(sessionID int64) (*message.SignStep2Msg, error) {
	signCtx, exists := ts.sessionMgr.GetSignSession(sessionID)
	if !exists {
		return nil, fmt.Errorf("sign session not found: %d", sessionID)
	}
	if signCtx.Step1Msg == nil {
		return nil, fmt.Errorf("step1 response not received")
	}

	schnorrProofOutput, witness, err := signCtx.P1Context.Step2(
		signCtx.Step1Msg.Proof,
		signCtx.Step1Msg.ECPoint,
	)
	if err != nil {
		return nil, fmt.Errorf("p1 step2 failed: %w", err)
	}

	return &message.SignStep2Msg{
		Address: signCtx.Address,
		CmtD:    witness,
		P1Proof: schnorrProofOutput,
	}, nil
}

// HandleSignStep2Response 处理 MPC Server 对 step2 的响应，生成最终签名
func (ts *TssClient) HandleSignStep2Response(sessionID int64, mpcRespBody json.RawMessage) error {
	// 1. 解析外层 MPC 响应
	var mpcResp model.MpcRsp
	if err := json.Unmarshal(mpcRespBody, &mpcResp); err != nil {
		return fmt.Errorf("parse MPC response failed: %w", err)
	}
	if mpcResp.Code != 0 {
		return fmt.Errorf("MPC error: %s", mpcResp.Msg)
	}

	// 2. 解析内层数据为 SignStep2Rsp
	var step2Resp model.SignStep2Rsp
	if err := json.Unmarshal(mpcResp.Data, &step2Resp); err != nil {
		return fmt.Errorf("parse step2 response data failed: %w", err)
	}

	// 3. 更新会话并生成签名
	signCtx, exists := ts.sessionMgr.GetSignSession(sessionID)
	if !exists {
		return fmt.Errorf("sign session not found: %d", sessionID)
	}
	signCtx.Step2Msg = &step2Resp
	ts.sessionMgr.SetSignSession(sessionID, signCtx)

	// 4. Step3: 计算 (r, s)
	r, s, err := signCtx.P1Context.Step3(ecdsa_util.Str2BigInt(step2Resp.E_k2_h_xr))
	if err != nil {
		return fmt.Errorf("p1 step3 failed: %w", err)
	}

	// 5. 生成标准以太坊签名
	signHex, v, err := ecdsa_util.GetSignByRS(
		signCtx.PubKey,
		common.HexToHash(signCtx.Message),
		r,
		s,
	)
	if err != nil {
		return fmt.Errorf("generate signature failed: %w", err)
	}

	signCtx.Step3Data = &model.SignStep3Result{
		R:    *r,
		S:    *s,
		V:    v,
		Sign: signHex,
	}
	ts.sessionMgr.SetSignSession(sessionID, signCtx)

	return nil
}

// SetKeyFrom 保存收款地址的完整密钥分片数据（自动提交事务）
func (ts *TssClient) SetKeyFrom(receiptAddress, splitterAddress string, keyFrom *ecdsa_ctx.ECDSAKeyFrom) error {
	// 开始事务
	tx := ts.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 1. 校验 split_wallet 并获取 chain 和 merchant 信息
	var splitWallet db_model.SplitWallet
	err := tx.Where("address = ?", splitterAddress).First(&splitWallet).Error
	if err != nil {
		tx.Rollback()
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("split wallet %s not found", splitterAddress)
		}
		return fmt.Errorf("query split wallet: %w", err)
	}
	chain := splitWallet.Chain
	// merchant 字段存储商户钱包地址，后面可能用不到，但原代码中查询了 merchant_address，此处保留

	// 序列化 keyFrom → 加密
	keyFromBlob, err := ts.encryptKeyFrom(keyFrom)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("encrypt ecdsa key from error: %w", err)
	}

	// 2. 插入或替换 receipt_address 记录
	receipt := &db_model.ReceiptAddress{
		Address:     receiptAddress,
		Splitter:    splitterAddress,
		Chain:       chain,
		Curve:       "secp256k1",
		KeyFromData: keyFromBlob,
		UpdatedAt:   time.Now(),
	}

	err = tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "address"}},
		DoUpdates: clause.AssignmentColumns([]string{"splitter", "chain", "curve", "key_from_data", "updated_at"}),
	}).Create(receipt).Error
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("insert receipt address: %w", err)
	}

	return tx.Commit().Error
}

// SetManagerKeyFrom 保存 splitWalletManager 的 MPC key 到 split_wallet_manager 表
func (ts *TssClient) SetManagerKeyFrom(managerAddress, splitter, chain, merchant string, keyFrom *ecdsa_ctx.ECDSAKeyFrom) error {
	keyFromBlob, err := ts.encryptKeyFrom(keyFrom)
	if err != nil {
		return fmt.Errorf("encrypt ecdsa key from error: %w", err)
	}

	mgr := &db_model.SplitWalletManager{
		Splitter:       splitter,
		Chain:          chain,
		Merchant:       merchant,
		ManagerAddress: managerAddress,
		KeyFromData:    keyFromBlob,
	}

	return ts.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "splitter"}},
		DoUpdates: clause.AssignmentColumns([]string{"manager_address", "key_from_data"}),
	}).Create(mgr).Error
}

// GetKeyFrom 获取地址的完整密钥分片数据（先查 receipt_address，再查 receipt_wallet_manager）
func (ts *TssClient) GetKeyFrom(address string) (*ecdsa_ctx.ECDSAKeyFrom, bool, error) {
	// 1. 先查 receipt_address 表
	var receipt db_model.ReceiptAddress
	err := ts.db.Where("address = ?", address).First(&receipt).Error
	if err == nil {
		keyFrom, err := ts.decryptKeyFrom(receipt.KeyFromData)
		if err != nil {
			return nil, false, fmt.Errorf("decrypt from key error: %w", err)
		}
		return keyFrom, true, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, fmt.Errorf("query receipt address: %w", err)
	}

	// 2. fallback 查 split_wallet_manager 表
	var mgr db_model.SplitWalletManager
	err = ts.db.Where("manager_address = ?", address).First(&mgr).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("query split wallet manager: %w", err)
	}
	if len(mgr.KeyFromData) == 0 {
		return nil, false, nil
	}
	keyFrom, err := ts.decryptKeyFrom(mgr.KeyFromData)
	if err != nil {
		return nil, false, fmt.Errorf("decrypt manager key from error: %w", err)
	}
	return keyFrom, true, nil
}

// SetPubKey 保存收款地址的公钥（独立事务）
func (ts *TssClient) SetPubKey(receiptAddress, splitterAddress string, pubKey *ecdsa.PublicKey) error {
	// 序列化公钥
	pubKeyBlob, err := serializePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("serialize pub key error: %w", err)
	}

	// 开始事务
	tx := ts.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 更新 pub_key_data 字段
	result := tx.Model(&db_model.ReceiptAddress{}).
		Where("address = ? AND splitter = ?", receiptAddress, splitterAddress).
		Update("pub_key_data", pubKeyBlob)
	if result.Error != nil {
		tx.Rollback()
		return fmt.Errorf("update pubkey: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		tx.Rollback()
		return fmt.Errorf("receipt address not found: %s", receiptAddress)
	}

	return tx.Commit().Error
}

// GetPubKey 获取地址的公钥（先查 receipt_address，再查 receipt_wallet_manager）
func (ts *TssClient) GetPubKey(address string) (*ecdsa.PublicKey, bool, error) {
	// 1. 先查 receipt_address 表
	var receipt db_model.ReceiptAddress
	err := ts.db.Select("pub_key_data").
		Where("address = ?", address).
		First(&receipt).Error
	if err == nil {
		if len(receipt.PubKeyData) == 0 {
			return nil, false, nil
		}
		fmt.Printf("load pub key blob from database %s\n", string(receipt.PubKeyData))
		pubKey, err := deserializePublicKey(receipt.PubKeyData)
		if err != nil {
			return nil, false, fmt.Errorf("deserialize pubkey: %w", err)
		}
		return pubKey, true, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, fmt.Errorf("query pubkey: %w", err)
	}

	// 2. fallback 查 split_wallet_manager 表
	var mgr db_model.SplitWalletManager
	err = ts.db.Select("pub_key_data").
		Where("manager_address = ?", address).
		First(&mgr).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("query manager pubkey: %w", err)
	}
	if len(mgr.PubKeyData) == 0 {
		return nil, false, nil
	}
	fmt.Printf("load manager pub key blob from database %s\n", string(mgr.PubKeyData))
	pubKey, err := deserializePublicKey(mgr.PubKeyData)
	if err != nil {
		return nil, false, fmt.Errorf("deserialize manager pubkey: %w", err)
	}
	return pubKey, true, nil
}

// SetManagerPubKey 保存 manager 地址的公钥
func (ts *TssClient) SetManagerPubKey(managerAddress string, pubKey *ecdsa.PublicKey) error {
	pubKeyBlob, err := serializePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("serialize pub key error: %w", err)
	}
	return ts.db.Model(&db_model.SplitWalletManager{}).
		Where("manager_address = ?", managerAddress).
		Update("pub_key_data", pubKeyBlob).Error
}

// encryptKeyFrom 序列化 ECDSAKeyFrom，仅加密私密字段（ShareI + Paillier 私钥）
func (ts *TssClient) encryptKeyFrom(keyFrom *ecdsa_ctx.ECDSAKeyFrom) ([]byte, error) {
	password := ts.getPassword()
	return serializeECDSAKeyFromEncrypted(keyFrom, password)
}

// decryptKeyFrom 反序列化 ECDSAKeyFrom，解密私密字段
func (ts *TssClient) decryptKeyFrom(cipherBlob []byte) (*ecdsa_ctx.ECDSAKeyFrom, error) {
	password := ts.getPassword()
	return deserializeECDSAKeyFromEncrypted(cipherBlob, password)
}

