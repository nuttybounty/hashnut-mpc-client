package client

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"hashnut-mpc-client/ctx/ecdsa_ctx"
	db_model "hashnut-mpc-client/storage/dal/model"
	"strconv"
	"time"

	"gorm.io/gorm"
)

// GetLocalSplitWalletManager 从本地 SQLite 获取指定 splitter 的 manager 地址
func (mc *MerchantClient) GetLocalSplitWalletManager(splitter string) (string, error) {
	var mgr db_model.SplitWalletManager
	err := mc.storageMgr.GetDB().Where("splitter = ?", splitter).First(&mgr).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", err
	}
	return mgr.ManagerAddress, nil
}

// ManagerKeygen 为指定 split wallet 执行 MPC keygen，生成 splitWalletManager 地址
func (mc *MerchantClient) ManagerKeygen(ctx context.Context, chain, splitter string) (string, error) {
	sessionID := time.Now().UnixNano()

	// Step1
	msg1, err := mc.tssCli.PrepareKGStep1(sessionID, chain, splitter)
	if err != nil {
		return "", fmt.Errorf("manager keygen step1 prepare failed: %w", err)
	}
	sid := strconv.FormatInt(sessionID, 10)
	data1, err := mc.doSignedRequest(ctx, "/api/v4.0.0/mpc/activate/keygen", "/kg/step1", msg1, sid, chain, splitter)
	if err != nil {
		return "", fmt.Errorf("manager keygen step1 request failed: %w", err)
	}
	if err := mc.tssCli.HandleKGStep1Response(sessionID, data1); err != nil {
		return "", fmt.Errorf("manager keygen step1 handle failed: %w", err)
	}

	// Step2
	msg2, err := mc.tssCli.PrepareKGStep2(sessionID)
	if err != nil {
		return "", fmt.Errorf("manager keygen step2 prepare failed: %w", err)
	}
	data2, err := mc.doSignedRequest(ctx, "/api/v4.0.0/mpc/activate/keygen", "/kg/step2", msg2, sid, chain, splitter)
	if err != nil {
		return "", fmt.Errorf("manager keygen step2 request failed: %w", err)
	}
	_, verifyMsg, err := mc.tssCli.HandleKGStep2Response(sessionID, data2)
	if err != nil {
		return "", fmt.Errorf("manager keygen step2 handle failed: %w", err)
	}

	// VerifyBind
	verifyData, err := mc.doSignedRequest(ctx, "/api/v4.0.0/mpc/activate/keygen", "/kg/verify-bind", verifyMsg, sid, chain, splitter)
	if err != nil {
		return "", fmt.Errorf("manager keygen verify-bind request failed: %w", err)
	}
	resultAddress, keyFrom, err := mc.tssCli.HandleKGVerifyBindResponse(sessionID, verifyData)
	if err != nil {
		return "", fmt.Errorf("manager keygen verify-bind handle failed: %w", err)
	}

	// 持久化 KeyFrom 到 split_wallet_manager 表
	walletCtx := mc.walletMgr.GetWalletCtx()
	if err := mc.tssCli.SetManagerKeyFrom(resultAddress, splitter, chain, walletCtx.Address, keyFrom); err != nil {
		return "", fmt.Errorf("manager keygen persist key failed: %w", err)
	}

	// 从 MPC Server 获取公钥并保存到 manager 表
	msg, err := mc.tssCli.PrepareGetAddress(resultAddress)
	if err != nil {
		return "", fmt.Errorf("manager get-address prepare failed: %w", err)
	}
	addrData, err := mc.doSignedRequest(ctx, "/api/v4.0.0/mpc/activate/keygen", "/kg/get-address", msg, "", chain, "")
	if err != nil {
		return "", fmt.Errorf("manager get-address request failed: %w", err)
	}
	pubKey, err := mc.tssCli.HandleGetAddressResponse(addrData)
	if err != nil {
		return "", fmt.Errorf("manager get-address handle failed: %w", err)
	}
	if err := mc.tssCli.SetManagerPubKey(resultAddress, pubKey); err != nil {
		return "", fmt.Errorf("manager save pubkey failed: %w", err)
	}

	return resultAddress, nil
}

// EnsureSplitWalletManager 检查指定 splitter 的 manager 是否存在，不存在则创建
func (mc *MerchantClient) EnsureSplitWalletManager(ctx context.Context, splitter string) error {
	splitWallet, err := mc.splitMgr.GetSplit(splitter)
	if err != nil {
		return fmt.Errorf("查询 split wallet 失败: %w", err)
	}
	if splitWallet == nil {
		return fmt.Errorf("split wallet %s 不存在，请先通过 splitter fetch <chain> 同步", splitter)
	}
	chain := splitWallet.Chain

	localManager, err := mc.GetLocalSplitWalletManager(splitter)
	if err != nil {
		return fmt.Errorf("查询本地 manager 失败: %w", err)
	}
	if localManager != "" {
		fmt.Printf("Split Wallet Manager 已存在: %s\n", localManager)
		return nil
	}

	remoteManager, err := mc.QuerySplitWalletManager(ctx, chain, splitter)
	if err != nil {
		return fmt.Errorf("查询远端 manager 失败: %w", err)
	}
	if remoteManager != "" {
		fmt.Printf("Split Wallet Manager 已在服务端存在: %s，但本地无密钥分片，需要重新生成\n", remoteManager)
	}

	fmt.Printf("正在通过 MPC keygen 为 split wallet %s 生成 Split Wallet Manager...\n", splitter)
	managerAddress, err := mc.ManagerKeygen(ctx, chain, splitter)
	if err != nil {
		return fmt.Errorf("生成 manager 地址失败: %w", err)
	}

	if err := mc.RegisterSplitWalletManager(ctx, chain, splitter, managerAddress); err != nil {
		return fmt.Errorf("注册 manager 到服务端失败: %w", err)
	}

	mc.storageMgr.GetDB().Model(splitWallet).Update("split_wallet_manager", managerAddress)

	fmt.Printf("Split Wallet Manager 生成成功: %s\n", managerAddress)
	return nil
}

func (mc *MerchantClient) GetKGCtx(sessionID int64) (*ecdsa_ctx.KGContext, bool) {
	return mc.tssCli.GetKGCtx(sessionID)
}

func (mc *MerchantClient) setKGCtx(sessionID int64, kgCtx *ecdsa_ctx.KGContext) {
	mc.tssCli.setKGCtx(sessionID, kgCtx)
}

// KeygenStep1 执行密钥生成第一步
func (mc *MerchantClient) KeygenStep1(ctx context.Context, sessionID int64, splitWalletAddress string) error {
	splitWallet, err := mc.splitMgr.GetSplit(splitWalletAddress)
	if err != nil {
		return fmt.Errorf("查看split wallet信息错误: %v", err)
	}
	if splitWallet == nil {
		return errors.New("无法找到split wallet信息")
	}

	msg, err := mc.tssCli.PrepareKGStep1(sessionID, splitWallet.Chain, splitWallet.Address)
	if err != nil {
		return err
	}
	sid := strconv.FormatInt(sessionID, 10)
	data, err := mc.doSignedRequest(ctx, "/api/v4.0.0/mpc/receipt/keygen", "/kg/step1", msg, sid, splitWallet.Chain, splitWallet.Address)
	if err != nil {
		return err
	}
	return mc.tssCli.HandleKGStep1Response(sessionID, data)
}

// KeygenStep2 执行密钥生成第二步，并自动完成验证绑定
func (mc *MerchantClient) KeygenStep2(ctx context.Context, sessionID int64, splitWallet string) error {
	kgCtx, exist := mc.tssCli.GetKGCtx(sessionID)
	if !exist {
		return fmt.Errorf("无法根据会话Id: %d 找到keygen上下文", sessionID)
	}
	msg, err := mc.tssCli.PrepareKGStep2(sessionID)
	if err != nil {
		return err
	}

	sid := strconv.FormatInt(sessionID, 10)
	data, err := mc.doSignedRequest(ctx, "/api/v4.0.0/mpc/receipt/keygen", "/kg/step2", msg, sid, kgCtx.Chain, splitWallet)
	if err != nil {
		return err
	}

	_, verifyMsg, err := mc.tssCli.HandleKGStep2Response(sessionID, data)
	if err != nil {
		return err
	}

	verifyData, err := mc.doSignedRequest(ctx, "/api/v4.0.0/mpc/receipt/keygen", "/kg/verify-bind", verifyMsg, sid, kgCtx.Chain, splitWallet)
	if err != nil {
		return err
	}

	resultAddress, keyFrom, err := mc.tssCli.HandleKGVerifyBindResponse(sessionID, verifyData)
	if err != nil {
		return err
	}

	if err := mc.tssCli.SetKeyFrom(resultAddress, splitWallet, keyFrom); err != nil {
		return err
	}
	return nil
}

// GetAddress 获取地址公钥并保存
func (mc *MerchantClient) GetAddress(ctx context.Context, chain, receiptAddress, splitWalletAddress string) error {
	msg, err := mc.tssCli.PrepareGetAddress(receiptAddress)
	if err != nil {
		return err
	}
	data, err := mc.doSignedRequest(ctx, "/api/v4.0.0/mpc/receipt/keygen", "/kg/get-address", msg, "", chain, "")
	if err != nil {
		return err
	}
	pubKey, err := mc.tssCli.HandleGetAddressResponse(data)
	if err := mc.tssCli.SetPubKey(receiptAddress, splitWalletAddress, pubKey); err != nil {
		return fmt.Errorf("save public key failed: %w", err)
	}
	return nil
}

func (mc *MerchantClient) GetGeneratedAddr(address string) (*ecdsa.PublicKey, *ecdsa_ctx.ECDSAKeyFrom, bool, error) {
	pubKey, exist, err := mc.tssCli.GetPubKey(address)
	if err != nil || !exist {
		return nil, nil, false, err
	}
	fromKey, exist, err := mc.tssCli.GetKeyFrom(address)
	if err != nil || !exist {
		return nil, nil, false, err
	}
	return pubKey, fromKey, true, nil
}
