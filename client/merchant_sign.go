package client

import (
	"context"
	"errors"
	"fmt"
	"hashnut-mpc-client/ctx/ecdsa_ctx"
	"strconv"
)

func (mc *MerchantClient) GetSignCtx(sessionID int64) (*ecdsa_ctx.SignContext, bool) {
	return mc.tssCli.GetSignCtx(sessionID)
}

// SignInit 签名初始化（带 split wallet 查链信息）
// endpoint: 业务端点路径，如 "/api/v4.0.0/mpc/receipt/sign/approve"
// txInfo: init 阶段传 rawTx 信息供 Guard 校验，step1/step2 传 nil
func (mc *MerchantClient) SignInit(ctx context.Context, sessionID int64, receipt, split, messageHash, endpoint string, txInfo *SignTxInfo) error {
	splitWallet, err := mc.splitMgr.GetSplit(split)
	if err != nil {
		return fmt.Errorf("查看split wallet信息错误: %v", err)
	}
	if splitWallet == nil {
		return errors.New("无法找到split wallet信息")
	}

	msg, err := mc.tssCli.PrepareSignInit(sessionID, splitWallet.Chain, receipt, messageHash)
	if err != nil {
		return err
	}
	sid := strconv.FormatInt(sessionID, 10)
	data, err := mc.doSignedRequestWithTx(ctx, endpoint, "/sign/init-ctx", msg, sid, splitWallet.Chain, split, txInfo)
	if err != nil {
		return err
	}
	return mc.tssCli.HandleSignInitResponse(sessionID, data)
}

// SignStep1 签名第一步
func (mc *MerchantClient) SignStep1(ctx context.Context, sessionID int64, split, endpoint string) error {
	signCtx, exist := mc.tssCli.GetSignCtx(sessionID)
	if !exist {
		return fmt.Errorf("无法根据会话Id: %d 找到sign上下文", sessionID)
	}
	msg, err := mc.tssCli.PrepareSignStep1(sessionID)
	if err != nil {
		return err
	}
	sid := strconv.FormatInt(sessionID, 10)
	data, err := mc.doSignedRequest(ctx, endpoint, "/sign/p2-step1", msg, sid, signCtx.Chain, split)
	if err != nil {
		return err
	}
	return mc.tssCli.HandleSignStep1Response(sessionID, data)
}

// SignStep2 签名第二步，完成后签名结果存入 session
func (mc *MerchantClient) SignStep2(ctx context.Context, sessionID int64, splitWallet, endpoint string) error {
	signCtx, exist := mc.tssCli.GetSignCtx(sessionID)
	if !exist {
		return fmt.Errorf("无法根据会话Id: %d 找到sign上下文", sessionID)
	}
	msg, err := mc.tssCli.PrepareSignStep2(sessionID)
	if err != nil {
		return err
	}
	sid := strconv.FormatInt(sessionID, 10)
	data, err := mc.doSignedRequest(ctx, endpoint, "/sign/p2-step2", msg, sid, signCtx.Chain, splitWallet)
	if err != nil {
		return err
	}
	return mc.tssCli.HandleSignStep2Response(sessionID, data)
}

// SignInitWithChain 不绑定 split wallet 的签名初始化（用于 sweep、manager addReceiptWallets 等）
func (mc *MerchantClient) SignInitWithChain(ctx context.Context, sessionID int64, receipt, messageHash, chain, splitter, endpoint string, txInfo *SignTxInfo) error {
	msg, err := mc.tssCli.PrepareSignInit(sessionID, chain, receipt, messageHash)
	if err != nil {
		return err
	}
	sid := strconv.FormatInt(sessionID, 10)
	data, err := mc.doSignedRequestWithTx(ctx, endpoint, "/sign/init-ctx", msg, sid, chain, splitter, txInfo)
	if err != nil {
		return err
	}
	return mc.tssCli.HandleSignInitResponse(sessionID, data)
}

// SignStep1WithChain 不绑定 split wallet 的签名第一步
func (mc *MerchantClient) SignStep1WithChain(ctx context.Context, sessionID int64, chain, splitter, endpoint string) error {
	signCtx, exist := mc.tssCli.GetSignCtx(sessionID)
	if !exist {
		return fmt.Errorf("无法根据会话Id: %d 找到sign上下文", sessionID)
	}
	msg, err := mc.tssCli.PrepareSignStep1(sessionID)
	if err != nil {
		return err
	}
	sid := strconv.FormatInt(sessionID, 10)
	data, err := mc.doSignedRequest(ctx, endpoint, "/sign/p2-step1", msg, sid, signCtx.Chain, splitter)
	if err != nil {
		return err
	}
	return mc.tssCli.HandleSignStep1Response(sessionID, data)
}

// SignStep2WithChain 不绑定 split wallet 的签名第二步
func (mc *MerchantClient) SignStep2WithChain(ctx context.Context, sessionID int64, chain, splitter, endpoint string) error {
	signCtx, exist := mc.tssCli.GetSignCtx(sessionID)
	if !exist {
		return fmt.Errorf("无法根据会话Id: %d 找到sign上下文", sessionID)
	}
	msg, err := mc.tssCli.PrepareSignStep2(sessionID)
	if err != nil {
		return err
	}
	sid := strconv.FormatInt(sessionID, 10)
	data, err := mc.doSignedRequest(ctx, endpoint, "/sign/p2-step2", msg, sid, signCtx.Chain, splitter)
	if err != nil {
		return err
	}
	return mc.tssCli.HandleSignStep2Response(sessionID, data)
}
