package client

import (
	"context"
	"encoding/json"
	"fmt"
	"hashnut-mpc-client/model"
	"strings"
	"time"
)

// CoinInfoItem 后端返回的 token 信息
type CoinInfoItem struct {
	Chain           string      `json:"chain"`
	ChainCode       string      `json:"chainCode"`
	CoinCode        string      `json:"coinCode"`
	ContractAddress string      `json:"contractAddress"`
	CoinDesc        string      `json:"coinDesc"`
	Decimals        json.Number `json:"decimals"`
}

// FetchSplitWallets 从 proxy 获取当前商户在指定链上已部署完成的分账合约，并同步到本地数据库
func (mc *MerchantClient) FetchSplitWallets(ctx context.Context, chain string) error {
	data, err := mc.doSignedRequest(ctx, "/api/v4.0.0/mpc/fetchSplitWallets", "fetchSplitWallets", nil, "", chain, "")
	if err != nil {
		return fmt.Errorf("获取分账合约列表失败: %w", err)
	}

	var records []model.SplitWalletDeployDetail
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("解析分账合约列表失败: %w", err)
	}

	walletCtx := mc.walletMgr.GetWalletCtx()
	synced, err := mc.splitMgr.SyncSplitWallets(records, walletCtx.Address)
	if err != nil {
		return fmt.Errorf("同步分账合约到本地数据库失败: %w", err)
	}

	fmt.Printf("从服务端获取到 %d 个分账合约，新同步 %d 个\n", len(records), synced)
	return nil
}

func (mc *MerchantClient) RegisterReceiptWalletGenerated(ctx context.Context, chain, splitterAddress, receiptAddress string) error {
	_, err := mc.doSignedJSONRequest(ctx, "/api/v4.0.0/mpc/receipt/generated", map[string]interface{}{
		"chain":           chain,
		"splitterAddress": splitterAddress,
		"receiptAddress":  receiptAddress,
	})
	return err
}

func (mc *MerchantClient) NotifyReceiptApproveBroadcast(ctx context.Context, chain, splitterAddress, receiptAddress, tokenAddress, approveAmount, approveTxId string) error {
	_, err := mc.doSignedJSONRequest(ctx, "/api/v4.0.0/mpc/receipt/approve/broadcast", map[string]interface{}{
		"chain":           chain,
		"splitterAddress": splitterAddress,
		"receiptAddress":  receiptAddress,
		"tokenAddress":    tokenAddress,
		"approveAmount":   approveAmount,
		"approveTxId":     approveTxId,
	})
	return err
}

// SubmitApprove 批量报告 approve 交易已广播: GENERATED → APPROVE_BROADCAST
func (mc *MerchantClient) SubmitApprove(ctx context.Context, chain, splitterAddress string,
	walletAddresses, approveTxIds []string, tokenAddress, approveAmount string) error {
	_, err := mc.doSignedJSONRequest(ctx, "/api/v4.0.0/mpc/receipt/approve/commit", map[string]interface{}{
		"chain":           chain,
		"splitterAddress": splitterAddress,
		"walletAddresses": walletAddresses,
		"approveTxIds":    approveTxIds,
		"tokenAddress":    tokenAddress,
		"approveAmount":   approveAmount,
	})
	return err
}

// SubmitAddReceiptWallets 报告 addReceiptWallets 交易已广播: APPROVED → ADDING
func (mc *MerchantClient) SubmitAddReceiptWallets(ctx context.Context, chain, splitterAddress string,
	walletAddresses []string, addTxId string) error {
	_, err := mc.doSignedJSONRequest(ctx, "/api/v4.0.0/mpc/receipt/add/commit", map[string]interface{}{
		"chain":           chain,
		"splitterAddress": splitterAddress,
		"walletAddresses": walletAddresses,
		"addTxId":         addTxId,
	})
	return err
}

// QueryCoinInfo 从后端查询指定链支持的 token 列表
func (mc *MerchantClient) QueryCoinInfo(ctx context.Context, chain string) ([]CoinInfoItem, error) {
	data, err := mc.doPostJSON(ctx, "/api/v4.0.0/config/coins/query", map[string]interface{}{
		"chain": chain,
	})
	if err != nil {
		return nil, err
	}
	var items []CoinInfoItem
	if len(data) == 0 || string(data) == "null" {
		return items, nil
	}
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("解析 coinInfo 响应失败 (data=%s): %w", string(data), err)
	}
	return items, nil
}

// PollReceiptState 轮询指定收款地址，等待全部达到目标状态
func (mc *MerchantClient) PollReceiptState(ctx context.Context, chain, splitterAddress string,
	walletAddresses []string, targetState int, timeout time.Duration) error {
	walletsParam := strings.Join(walletAddresses, ",")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := mc.doGetRequest(ctx, fmt.Sprintf(
			"/api/v4.0.0/mpc/receipt/state?chain=%s&splitterAddress=%s&wallets=%s&state=%d",
			chain, splitterAddress, walletsParam, targetState))
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		var result struct {
			Ready bool `json:"ready"`
		}
		if err := json.Unmarshal(data, &result); err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		if result.Ready {
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("等待状态 %d 超时 (%v)", targetState, timeout)
}

// QuerySplitWalletManager 从 hashnut-payment 查询指定 splitter 的 splitWalletManager
func (mc *MerchantClient) QuerySplitWalletManager(ctx context.Context, chain, splitter string) (string, error) {
	data, err := mc.doSignedJSONRequest(ctx, "/api/v4.0.0/mpc/manager/query", map[string]interface{}{
		"chain":           chain,
		"splitterAddress": splitter,
	})
	if err != nil {
		return "", err
	}
	var result struct {
		ManagerAddress string `json:"managerAddress"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("解析 manager query 响应失败: %w", err)
	}
	return result.ManagerAddress, nil
}

// RegisterSplitWalletManager 向 hashnut-payment 注册 keygen 生成的 splitWalletManager
func (mc *MerchantClient) RegisterSplitWalletManager(ctx context.Context, chain, splitter, managerAddress string) error {
	_, err := mc.doSignedJSONRequest(ctx, "/api/v4.0.0/mpc/manager/generated", map[string]interface{}{
		"chain":           chain,
		"splitterAddress": splitter,
		"managerAddress":  managerAddress,
	})
	return err
}

func (mc *MerchantClient) InitSplitWalletActivation(ctx context.Context, chain, splitter string) (*model.SplitWalletActivationInfo, error) {
	data, err := mc.doSignedJSONRequest(ctx, "/api/v4.0.0/mpc/activate/init", map[string]interface{}{
		"chain":           chain,
		"splitterAddress": splitter,
	})
	if err != nil {
		return nil, err
	}
	var result model.SplitWalletActivationInfo
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("解析 activate init 响应失败: %w", err)
	}
	return &result, nil
}

func (mc *MerchantClient) RegisterActivationManager(ctx context.Context, chain, splitter, managerAddress string) error {
	_, err := mc.doSignedJSONRequest(ctx, "/api/v4.0.0/mpc/activate/manager/generated", map[string]interface{}{
		"chain":           chain,
		"splitterAddress": splitter,
		"managerAddress":  managerAddress,
	})
	return err
}

func (mc *MerchantClient) CommitSplitWalletActivation(ctx context.Context, chain, splitter, activateTxID string) error {
	_, err := mc.doSignedJSONRequest(ctx, "/api/v4.0.0/mpc/activate/commit", map[string]interface{}{
		"chain":           chain,
		"splitterAddress": splitter,
		"activateTxId":    activateTxID,
	})
	return err
}
