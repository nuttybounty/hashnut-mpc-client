package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	db_model "hashnut-mpc-client/storage/dal/model"
)

// TronRpcAuth 存储 Tron gRPC 认证信息
type TronRpcAuth struct {
	ApiKey   string
	Provider string
}

// RemoteConfigMgr 从后端拉取配置，缓存到内存。替代原来的 ConfigMgr + RpcMgr（SQLite）。
type RemoteConfigMgr struct {
	mu           sync.RWMutex
	chainMap     map[string]*db_model.ChainConfig // key: chain (uppercase)
	rpcUrlMap    map[string]string                // key: chain (uppercase), value: rpcUrl
	tronAuthMap  map[string]*TronRpcAuth          // key: chain (uppercase), Tron gRPC 认证
	chains       []db_model.ChainConfig           // 有序列表
	loaded       bool
}

func NewRemoteConfigMgr() *RemoteConfigMgr {
	return &RemoteConfigMgr{
		chainMap:    make(map[string]*db_model.ChainConfig),
		rpcUrlMap:   make(map[string]string),
		tronAuthMap: make(map[string]*TronRpcAuth),
	}
}

// LoadFromServer 从后端拉取链配置和 RPC 配置
func (r *RemoteConfigMgr) LoadFromServer(mc *MerchantClient) error {
	ctx := context.Background()

	// 1. 拉取链配置
	if err := r.fetchChainConfigs(mc, ctx); err != nil {
		return fmt.Errorf("拉取链配置失败: %w", err)
	}

	// 2. 拉取 RPC 配置
	if err := r.fetchRpcConfigs(mc, ctx); err != nil {
		return fmt.Errorf("拉取 RPC 配置失败: %w", err)
	}

	r.mu.Lock()
	r.loaded = true
	r.mu.Unlock()
	return nil
}

// ---- 对外查询接口 ----

func (r *RemoteConfigMgr) GetChainConfig(chain string) (*db_model.ChainConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cfg, ok := r.chainMap[strings.ToUpper(chain)]
	if !ok {
		return nil, fmt.Errorf("未知的链: %s", chain)
	}
	return cfg, nil
}

func (r *RemoteConfigMgr) ListChains() []db_model.ChainConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]db_model.ChainConfig, len(r.chains))
	copy(result, r.chains)
	return result
}

// GetRpcUrl 获取指定链的 RPC URL
// EVM 链: 返回后端 RPC 代理地址 (payServerURL + /api/v4.0.0/config/{chain}/rpc)
// Tron 链: 返回 FrontRpcUrl (gRPC 地址)
func (r *RemoteConfigMgr) GetRpcUrl(chain string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	url, ok := r.rpcUrlMap[strings.ToUpper(chain)]
	if !ok || url == "" {
		return "", fmt.Errorf("未找到链 %s 的 RPC 配置", chain)
	}
	return url, nil
}

// GetTronRpcAuth 获取 Tron 链的 gRPC 认证信息
func (r *RemoteConfigMgr) GetTronRpcAuth(chain string) *TronRpcAuth {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tronAuthMap[strings.ToUpper(chain)]
}

// GetExplorerTxUrl 构建交易详情的区块浏览器链接
func (r *RemoteConfigMgr) GetExplorerTxUrl(chain, txId string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cfg, ok := r.chainMap[strings.ToUpper(chain)]
	if !ok || cfg.ExplorerUrl == "" {
		return ""
	}
	return cfg.ExplorerUrl + cfg.ExplorerTxPath + txId
}

// GetExplorerAddrUrl 构建地址详情的区块浏览器链接
func (r *RemoteConfigMgr) GetExplorerAddrUrl(chain, addr string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cfg, ok := r.chainMap[strings.ToUpper(chain)]
	if !ok || cfg.ExplorerUrl == "" {
		return ""
	}
	return cfg.ExplorerUrl + cfg.ExplorerAddrPath + addr
}

func (r *RemoteConfigMgr) IsLoaded() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.loaded
}

// ---- 内部拉取逻辑 ----

// 后端 ChainInfo 响应结构
type chainInfoResp struct {
	Chain            string      `json:"chain"`
	ChainId          json.Number `json:"chainId"`
	ChainType        json.Number `json:"chainType"`
	BaseChainSymbol  string      `json:"baseChainSymbol"`
	BaseChainCoin    string      `json:"baseChainCoin"`
	Enable           bool        `json:"enable"`
	Multicall3       string      `json:"multicall3"`
	ExplorerUrl      string      `json:"explorerUrl"`
	ExplorerTxPath   string      `json:"explorerTxPath"`
	ExplorerAddrPath string      `json:"explorerAddrPath"`
}

func (r *RemoteConfigMgr) fetchChainConfigs(mc *MerchantClient, ctx context.Context) error {
	data, err := mc.doPostJSON(ctx, "/api/v4.0.0/config/chains", map[string]interface{}{})
	if err != nil {
		return err
	}
	var items []chainInfoResp
	if len(data) == 0 || string(data) == "null" {
		return fmt.Errorf("后端返回空的链配置")
	}
	if err := json.Unmarshal(data, &items); err != nil {
		return fmt.Errorf("解析链配置失败: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.chainMap = make(map[string]*db_model.ChainConfig, len(items))
	r.chains = make([]db_model.ChainConfig, 0, len(items))

	for _, item := range items {
		chainType := "evm"
		if strings.Contains(strings.ToUpper(item.Chain), "TRON") {
			chainType = "tron"
		}
		currency := item.BaseChainSymbol
		if currency == "" {
			currency = item.BaseChainCoin
		}

		chainId, _ := item.ChainId.Int64()
		cfg := db_model.ChainConfig{
			Chain:            item.Chain,
			ChainID:          int32(chainId),
			ChainType:        chainType,
			Currency:         currency,
			Multicall3:       item.Multicall3,
			ExplorerUrl:      item.ExplorerUrl,
			ExplorerTxPath:   item.ExplorerTxPath,
			ExplorerAddrPath: item.ExplorerAddrPath,
		}
		r.chainMap[strings.ToUpper(item.Chain)] = &cfg
		r.chains = append(r.chains, cfg)
	}
	return nil
}

// 后端 RPC 配置响应结构
type rpcConfigResp struct {
	BlockChain   string `json:"blockChain"`
	RpcUrl       string `json:"rpcUrl"`
	GrpcEndpoint string `json:"grpcEndpoint,omitempty"` // Tron gRPC 直连地址
	ApiKey       string `json:"apiKey,omitempty"`
	Provider     string `json:"provider,omitempty"`
}

func (r *RemoteConfigMgr) fetchRpcConfigs(mc *MerchantClient, ctx context.Context) error {
	data, err := mc.doPostJSON(ctx, "/api/v4.0.0/config/rpc", map[string]interface{}{})
	if err != nil {
		return err
	}
	var items []rpcConfigResp
	if len(data) == 0 || string(data) == "null" {
		return fmt.Errorf("后端返回空的 RPC 配置")
	}
	if err := json.Unmarshal(data, &items); err != nil {
		return fmt.Errorf("解析 RPC 配置失败: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, item := range items {
		chain := strings.ToUpper(item.BlockChain)
		if strings.Contains(chain, "TRON") {
			// Tron: 优先使用 grpcEndpoint（gRPC 直连），fallback 到 rpcUrl
			endpoint := item.GrpcEndpoint
			if endpoint == "" {
				endpoint = item.RpcUrl
			}
			r.rpcUrlMap[chain] = endpoint
			r.tronAuthMap[chain] = &TronRpcAuth{
				ApiKey:   item.ApiKey,
				Provider: item.Provider,
			}
		} else {
			// EVM: 使用后端 RPC 代理，MPC Client 不需要知道实际 RPC 地址
			r.rpcUrlMap[chain] = mc.payServerURL + "/api/v4.0.0/config/" + chain + "/rpc"
		}
	}
	return nil
}
