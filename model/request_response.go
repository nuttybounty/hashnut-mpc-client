package model

import (
	"encoding/json"
	"github.com/okx/threshold-lib/crypto/commitment"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/tss"
	"math/big"
)

// BaseRsp 通用响应结构
type BaseRsp struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// MpcRsp Mpc响应结构体
type MpcRsp struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// KGStepReq KeyGen相关请求
type KGStepReq struct {
	Message *tss.Message `json:"message"`
}

// KGVerifyBindReq 验证地址并绑定P2Context的请求
type KGVerifyBindReq struct {
	PublicKey struct {
		X string `json:"X"`
		Y string `json:"Y"`
	} `json:"PublicKey"`
	Chain          string      `json:"ChainType"`
	ChainCode      string      `json:"ChainCode"`
	P1DataId       int         `json:"P1DataId"`
	P1PreSignParam tss.Message `json:"P1PreSignParam"`
}

// KGVerifyBindRsp 验证地址并绑定P2Context的回复
type KGVerifyBindRsp struct {
	PublicKey struct {
		X string `json:"X"`
		Y string `json:"Y"`
	} `json:"PublicKey"`
	Address   string `json:"Address"`
	ChainCode string `json:"ChainCode"`
	Verified  bool   `json:"Verified"`
}

// KGGetAddressReq 获取地址的请求
type KGGetAddressReq struct {
	Address string `json:"address"`
}

// KGGetAddressRsp 获取地址回复
type KGGetAddressRsp struct {
	PubKey  string `json:"pub_key"`
	Address string `json:"address"`
}

// InitSignCtxReq Sign相关请求
type InitSignCtxReq struct {
	Address string `json:"address"`
	Message string `json:"message"`
}

// SignStep1Req 签名step1请求
type SignStep1Req struct {
	Address    string `json:"address"`
	Commitment string `json:"commitment"`
}

// SignStep1Rsp 签名step1回复
type SignStep1Rsp struct {
	Proof   *schnorr.Proof  `json:"proof"`
	ECPoint *curves.ECPoint `json:"ecpoint"`
}

// SignStep2Req 签名step2请求
type SignStep2Req struct {
	Address string              `json:"address"`
	CmtD    *commitment.Witness `json:"cmt_d"`
	P1Proof *schnorr.Proof      `json:"p1_proof"`
}

// SignStep2Rsp 签名step2回复
type SignStep2Rsp struct {
	E_k2_h_xr string `json:"E_k2_h_xr"`
}

// SignStep3Result 签名最终结果
type SignStep3Result struct {
	R    big.Int `json:"r"`
	S    big.Int `json:"s"`
	V    uint8   `json:"v"`
	Sign string  `json:"sign"`
}

// SplitWalletDeployDetail 从 proxy 获取的分账合约部署记录
type SplitWalletDeployDetail struct {
	ContractAddress    string `json:"contractAddress"`
	Chain              string `json:"chain"`
	MerchantAddress    string `json:"merchantAddress"`
	ContractAlias      string `json:"contractAlias"`
	SplitWalletManager string `json:"splitWalletManager"`
	State              int    `json:"state,string"`
	ActivateTxID       string `json:"activateTxId"`
	ProxyAdmin         string `json:"proxyAdmin"`
}

type SplitWalletActivationInfo struct {
	Chain           string `json:"chain"`
	MerchantAddress string `json:"merchantAddress"`
	SplitterAddress string `json:"splitterAddress"`
	ManagerAddress  string `json:"managerAddress"`
	ProxyAdmin      string `json:"proxyAdmin"`
	State           int    `json:"state,string"`
}

// ClientConfig 客户端配置
type ClientConfig struct {
	ServerURL string
	Timeout   int
}
