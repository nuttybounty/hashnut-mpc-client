package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	"hashnut-mpc-client/ctx/ecdsa_ctx"
	"hashnut-mpc-client/util/encrypt_util"
)

// 序列化ECDSAKeyFrom - 包含 PreParams
func serializeECDSAKeyFrom(key *ecdsa_ctx.ECDSAKeyFrom) ([]byte, error) {
	type serializableKeyFrom struct {
		CurveName        string
		KeyStep3Data     *tss.KeyStep3Data
		PaillierPrivateN *big.Int
		PaillierPrivateL *big.Int
		PaillierPrivateP *big.Int
		PaillierPublicN  *big.Int
		PreParams        *keygen.PreParams
	}

	// 提取Paillier私钥的字段
	var privN, privL, privP, pubN *big.Int
	if key.PaillierPrivateKey != nil {
		privN = key.PaillierPrivateKey.N
		privL = key.PaillierPrivateKey.Lambda
		privP = key.PaillierPrivateKey.Phi
	}
	if key.PaillierPublicKey != nil {
		pubN = key.PaillierPublicKey.N
	}

	// 获取曲线名称
	curveName := ""
	if key.ECDSAKeyCommon.Curve != nil {
		curveName = "secp256k1"
	}

	skf := serializableKeyFrom{
		CurveName:        curveName,
		KeyStep3Data:     key.ECDSAKeyCommon.KeyStep3Data,
		PaillierPrivateN: privN,
		PaillierPrivateL: privL,
		PaillierPrivateP: privP,
		PaillierPublicN:  pubN,
		PreParams:        key.ECDSAKeyCommon.PreParams,
	}

	return json.Marshal(skf)
}

// 反序列化ECDSAKeyFrom，PreParams 已包含在序列化数据中
func deserializeECDSAKeyFrom(data []byte) (*ecdsa_ctx.ECDSAKeyFrom, error) {
	type serializableKeyFrom struct {
		CurveName        string
		KeyStep3Data     *tss.KeyStep3Data
		PaillierPrivateN *big.Int
		PaillierPrivateL *big.Int
		PaillierPrivateP *big.Int
		PaillierPublicN  *big.Int
		PreParams        *keygen.PreParams
	}

	var skf serializableKeyFrom
	if err := json.Unmarshal(data, &skf); err != nil {
		return nil, err
	}

	// 重建Paillier私钥
	var paillierPrivKey *paillier.PrivateKey
	if skf.PaillierPrivateN != nil && skf.PaillierPrivateL != nil && skf.PaillierPrivateP != nil {
		paillierPrivKey = &paillier.PrivateKey{
			PublicKey: paillier.PublicKey{
				N: skf.PaillierPrivateN,
			},
			Lambda: skf.PaillierPrivateL,
			Phi:    skf.PaillierPrivateP,
		}
	}

	// 重建Paillier公钥
	var paillierPubKey *paillier.PublicKey
	if skf.PaillierPublicN != nil {
		paillierPubKey = &paillier.PublicKey{
			N: skf.PaillierPublicN,
		}
	}

	// 重建曲线
	var curve *secp256k1.KoblitzCurve
	if skf.CurveName == "secp256k1" {
		curve = secp256k1.S256()
	}

	return &ecdsa_ctx.ECDSAKeyFrom{
		ECDSAKeyCommon: ecdsa_ctx.ECDSAKeyCommon{
			Curve:        curve,
			KeyStep3Data: skf.KeyStep3Data,
			PreParams:    skf.PreParams,
		},
		PaillierPrivateKey: paillierPrivKey,
		PaillierPublicKey:  paillierPubKey,
	}, nil
}

// ============ 加密序列化（仅加密私密字段） ============

// encryptedKeyFrom 存储格式：私密字段加密，公开字段明文
type encryptedKeyFrom struct {
	CurveName string             `json:"CurveName"`
	// 公开字段
	KeyStep3Id       int               `json:"Id"`
	PublicKeyX       string            `json:"PublicKeyX"`
	PublicKeyY       string            `json:"PublicKeyY"`
	ChainCode        string            `json:"ChainCode"`
	PaillierPublicN  string            `json:"PaillierPublicN,omitempty"`
	PreParams        *keygen.PreParams `json:"PreParams,omitempty"`
	// 私密字段（加密后的 JSON）
	EncShareI        json.RawMessage   `json:"EncShareI"`        // 加密的 KeyStep3Data.ShareI
	EncPaillierPriv  json.RawMessage   `json:"EncPaillierPriv,omitempty"`  // 加密的 {Lambda, Phi}
}

type paillierPrivSecrets struct {
	Lambda string `json:"l"`
	Phi    string `json:"p"`
}

func serializeECDSAKeyFromEncrypted(key *ecdsa_ctx.ECDSAKeyFrom, password string) ([]byte, error) {
	ekf := encryptedKeyFrom{
		CurveName: "secp256k1",
	}

	// 公开字段
	if key.KeyStep3Data != nil {
		ekf.KeyStep3Id = key.KeyStep3Data.Id
		if key.KeyStep3Data.PublicKey != nil {
			ekf.PublicKeyX = key.KeyStep3Data.PublicKey.X.String()
			ekf.PublicKeyY = key.KeyStep3Data.PublicKey.Y.String()
		}
		ekf.ChainCode = key.KeyStep3Data.ChainCode

		// 加密 ShareI
		shareIBytes := []byte(key.KeyStep3Data.ShareI.String())
		enc, err := encrypt_util.Encrypt(shareIBytes, password)
		if err != nil {
			return nil, fmt.Errorf("encrypt ShareI: %w", err)
		}
		ekf.EncShareI, err = json.Marshal(enc)
		if err != nil {
			return nil, err
		}
	}

	if key.PaillierPublicKey != nil {
		ekf.PaillierPublicN = key.PaillierPublicKey.N.String()
	}
	ekf.PreParams = key.PreParams

	// 加密 Paillier 私钥
	if key.PaillierPrivateKey != nil {
		secrets := paillierPrivSecrets{
			Lambda: key.PaillierPrivateKey.Lambda.String(),
			Phi:    key.PaillierPrivateKey.Phi.String(),
		}
		secretsJSON, err := json.Marshal(secrets)
		if err != nil {
			return nil, err
		}
		enc, err := encrypt_util.Encrypt(secretsJSON, password)
		if err != nil {
			return nil, fmt.Errorf("encrypt PaillierPriv: %w", err)
		}
		ekf.EncPaillierPriv, err = json.Marshal(enc)
		if err != nil {
			return nil, err
		}
	}

	return json.Marshal(ekf)
}

func deserializeECDSAKeyFromEncrypted(data []byte, password string) (*ecdsa_ctx.ECDSAKeyFrom, error) {
	var ekf encryptedKeyFrom
	if err := json.Unmarshal(data, &ekf); err != nil {
		return nil, fmt.Errorf("unmarshal encrypted key_from_data: %w", err)
	}
	if len(ekf.EncShareI) == 0 {
		return nil, fmt.Errorf("missing EncShareI field")
	}

	curve := secp256k1.S256()

	// 解密 ShareI
	var encShareI encrypt_util.EncryptedPrivateKey
	if err := json.Unmarshal(ekf.EncShareI, &encShareI); err != nil {
		return nil, fmt.Errorf("unmarshal EncShareI: %w", err)
	}
	shareIBytes, err := encrypt_util.Decrypt(&encShareI, password)
	if err != nil {
		return nil, fmt.Errorf("decrypt ShareI: %w", err)
	}
	shareI := new(big.Int)
	shareI.SetString(string(shareIBytes), 10)

	// 重建 PublicKey ECPoint
	pubX := new(big.Int)
	pubY := new(big.Int)
	pubX.SetString(ekf.PublicKeyX, 10)
	pubY.SetString(ekf.PublicKeyY, 10)

	step3Data := &tss.KeyStep3Data{
		Id:        ekf.KeyStep3Id,
		ShareI:    shareI,
		ChainCode: ekf.ChainCode,
	}
	// 仅在有坐标时恢复 PublicKey
	if pubX.Sign() > 0 && pubY.Sign() > 0 {
		step3Data.PublicKey = &curves.ECPoint{Curve: curve, X: pubX, Y: pubY}
	}

	// Paillier 公钥
	var paillierPubKey *paillier.PublicKey
	if ekf.PaillierPublicN != "" {
		n := new(big.Int)
		n.SetString(ekf.PaillierPublicN, 10)
		paillierPubKey = &paillier.PublicKey{N: n}
	}

	// 解密 Paillier 私钥
	var paillierPrivKey *paillier.PrivateKey
	if len(ekf.EncPaillierPriv) > 0 {
		var encPriv encrypt_util.EncryptedPrivateKey
		if err := json.Unmarshal(ekf.EncPaillierPriv, &encPriv); err == nil {
			privBytes, err := encrypt_util.Decrypt(&encPriv, password)
			if err == nil {
				var secrets paillierPrivSecrets
				if err := json.Unmarshal(privBytes, &secrets); err == nil {
					lambda := new(big.Int)
					phi := new(big.Int)
					lambda.SetString(secrets.Lambda, 10)
					phi.SetString(secrets.Phi, 10)
					n := new(big.Int)
					if paillierPubKey != nil {
						n = paillierPubKey.N
					}
					paillierPrivKey = &paillier.PrivateKey{
						PublicKey: paillier.PublicKey{N: n},
						Lambda:   lambda,
						Phi:      phi,
					}
				}
			}
		}
	}

	return &ecdsa_ctx.ECDSAKeyFrom{
		ECDSAKeyCommon: ecdsa_ctx.ECDSAKeyCommon{
			Curve:        curve,
			KeyStep3Data: step3Data,
			PreParams:    ekf.PreParams,
		},
		PaillierPrivateKey: paillierPrivKey,
		PaillierPublicKey:  paillierPubKey,
	}, nil
}

// 序列化PublicKey - 自定义序列化处理secp256k1
func serializePublicKey(pubKey *ecdsa.PublicKey) ([]byte, error) {
	type serializablePubKey struct {
		CurveName   string `json:"curve_name"`
		X           string `json:"x"`
		Y           string `json:"y"`
		IsSecp256k1 bool   `json:"is_secp256k1"`
	}

	curveName := ""
	isSecp256k1 := false

	if pubKey.Curve == secp256k1.S256() {
		curveName = "secp256k1"
		isSecp256k1 = true
	} else {
		switch pubKey.Curve.(type) {
		case *elliptic.CurveParams:
			params := pubKey.Curve.(*elliptic.CurveParams)
			curveName = params.Name
		default:
			curveName = "unknown"
		}
	}

	spk := serializablePubKey{
		CurveName:   curveName,
		X:           pubKey.X.String(),
		Y:           pubKey.Y.String(),
		IsSecp256k1: isSecp256k1,
	}

	return json.Marshal(spk)
}

// 反序列化PublicKey
func deserializePublicKey(data []byte) (*ecdsa.PublicKey, error) {
	type serializablePubKey struct {
		CurveName   string `json:"curve_name"`
		X           string `json:"x"`
		Y           string `json:"y"`
		IsSecp256k1 bool   `json:"is_secp256k1"`
	}

	var spk serializablePubKey
	if err := json.Unmarshal(data, &spk); err != nil {
		return nil, err
	}

	x := new(big.Int)
	y := new(big.Int)

	if _, success := x.SetString(spk.X, 10); !success {
		return nil, errors.New("failed to parse X coordinate")
	}

	if _, success := y.SetString(spk.Y, 10); !success {
		return nil, errors.New("failed to parse Y coordinate")
	}

	var curve elliptic.Curve
	if spk.IsSecp256k1 {
		curve = secp256k1.S256()
	} else {
		switch spk.CurveName {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		case "secp256k1":
			curve = secp256k1.S256()
		default:
			return nil, fmt.Errorf("unsupported curve: %s", spk.CurveName)
		}
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}
