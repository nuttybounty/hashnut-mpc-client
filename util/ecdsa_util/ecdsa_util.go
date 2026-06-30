package ecdsa_util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/crypto/schnorr"
	"github.com/okx/threshold-lib/crypto/zkp"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	"golang.org/x/crypto/sha3"
	"math/big"
)

// GetCurveByName 根据曲线名称获取曲线对象
func GetCurveByName(curveName string) *secp256k1.KoblitzCurve {
	switch curveName {
	case "secp256k1":
		return secp256k1.S256()
	default:
		// 默认返回 secp256k1
		return secp256k1.S256()
	}
}

func HexToECDSAPubKey(hexStr string) (*ecdsa.PublicKey, error) {
	pubKeyBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	X, Y := elliptic.Unmarshal(secp256k1.S256(), pubKeyBytes)
	return &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     X,
		Y:     Y,
	}, nil
}

func ECDSAPubKeyToHex(pubKey *ecdsa.PublicKey) string {
	pubKeyBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	return hex.EncodeToString(pubKeyBytes)
}

// JsonToKeyStep3Data KeyStep3Data 反序列化
func JsonToKeyStep3Data(jsonBytes []byte) (*tss.KeyStep3Data, error) {
	res := &tss.KeyStep3Data{}
	err := json.Unmarshal(jsonBytes, &res)
	return res, err
}

// KeyStep3DataToJson KeyStep3Data 序列化
func KeyStep3DataToJson(data *tss.KeyStep3Data) ([]byte, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

// JsonToPreParams PreParams 反序列化
func JsonToPreParams(jsonBytes []byte) (*keygen.PreParams, error) {
	res := keygen.PreParams{}
	if err := json.Unmarshal(jsonBytes, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// PreParamsToJson PreParams 序列化
func PreParamsToJson(data *keygen.PreParams) ([]byte, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

// JsonToDlnProof DlnProof 反序列化
func JsonToDlnProof(jsonBytes []byte) (*zkp.DlnProof, error) {
	res := zkp.DlnProof{}
	if err := json.Unmarshal(jsonBytes, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// DlnProofToJson PreParams 序列化
func DlnProofToJson(data *zkp.DlnProof) ([]byte, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

// JsonToPaillierPubKey paillier public key 反序列化
func JsonToPaillierPubKey(jsonBytes []byte) (*paillier.PublicKey, error) {
	res := paillier.PublicKey{}
	if err := json.Unmarshal(jsonBytes, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// PaillierPubKeyToJson paillier public key 序列化
func PaillierPubKeyToJson(data *paillier.PublicKey) ([]byte, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

// JsonToPaillierPrivKey paillier private key 反序列化
func JsonToPaillierPrivKey(jsonBytes []byte) (*paillier.PrivateKey, error) {
	res := paillier.PrivateKey{}
	if err := json.Unmarshal(jsonBytes, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// PaillierPrivKeyToJson paillier private key 序列化
func PaillierPrivKeyToJson(data *paillier.PrivateKey) ([]byte, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

// JsonToSchnorrProof 序列化
func JsonToSchnorrProof(schnorrProofJson string) (*schnorr.Proof, error) {
	res := &schnorr.Proof{}
	err := json.Unmarshal([]byte(schnorrProofJson), &res)
	return res, err
}

// JsonToCurvesECPoint ECPoint序列化
func JsonToCurvesECPoint(curvesECPointJson string) (*curves.ECPoint, error) {
	res := &curves.ECPoint{}
	err := json.Unmarshal([]byte(curvesECPointJson), &res)
	return res, err
}

func Str2BigInt(str string) *big.Int {
	// 将字符串转换为大整数
	num := new(big.Int)
	num.SetString(str, 10)
	return num
}

func GetSignByRS(pubKey *ecdsa.PublicKey, messageHash common.Hash, r *big.Int, s *big.Int) (string, uint8, error) {
	// 将 r, s 各填充到 32 字节
	rBytes := padTo32Bytes(r.Bytes())
	sBytes := padTo32Bytes(s.Bytes())

	// 构造 65 字节的以太坊签名: r(32) + s(32) + v(1)
	ethSignature := make([]byte, 65)
	copy(ethSignature[0:32], rBytes)
	copy(ethSignature[32:64], sBytes)

	originalV := recoverV(r, s, messageHash.Bytes(), common.BytesToAddress(PublicKeyToAddressBytes(pubKey)))
	ethSignature[64] = originalV

	return hex.EncodeToString(ethSignature), originalV, nil
}

// padTo32Bytes 将字节切片左填充零到 32 字节
func padTo32Bytes(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func recoverV(r, s *big.Int, hash []byte, address common.Address) uint8 {
	rBytes := padTo32Bytes(r.Bytes())
	sBytes := padTo32Bytes(s.Bytes())
	ethSignature := make([]byte, 64)
	copy(ethSignature[0:32], rBytes)
	copy(ethSignature[32:64], sBytes)
	for i := uint8(0); i < 4; i++ {
		sign2 := append(ethSignature, i)
		uncompressedPubKey, err := crypto.Ecrecover(hash, sign2)
		if err != nil {
			continue
		}
		pubKey, _ := crypto.UnmarshalPubkey(uncompressedPubKey)
		if bytes.Equal(address.Bytes(), crypto.PubkeyToAddress(*pubKey).Bytes()) {
			return i
		}
	}
	return 0
}

func PublicKeyToAddressBytes(publicKey *ecdsa.PublicKey) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)[1:])
	return hash.Sum(nil)[12:]
}
