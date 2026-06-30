package ecdsa_ctx

import (
	"crypto/ecdsa"
	"errors"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/okx/threshold-lib/crypto/curves"
	"github.com/okx/threshold-lib/crypto/paillier"
	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	tsssign "github.com/okx/threshold-lib/tss/ecdsa/sign"
	"github.com/okx/threshold-lib/tss/key/bip32"
	"github.com/okx/threshold-lib/tss/key/dkg"
	"github.com/okx/threshold-lib/tss/key/reshare"
	"hashnut-mpc-client/model"
	"math/big"
)

type KGContext struct {
	SessionID int64
	Chain     string
	Splitter  string // split wallet 地址（用于 PreParams 复用）
	Setup     *dkg.SetupInfo
	Step1Msg  *tss.Message
	Step2Msg  *tss.Message
	Step3Data *tss.KeyStep3Data
	Address   *common.Address
	KeyFrom   *ECDSAKeyFrom
	KGResult  *model.KGVerifyBindRsp
}

type SignContext struct {
	SessionID int64
	Chain     string
	Address   string
	Message   string
	P1Context *tsssign.P1Context
	PubKey    *ecdsa.PublicKey
	KeyFrom   *ECDSAKeyFrom
	Step1Msg  *model.SignStep1Rsp
	Step2Msg  *model.SignStep2Rsp
	Step3Data *model.SignStep3Result
}

type ECDSAKeyCommon struct {
	PreParams    *keygen.PreParams
	Curve        *secp256k1.KoblitzCurve
	KeyStep3Data *tss.KeyStep3Data // KeyStep3Data ShareI is private share key
}

type ECDSAKeyFrom struct {
	ECDSAKeyCommon
	PaillierPrivateKey *paillier.PrivateKey
	PaillierPublicKey  *paillier.PublicKey
}

type ECDSAKeyTo struct {
	ECDSAKeyCommon
	SaveData *keygen.P2SaveData
}

func (e *ECDSAKeyCommon) NewEcdsaKey(preParams *keygen.PreParams) *ECDSAKeyCommon {
	e.PreParams = preParams
	e.Curve = secp256k1.S256()
	return e
}

// KeyGenRequestMessage p1 send message to p2 for keygen
func (e *ECDSAKeyFrom) KeyGenRequestMessage(partnerDataId int, preParams *keygen.PreParams) (*tss.Message, error) {
	var err error
	e.PaillierPrivateKey, e.PaillierPublicKey, err = paillier.NewKeyPair(8)
	if err != nil {
		return nil, err
	}
	p1Dto, err := keygen.P1(e.KeyStep3Data.ShareI, e.PaillierPrivateKey, e.KeyStep3Data.Id, partnerDataId, preParams)
	return p1Dto, err
}

// KeyGenRequestMessageByPrime p1 send message to p2 for keygen
func (e *ECDSAKeyFrom) KeyGenRequestMessageByPrime(partnerDataId int, preParams *keygen.PreParams, prime1, prime2 string) (*tss.Message, error) {
	var err error
	e.PaillierPrivateKey, e.PaillierPublicKey, err = PaillierNewKeyPair(prime1, prime2)
	if err != nil {
		return nil, err
	}
	p1Dto, err := keygen.P1(e.KeyStep3Data.ShareI, e.PaillierPrivateKey, e.KeyStep3Data.Id, partnerDataId, preParams)
	return p1Dto, err
}

// GenKeyStep3DataForPartners generates private data for partners
func (e *ECDSAKeyCommon) GenKeyStep3DataForPartners() (*tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data, error) {
	setUp1 := dkg.NewSetUp(1, 3, e.Curve)
	setUp2 := dkg.NewSetUp(2, 3, e.Curve)
	setUp3 := dkg.NewSetUp(3, 3, e.Curve)

	msgs1_1, err := setUp1.DKGStep1()
	if err != nil {
		return nil, nil, nil, err
	}
	msgs2_1, err := setUp2.DKGStep1()
	if err != nil {
		return nil, nil, nil, err
	}
	msgs3_1, err := setUp3.DKGStep1()
	if err != nil {
		return nil, nil, nil, err
	}

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3]}

	msgs1_2, err := setUp1.DKGStep2(msgs1_2_in)
	if err != nil {
		return nil, nil, nil, err
	}
	msgs2_2, err := setUp2.DKGStep2(msgs2_2_in)
	if err != nil {
		return nil, nil, nil, err
	}
	msgs3_2, err := setUp3.DKGStep2(msgs3_2_in)
	if err != nil {
		return nil, nil, nil, err
	}

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1]}
	if err != nil {
		return nil, nil, nil, err
	}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2]}
	if err != nil {
		return nil, nil, nil, err
	}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3]}
	if err != nil {
		return nil, nil, nil, err
	}

	p1Data, err := setUp1.DKGStep3(msgs1_3_in)
	if err != nil {
		return nil, nil, nil, err
	}
	p2Data, err := setUp2.DKGStep3(msgs2_3_in)
	if err != nil {
		return nil, nil, nil, err
	}
	p3Data, err := setUp3.DKGStep3(msgs3_3_in)
	if err != nil {
		return nil, nil, nil, err
	}

	return p1Data, p2Data, p3Data, nil
}

func (e *ECDSAKeyCommon) RefreshKey(devoteList [2]int, datas [3]*tss.KeyStep3Data) (*tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data) {
	refresh1 := reshare.NewRefresh(1, 3, devoteList, datas[0].ShareI, datas[0].PublicKey)
	refresh2 := reshare.NewRefresh(2, 3, devoteList, datas[1].ShareI, datas[1].PublicKey)
	refresh3 := reshare.NewRefresh(3, 3, devoteList, datas[2].ShareI, datas[2].PublicKey)

	msgs1_1, _ := refresh1.DKGStep1()
	msgs2_1, _ := refresh2.DKGStep1()
	msgs3_1, _ := refresh3.DKGStep1()

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3]}

	msgs1_2, _ := refresh1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := refresh2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := refresh3.DKGStep2(msgs3_2_in)

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3]}

	p1Data, _ := refresh1.DKGStep3(msgs1_3_in)
	p2Data, _ := refresh2.DKGStep3(msgs2_3_in)
	p3Data, _ := refresh3.DKGStep3(msgs3_3_in)

	// chaincode is same
	p1Data.ChainCode = datas[devoteList[0]-1].ChainCode
	p2Data.ChainCode = datas[devoteList[0]-1].ChainCode
	p3Data.ChainCode = datas[devoteList[0]-1].ChainCode
	return p1Data, p2Data, p3Data
}

func String2BigInt(str string) (*big.Int, error) {
	n := new(big.Int)
	n, ok := n.SetString(str, 10)
	if !ok {
		return nil, errors.New("SetString: error")
	}
	return n, nil
}

// PaillierNewKeyPair generate paillier key pair
func PaillierNewKeyPair(prime1, prime2 string) (*paillier.PrivateKey, *paillier.PublicKey, error) {
	p, err := String2BigInt(prime1)
	if err != nil {
		return nil, nil, err
	}
	q, err := String2BigInt(prime2)
	if err != nil {
		return nil, nil, err
	}

	// n = p*q
	n := new(big.Int).Mul(p, q)

	// phi = (p-1) * (q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	// lambda = lcm(p−1, q−1)
	gcd := new(big.Int).GCD(nil, nil, pMinus1, qMinus1)
	lambda := new(big.Int).Div(phi, gcd)

	publicKey := &paillier.PublicKey{N: n}
	privateKey := &paillier.PrivateKey{PublicKey: *publicKey, Lambda: lambda, Phi: phi}
	return privateKey, publicKey, nil
}

func (e *ECDSAKeyTo) GenSaveData(p1Dto *tss.Message, p1DataId int) error {
	publicKey, err := curves.NewECPoint(e.Curve, e.KeyStep3Data.PublicKey.X, e.KeyStep3Data.PublicKey.Y)
	if err != nil {
		return err
	}
	e.SaveData, err = keygen.P2(e.KeyStep3Data.ShareI, publicKey, p1Dto, p1DataId, e.KeyStep3Data.Id)
	return err
}

func (e *ECDSAKeyTo) GenPublicKeyAndShareI() (*ecdsa.PublicKey, *big.Int, error) {
	tssKey, err := bip32.NewTssKey(e.SaveData.X2, e.KeyStep3Data.PublicKey, e.KeyStep3Data.ChainCode)
	if err != nil {
		return nil, nil, err
	}
	tssKey, err = tssKey.NewChildKey(996)
	x2 := tssKey.ShareI()
	pubKey := &ecdsa.PublicKey{Curve: e.Curve, X: tssKey.PublicKey().X, Y: tssKey.PublicKey().Y}
	return pubKey, x2, nil
}
