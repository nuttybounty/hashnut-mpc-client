package client

import (
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/okx/threshold-lib/crypto/zkp"
	"time"

	"github.com/okx/threshold-lib/crypto/paillier"
	"testing"

	"github.com/okx/threshold-lib/tss"
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	"github.com/okx/threshold-lib/tss/key/dkg"
)

func TestP1PreSignCost(t *testing.T) {
	p1Data, p2Data, _ := KeyGen()

	// this step should be locally done by P1
	start := time.Now()
	paiPrivate, _, _ := paillier.NewKeyPair(8)
	end := time.Now()
	fmt.Printf("generate paillier key pair cost %v seconds\n", end.Sub(start).Seconds())

	start = time.Now()
	p1PreParams := keygen.GeneratePreParams()
	end = time.Now()
	fmt.Printf("generate p1 preparams cost %v seconds\n", end.Sub(start).Seconds())

	start = time.Now()
	zkp.NewDlnProve(p1PreParams.H1i, p1PreParams.H2i, p1PreParams.Alpha, p1PreParams.P, p1PreParams.Q, p1PreParams.NTildei)
	end = time.Now()
	fmt.Printf("generate dln prove standalone cost %v seconds\n", end.Sub(start).Seconds())

	start = time.Now()
	_, _ = keygen.P1(p1Data.ShareI, paiPrivate, p1Data.Id, p2Data.Id, p1PreParams)
	end = time.Now()
	fmt.Printf("generate p1 cost %v seconds\n", end.Sub(start).Seconds())
}

func KeyGen() (*tss.KeyStep3Data, *tss.KeyStep3Data, *tss.KeyStep3Data) {
	setUp1 := dkg.NewSetUp(1, 3, secp256k1.S256())
	setUp2 := dkg.NewSetUp(2, 3, secp256k1.S256())
	setUp3 := dkg.NewSetUp(3, 3, secp256k1.S256())

	msgs1_1, _ := setUp1.DKGStep1()
	msgs2_1, _ := setUp2.DKGStep1()
	msgs3_1, _ := setUp3.DKGStep1()

	msgs1_2_in := []*tss.Message{msgs2_1[1], msgs3_1[1]}
	msgs2_2_in := []*tss.Message{msgs1_1[2], msgs3_1[2]}
	msgs3_2_in := []*tss.Message{msgs1_1[3], msgs2_1[3]}

	msgs1_2, _ := setUp1.DKGStep2(msgs1_2_in)
	msgs2_2, _ := setUp2.DKGStep2(msgs2_2_in)
	msgs3_2, _ := setUp3.DKGStep2(msgs3_2_in)

	msgs1_3_in := []*tss.Message{msgs2_2[1], msgs3_2[1]}
	msgs2_3_in := []*tss.Message{msgs1_2[2], msgs3_2[2]}
	msgs3_3_in := []*tss.Message{msgs1_2[3], msgs2_2[3]}

	p1SaveData, _ := setUp1.DKGStep3(msgs1_3_in)
	p2SaveData, _ := setUp2.DKGStep3(msgs2_3_in)
	p3SaveData, _ := setUp3.DKGStep3(msgs3_3_in)

	return p1SaveData, p2SaveData, p3SaveData
}
