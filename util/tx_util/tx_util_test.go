package tx_util

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAddressConvert(t *testing.T) {
	tronAddr := "TGjUZEUoiB6YiFuWUkGkuWVPPRHJ4c6Xq1"
	ethAddr, err := TronToEth(tronAddr)
	assert.NoError(t, err, "convert tron address to eth error")
	t.Logf("convert tron address %s to eth address %s success\n", tronAddr, ethAddr)
}
