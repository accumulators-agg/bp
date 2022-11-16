package bpacc

import (
	"fmt"
	"testing"

	"github.com/alinush/go-mcl"
)

func TestPedersen(t *testing.T) {
	ell := []uint64{5}

	var n uint64
	n = uint64(1) << ell[len(ell)-1]
	elements := PopulateRandom(n)

	var acc BpAcc
	acc.KeyGenLoad(8, ell[len(ell)-1], "xyz", "../pkvk-21")

	for _, i := range ell {
		n = uint64(1) << i
		data := elements[:n]

		t.Run(fmt.Sprintf("PedersenOpenG2"), func(t *testing.T) {
			var random mcl.Fr
			random.Random()
			pedG2 := PedG2{acc.PedersenG2(data, acc.VK, random, acc.PedVK[0]), random}
			digest := acc.PedersenG2(data, acc.VK, pedG2.R, acc.PedVK[0])
			status := digest.IsEqual(&pedG2.Com)

			if status == false {
				t.Errorf("PedVCG2 did not verify %d", i)
			}
		})

	}
}
