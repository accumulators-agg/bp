package bpacc

import (
	"fmt"
	"testing"

	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
)

func TestComputeYsVec(t *testing.T) {

	l := uint64(5)
	N := uint64(1) << l
	I := make([]mcl.Fr, N)
	for i := range I {
		I[i].Random()
	}

	subProdTree := fft.SubProductTree(I)
	IProd := subProdTree[len(subProdTree)-1][0]

	Y_Result := ComputeYsVec(subProdTree)
	for i := range I {
		x := make([]mcl.Fr, 2)
		mcl.FrNeg(&x[0], &I[i])
		x[1].SetInt64(1)
		Y_i, _ := fft.PolyDiv(IProd, x)
		status := CheckEqualVec(Y_i, Y_Result[i])

		if !status {
			t.Errorf("Polynomials did not match %d", i)
		}
	}
}

func TestMultiPairing(t *testing.T) {

	l := uint64(5)
	N := (uint64(1) << l)

	var P mcl.G1
	P.Random()

	var Q mcl.G2
	Q.SetString("0", 10)

	Ps := make([]mcl.G1, N)
	Qs := make([]mcl.G2, N)

	for i := range Qs {
		Ps[i] = P
		Qs[i].Random()
		mcl.G2Add(&Q, &Q, &Qs[i])
	}

	fmt.Println(len(Ps), len(Qs))
	status := MultiPairingN(P, Q, Ps, Qs)

	if !status {
		t.Errorf("Multi-pairing failed")
	}
}

func CheckEqualVec(a []mcl.Fr, b []mcl.Fr) bool {
	n := len(a)
	if n == len(b) && n > 0 {
		flag := true
		for i := 0; i < n; i++ {
			flag = flag && a[i].IsEqual(&b[i])
		}
		return flag
	}
	return false
}

func BenchmarkComputeYsVec(b *testing.B) {

	l := uint64(8)
	N := uint64(1) << l
	I := make([]mcl.Fr, N)
	for i := range I {
		I[i].Random()
	}

	subProdTree := fft.SubProductTree(I)
	IProd := subProdTree[len(subProdTree)-1][0]

	var Y_Result [][]mcl.Fr
	b.Run(fmt.Sprintf("ComputeYsVec;2^%d", l), func(b *testing.B) {
		b.ResetTimer()
		for j := 0; j < b.N; j++ {
			Y_Result = ComputeYsVec(subProdTree)
		}
	})

	Y_i := make([][]mcl.Fr, len(I))
	b.Run(fmt.Sprintf("ComputeYsVecNaive;2^%d", l), func(b *testing.B) {
		b.ResetTimer()
		for j := 0; j < b.N; j++ {
			for i := range I {
				x := make([]mcl.Fr, 2)
				mcl.FrNeg(&x[0], &I[i])
				x[1].SetInt64(1)
				Y_i[i], _ = fft.PolyDiv(IProd, x)
			}
		}
	})

	for i := range I {
		status := CheckEqualVec(Y_i[i], Y_Result[i])
		if !status {
			b.Errorf("Polynomials did not match %d", i)
		}
	}
}
