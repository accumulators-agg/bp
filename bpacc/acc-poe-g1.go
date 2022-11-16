package bpacc

import (
	"fmt"

	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
)

// Actual protocol is in the paper. Notice that proving in G1 implies one G1 and one G2 element as proof.
// But proving in G2 implies, two G1 elements as proof.
func (self *BpAcc) NiPoEProveG1(w mcl.G1, u mcl.G1, v []mcl.Fr) (mcl.G1, mcl.G2) {

	ell := HashPoEParamsG1(w, u, v)
	q, r := fft.PolyDiv(v, ell)
	p := fft.PolySub(v, r)

	var Q1 mcl.G1
	var Q2 mcl.G2
	mcl.G1MulVec(&Q1, self.PK[:len(q)], q)
	mcl.G2MulVec(&Q2, self.VK[:len(p)], p)

	return Q1, Q2
}

// Actual protocol is in the paper. Notice that proving in G1 implies one G1 and one G2 element as proof.
// But proving in G2 implies, two G1 elements as proof.
func (self *BpAcc) NiPoEVerifyG1(Q1 mcl.G1, Q2 mcl.G2, w mcl.G1, u mcl.G1, v []mcl.Fr) bool {
	ell := HashPoEParamsG1(w, u, v)
	_, r := fft.PolyDiv(v, ell)

	var h1 mcl.G2
	mcl.G2MulVec(&h1, self.VK[:len(ell)], ell)
	status1 := MultiPairing2(Q1, h1, self.G, Q2)
	if !status1 {
		return false
	}

	var h2 mcl.G2
	mcl.G2Mul(&h2, &self.H, &r[0])
	mcl.G2Add(&h2, &h2, &Q2)
	status2 := MultiPairing2(u, h2, w, self.H)
	return status1 && status2
}

// Return (x - l)
func HashPoEParamsG1(w mcl.G1, u mcl.G1, v []mcl.Fr) []mcl.Fr {
	N := len(v)
	if N == 0 {
		panic("PoE: V(s) polynomial is empty.")
	}
	total := GetG1ByteSize() + GetG1ByteSize() + len(v)*GetFrByteSize()
	input := make([]byte, 0, total)
	input = append(input, w.Serialize()...)
	input = append(input, u.Serialize()...)
	for i := range v {
		input = append(input, v[i].Serialize()...)
	}
	var ell mcl.Fr
	if !ell.SetHashOf(input) {
		ell.SetInt64(17)
		fmt.Println("PoE: SetHashOf error.")
	}
	l := make([]mcl.Fr, 2)
	mcl.FrNeg(&l[0], &ell)
	l[1].SetInt64(1)
	return l
}
