package bpacc

import (
	"fmt"

	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
)

// Computes the commitment using trapdoor.
func (self *BpAcc) CommitFakeG1(elements []mcl.Fr) (mcl.G1, []mcl.Fr) {

	if uint64(len(elements)) > self.Q {
		panic(fmt.Sprintf("Wants to commit %d, but the accumulator supports only %d", len(elements), self.Q))
	}
	var prod mcl.Fr
	prod.SetInt64(1)
	for i := range elements {
		var tmp mcl.Fr
		mcl.FrSub(&tmp, &self.S, &elements[i])
		mcl.FrMul(&prod, &prod, &tmp)
	}

	var digest mcl.G1
	mcl.G1Mul(&digest, &self.G, &prod)
	return digest, []mcl.Fr{}
}

// Computes the commitment using trapdoor.
func (self *BpAcc) CommitFakeG2(elements []mcl.Fr) (mcl.G2, []mcl.Fr) {

	if uint64(len(elements)) > self.Q {
		panic(fmt.Sprintf("Wants to commit %d, but the accumulator supports only %d", len(elements), self.Q))
	}
	var prod mcl.Fr
	prod.SetInt64(1)
	for i := range elements {
		var tmp mcl.Fr
		mcl.FrSub(&tmp, &self.S, &elements[i])
		mcl.FrMul(&prod, &prod, &tmp)
	}

	var digest mcl.G2
	mcl.G2Mul(&digest, &self.H, &prod)
	return digest, []mcl.Fr{}
}

// Computes the membership proof for all elements in set I using the trapdoor.
func (self *BpAcc) ProveMemFake(X []mcl.Fr, I []mcl.Fr) []mcl.G1 {
	var xprod mcl.Fr
	xprod.SetInt64(1)

	for i := range X {
		var temp mcl.Fr
		mcl.FrSub(&temp, &self.S, &X[i])
		mcl.FrMul(&xprod, &xprod, &temp)
	}

	monomials := make([]mcl.Fr, len(I))
	for i := range I {
		mcl.FrSub(&monomials[i], &self.S, &I[i])
	}

	witness := ComputeYs(xprod, monomials)
	pi := make([]mcl.G1, len(I))

	for i := range witness {
		mcl.G1Mul(&pi[i], &self.G, &witness[i])
	}
	return pi
}

// Computes the non-membership proof for all elements in set I using the trapdoor.
func (self *BpAcc) ProveNonMemFake(X []mcl.Fr, I []mcl.Fr) []NonMemProof {
	var xprod mcl.Fr
	xprod.SetInt64(1)

	for i := range X {
		var temp mcl.Fr
		mcl.FrSub(&temp, &self.S, &X[i])
		mcl.FrMul(&xprod, &xprod, &temp)
	}

	monomials := make([]mcl.Fr, len(I))
	for i := range I {
		mcl.FrSub(&monomials[i], &self.S, &I[i])
	}

	pi := make([]NonMemProof, len(I))

	for i := range I {
		g, a, b := fft.XGCD([]mcl.Fr{xprod}, []mcl.Fr{monomials[i]})
		var u, v mcl.Fr
		mcl.FrDiv(&u, &a[0], &g[0])
		mcl.FrDiv(&v, &b[0], &g[0])
		var prod mcl.G1
		mcl.G1Mul(&prod, &self.G, &v)
		pi[i] = NonMemProof{u, prod}
	}
	return pi
}

// Computes the non-membership proof for all elements in set I using the trapdoor.
func (self *BpAcc) ProveBatchNonMemFake(X []mcl.Fr, I []mcl.Fr) (mcl.G2, mcl.G1) {
	var xprod, iprod mcl.Fr
	xprod.SetInt64(1)
	iprod.SetInt64(1)

	for i := range X {
		var temp mcl.Fr
		mcl.FrSub(&temp, &self.S, &X[i])
		mcl.FrMul(&xprod, &xprod, &temp)
	}

	for i := range I {
		var temp mcl.Fr
		mcl.FrSub(&temp, &self.S, &I[i])
		mcl.FrMul(&iprod, &iprod, &temp)
	}

	g, a, b := fft.XGCD([]mcl.Fr{xprod}, []mcl.Fr{iprod})
	var u, v mcl.Fr
	mcl.FrDiv(&u, &a[0], &g[0])
	mcl.FrDiv(&v, &b[0], &g[0])

	var A mcl.G2
	mcl.G2Mul(&A, &self.H, &u)
	var B mcl.G1
	mcl.G1Mul(&B, &self.G, &v)

	return A, B
}
