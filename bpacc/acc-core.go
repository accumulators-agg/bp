package bpacc

import (
	"fmt"

	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
)

// Add a bunch of elements to the accumulator and returns the digest and the accumulator polynomial
// Compute Subproduct tree from the roots |I|log^2|I|
// Computes |I| exponentiations.
func (self *BpAcc) Commit(elements []mcl.Fr) (mcl.G1, []mcl.Fr) {

	if uint64(len(elements)) > self.Q {
		panic(fmt.Sprintf("Wants to commit %d, but the accumulator supports only %d", len(elements), self.Q))
	}
	accPoly := fft.PolyTree(elements)
	var digest mcl.G1
	mcl.G1MulVec(&digest, self.PK[:len(accPoly)], accPoly)
	return digest, accPoly
}

// Takes two sets as inputs: X and I
// Return proof of all elements in I
// Compute Subproduct tree from the roots |X + I|log^2|X + I|
// Computes |I| long divisions
// Computes |I| multi-exp each of size |I| - 1
func (self *BpAcc) MemProve(X []mcl.Fr, I []mcl.Fr) []mcl.G1 {

	if uint64(len(X)+len(I)) > self.Q {
		panic(fmt.Sprintf("Wants to commit %d, but the accumulator supports only %d", len(X)+len(I), self.Q))
	}
	complete := append(X, I...)
	accPoly := fft.PolyTree(complete)

	proofs := make([]mcl.G1, len(I))

	for i := 0; i < len(I); i++ {
		x := make([]mcl.Fr, 2)
		x[1].SetInt64(1)
		mcl.FrNeg(&x[0], &I[i]) // x will contain x - i
		quotient, remainder := fft.PolyDiv(accPoly, x)
		if remainder[0].IsZero() == false {
			panic(fmt.Sprintf("Not sure why polynomial division does not return zero."))
		}
		mcl.G1MulVec(&proofs[i], self.PK[:len(quotient)], quotient)
	}
	return proofs
}

func (self *BpAcc) MemVerifySingle(digest mcl.G1, I mcl.Fr, proof mcl.G1) bool {

	// Compute h^{s - i}
	var h1 mcl.G2
	mcl.G2Mul(&h1, &self.VK[0], &I)
	mcl.G2Sub(&h1, &self.VK[1], &h1)

	P := []mcl.G1{digest, proof}
	Q := []mcl.G2{self.Hneg, h1}

	var e mcl.GT
	mcl.MillerLoopVec(&e, P, Q)
	mcl.FinalExp(&e, &e)

	return e.IsOne()
	// return MultiPairing2(digest, self.H, proof, h1)
}

// Takes two disjoint sets as inputs: X and I
// Return proof of nonmembership for all elements in I
// Compute Subproduct tree from the roots |X|log^2|X|
// Computes |I| xGCD
// Computes |I| multi-exp each of size |I| - 1
func (self *BpAcc) NonMemProve(X []mcl.Fr, I []mcl.Fr) []NonMemProof {

	if uint64(len(X)) > self.Q {
		panic(fmt.Sprintf("Wants to commit %d, but the accumulator supports only %d", len(X), self.Q))
	}

	accPoly := fft.PolyTree(X)

	proofs := make([]NonMemProof, len(I))

	for i := 0; i < len(I); i++ {
		x := make([]mcl.Fr, 2)
		mcl.FrNeg(&x[0], &I[i])
		x[1].SetInt64(1)

		g, alpha, beta := fft.XGCD(accPoly, x)

		// Make sure that ax + by = g = 1
		alpha, _ = fft.PolyDiv(alpha, g)
		beta, _ = fft.PolyDiv(beta, g)
		g, _ = fft.PolyDiv(g, g)

		if len(alpha) != 1 {
			panic(fmt.Sprintf("Not sure why len(alpha) != 1"))
		}
		if g[0].IsOne() == false {
			panic(fmt.Sprintf("Not sure why GCD != 1. %s", g[0].GetString(10)))
		}

		pi := NonMemProof{}
		pi.Alpha = alpha[0] // Since alpha contains only the const, alpha[0] is saved in pi.Alpha

		mcl.G1MulVec(&pi.Beta, self.PK[:len(beta)], beta)
		proofs[i] = pi
	}
	return proofs
}

func (self *BpAcc) NonMemVerifySingle(digest mcl.G1, y mcl.Fr, pi *NonMemProof) bool {

	var g1 mcl.G1

	mcl.G1Mul(&g1, &digest, &pi.Alpha)

	var h2 mcl.G2

	mcl.G2Mul(&h2, &self.VK[0], &y)
	mcl.G2Sub(&h2, &self.VK[1], &h2)

	P := []mcl.G1{g1, pi.Beta}
	Q := []mcl.G2{self.VK[0], h2}

	var e5 mcl.GT
	mcl.MillerLoopVec(&e5, P, Q)
	mcl.FinalExp(&e5, &e5)

	return e5.IsEqual(&self.IdGT)
}

// Takes |I| elements and its membership proofs
// Returns the aggergate for set I
// Compute subproduct tree |I|log^2|I|
// Compute differentiation |I|
// Compute PolyMultiEvaluate |I|log^2|I|
// Compute |I| FrInv
// Compute |I| multi-exp
func (self *BpAcc) AggMemProve(I []mcl.Fr, proofs []mcl.G1) (mcl.G1, []mcl.Fr) {

	subProdTree := fft.SubProductTree(I)
	IPrime := fft.PolyDifferentiate(subProdTree[len(subProdTree)-1][0])

	evaluations := fft.PolyMultiEvaluate(IPrime, subProdTree)
	evaluations = FrInvVec(evaluations)
	var proof mcl.G1
	mcl.G1MulVec(&proof, proofs, evaluations)
	return proof, subProdTree[len(subProdTree)-1][0]
}

func (self *BpAcc) AggMemVerify(digest mcl.G1, I []mcl.Fr, proof mcl.G1) bool {

	accPoly := fft.PolyTree(I)

	var h1 mcl.G2
	mcl.G2MulVec(&h1, self.VK[:len(accPoly)], accPoly)

	P := []mcl.G1{digest, proof}
	Q := []mcl.G2{self.Hneg, h1}

	var e mcl.GT
	mcl.MillerLoopVec(&e, P, Q)
	mcl.FinalExp(&e, &e)

	return e.IsOne()
}

func (self *BpAcc) AggMemProvePoE(digest mcl.G1, I []mcl.Fr, proofs []mcl.G1) (mcl.G1, mcl.G1, mcl.G2, []mcl.Fr) {
	proof, I_s := self.AggMemProve(I, proofs)
	Q1, Q2 := self.NiPoEProveG1(digest, proof, I_s)
	return proof, Q1, Q2, I_s
}

func (self *BpAcc) AggMemVerifyPoE(digest mcl.G1, I []mcl.Fr, proof mcl.G1, Q1 mcl.G1, Q2 mcl.G2) bool {
	I_s := fft.PolyTree(I)
	return self.NiPoEVerifyG1(Q1, Q2, digest, proof, I_s)
}

// Takes |I| elements and its nonmembership proofs
// Returns the aggergate for set I
// Compute subproduct tree |I|log^2|I|
// Compute differentiation |I|
// Compute PolyMultiEvaluate |I|log^2|I|
// Compute |I| FrInv
// Compute |I| long divisions
// 2 x Compute |I| scalar multiplications of size |I|
// Compute |I| G2 Multi-exp
func (self *BpAcc) AggNonMemProve(I []mcl.Fr, proofs []NonMemProof) (mcl.G2, mcl.G1, []mcl.Fr) {

	subProdTree := fft.SubProductTree(I)
	IPrime := fft.PolyDifferentiate(subProdTree[len(subProdTree)-1][0])

	bezouts := fft.PolyMultiEvaluate(IPrime, subProdTree)
	bezouts = FrInvVec(bezouts)

	var Y_i []mcl.Fr
	var hY mcl.G2

	var alpha mcl.G2
	var beta mcl.G1

	for i := 0; i < len(I); i++ {
		x := make([]mcl.Fr, 2)
		mcl.FrNeg(&x[0], &I[i])
		x[1].SetInt64(1)

		Y_i, _ = fft.PolyDiv(subProdTree[len(subProdTree)-1][0], x)
		Y_i = PolyMulScalar(Y_i, &bezouts[i])
		Y_i = PolyMulScalar(Y_i, &proofs[i].Alpha)
		mcl.G2MulVec(&hY, self.VK[:len(Y_i)], Y_i)
		mcl.G2Add(&alpha, &alpha, &hY)

		var gB mcl.G1
		mcl.G1Mul(&gB, &proofs[i].Beta, &bezouts[i])
		mcl.G1Add(&beta, &beta, &gB)
	}

	return alpha, beta, subProdTree[len(subProdTree)-1][0]
}

func (self *BpAcc) AggNonMemVerify(digest mcl.G1, alphaOfS mcl.G2, betaOfS mcl.G1, I []mcl.Fr) bool {

	var h2 mcl.G2

	accPoly := fft.PolyTree(I)
	mcl.G2MulVec(&h2, self.VK[:len(accPoly)], accPoly)

	P := []mcl.G1{digest, betaOfS}
	Q := []mcl.G2{alphaOfS, h2}

	var e5 mcl.GT
	mcl.MillerLoopVec(&e5, P, Q)
	mcl.FinalExp(&e5, &e5)

	return e5.IsEqual(&self.IdGT)
}

func (self *BpAcc) AggNonMemProvePoE(I []mcl.Fr, proofs []NonMemProof) (mcl.G2, mcl.G1, mcl.G1, mcl.G1, mcl.G2, []mcl.Fr) {
	alpha, beta, I_s := self.AggNonMemProve(I, proofs)
	var w mcl.G2
	mcl.G2MulVec(&w, self.VK[:len(I_s)], I_s)
	Q1, Q2 := self.NiPoEProveG2(w, self.H, I_s)
	return alpha, beta, Q1, Q2, w, I_s
}

func (self *BpAcc) AggNonMemVerifyPoE(digest mcl.G1, alphaOfS mcl.G2, betaOfS mcl.G1,
	Q1 mcl.G1, Q2 mcl.G1, w mcl.G2, I []mcl.Fr) bool {

	I_s := fft.PolyTree(I)
	var status bool
	status = self.NiPoEVerifyG2(Q1, Q2, w, self.H, I_s)

	P := []mcl.G1{digest, betaOfS}
	Q := []mcl.G2{alphaOfS, w}

	var e5 mcl.GT
	mcl.MillerLoopVec(&e5, P, Q)
	mcl.FinalExp(&e5, &e5)

	return status && e5.IsEqual(&self.IdGT)
}
