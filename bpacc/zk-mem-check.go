package bpacc

import (
	"github.com/alinush/go-mcl"
)

func (self *BpAcc) ZKMemProver(C_I PedG2, Pi_I mcl.G1, transcript [32]byte) zkMemProof {

	var proof zkMemProof
	var tau_1, tau_2 mcl.Fr

	tau_1.Random()
	tau_2.Random()

	var delta_1, delta_2 mcl.Fr
	mcl.FrMul(&delta_1, &C_I.R, &tau_1)
	mcl.FrMul(&delta_2, &C_I.R, &tau_2)

	var aG1, bG1, cG1 mcl.G1

	mcl.G1MulVec(&proof.Pi_I_1, []mcl.G1{self.G, self.A[0]}, []mcl.Fr{tau_1, tau_2})

	mcl.G1Mul(&aG1, &self.A[0], &tau_1)
	mcl.G1Add(&proof.Pi_I_2, &aG1, &Pi_I)

	var r_r, r_tau_1, r_tau_2, r_delta_1, r_delta_2 mcl.Fr
	r_r.Random()
	r_tau_1.Random()
	r_tau_2.Random()
	r_delta_1.Random()
	r_delta_2.Random()

	var neg_r_delta_1, neg_r_delta_2 mcl.Fr
	mcl.FrNeg(&neg_r_delta_1, &r_delta_1)
	mcl.FrNeg(&neg_r_delta_2, &r_delta_2)

	mcl.G1MulVec(&proof.R_1, []mcl.G1{self.G, self.A[0]}, []mcl.Fr{r_tau_1, r_tau_2})
	mcl.G1MulVec(&proof.R_2, []mcl.G1{proof.Pi_I_1, self.G, self.A[0]}, []mcl.Fr{r_r, neg_r_delta_1, neg_r_delta_2})

	mcl.G1Mul(&aG1, &self.A[0], &r_tau_1)
	mcl.G1Mul(&bG1, &self.A[0], &neg_r_delta_1)
	mcl.G1Mul(&cG1, &proof.Pi_I_2, &r_r)

	mcl.MillerLoopVec(&proof.R_3, []mcl.G1{aG1, bG1, cG1}, []mcl.G2{C_I.Com, self.PedVK[0], self.PedVK[0]})
	mcl.FinalExp(&proof.R_3, &proof.R_3)

	var c mcl.Fr
	c.SetHashOf(proof.FiatShamir(transcript))

	mcl.FrMul(&proof.s_r, &c, &C_I.R)
	mcl.FrMul(&proof.s_tau_1, &c, &tau_1)
	mcl.FrMul(&proof.s_tau_2, &c, &tau_2)
	mcl.FrMul(&proof.s_delta_1, &c, &delta_1)
	mcl.FrMul(&proof.s_delta_2, &c, &delta_2)

	mcl.FrAdd(&proof.s_r, &proof.s_r, &r_r)
	mcl.FrAdd(&proof.s_tau_1, &proof.s_tau_1, &r_tau_1)
	mcl.FrAdd(&proof.s_tau_2, &proof.s_tau_2, &r_tau_2)
	mcl.FrAdd(&proof.s_delta_1, &proof.s_delta_1, &r_delta_1)
	mcl.FrAdd(&proof.s_delta_2, &proof.s_delta_2, &r_delta_2)

	return proof
}

func (self *BpAcc) ZKMemVerifier(proof zkMemProof, A_X mcl.G1, C_I mcl.G2, transcript [32]byte) bool {

	var status bool
	status = true

	var c, neg_c mcl.Fr
	c.SetHashOf(proof.FiatShamir(transcript))
	mcl.FrNeg(&neg_c, &c)

	var R_1 mcl.G1
	// Check R1
	mcl.G1MulVec(&R_1, []mcl.G1{proof.Pi_I_1, self.G, self.A[0]}, []mcl.Fr{neg_c, proof.s_tau_1, proof.s_tau_2})

	status = status && R_1.IsEqual(&proof.R_1)

	var neg_s_delta_1, neg_s_delta_2 mcl.Fr
	mcl.FrNeg(&neg_s_delta_1, &proof.s_delta_1)
	mcl.FrNeg(&neg_s_delta_2, &proof.s_delta_2)

	// Check R2
	var R_2 mcl.G1
	mcl.G1MulVec(&R_2, []mcl.G1{proof.Pi_I_1, self.G, self.A[0]}, []mcl.Fr{proof.s_r, neg_s_delta_1, neg_s_delta_2})

	status = status && R_2.IsEqual(&proof.R_2)

	var R_3 mcl.GT
	A := make([]mcl.G1, 5)
	B := make([]mcl.G2, 5)
	// Check R3
	mcl.G1Mul(&A[0], &self.A[0], &proof.s_tau_1)
	mcl.G1Mul(&A[1], &self.A[0], &neg_s_delta_1)
	mcl.G1Mul(&A[2], &proof.Pi_I_2, &proof.s_r)
	mcl.G1Mul(&A[3], &proof.Pi_I_2, &neg_c)
	mcl.G1Mul(&A[4], &A_X, &c)
	B = []mcl.G2{C_I, self.PedVK[0], self.PedVK[0], C_I, self.H}

	mcl.MillerLoopVec(&R_3, A, B)
	mcl.FinalExp(&R_3, &R_3)
	status = status && R_3.IsEqual(&proof.R_3)

	return status
}
