package bpacc

import (
	"github.com/alinush/go-mcl"
)

func (self *BpAcc) ZKNonMemProver(digest mcl.G1, C_I PedG2, A mcl.G2, B mcl.G1, transcript [32]byte) zkNonMemProof {

	var proof zkNonMemProof
	proof.Setup()

	var tau []mcl.Fr
	tau = make([]mcl.Fr, 4)
	for i := range tau {
		tau[i].Random()
	}

	var delta_3, delta_4 mcl.Fr

	mcl.FrMul(&delta_3, &tau[2], &C_I.R)
	mcl.FrMul(&delta_4, &tau[3], &C_I.R)

	var bG1 mcl.G1
	var bG2 mcl.G2

	mcl.G2MulVec(&proof.A_bar[0], []mcl.G2{self.H, self.B[0]}, []mcl.Fr{tau[0], tau[1]})

	mcl.G2Mul(&bG2, &self.B[0], &tau[0])
	mcl.G2Add(&proof.A_bar[1], &A, &bG2)

	mcl.G1MulVec(&proof.B_bar[0], []mcl.G1{self.G, self.A[0]}, []mcl.Fr{tau[2], tau[3]})

	mcl.G1Mul(&bG1, &self.A[0], &tau[2])
	mcl.G1Add(&proof.B_bar[1], &B, &bG1)

	var r_r mcl.Fr
	var r_tau []mcl.Fr
	var r_delta_3, r_delta_4 mcl.Fr
	r_tau = make([]mcl.Fr, 4)

	r_r.Random()
	for i := range r_tau {
		r_tau[i].Random()
	}
	r_delta_3.Random()
	r_delta_4.Random()

	mcl.G2MulVec(&proof.R_1, []mcl.G2{self.H, self.B[0]}, []mcl.Fr{r_tau[0], r_tau[1]})

	mcl.G1MulVec(&proof.R_2[0], []mcl.G1{self.G, self.A[0]}, []mcl.Fr{r_tau[2], r_tau[3]})

	var neg_r_delta_3, neg_r_delta_4 mcl.Fr
	mcl.FrNeg(&neg_r_delta_3, &r_delta_3)
	mcl.FrNeg(&neg_r_delta_4, &r_delta_4)

	mcl.G1MulVec(&proof.R_2[1], []mcl.G1{proof.B_bar[0], self.G, self.A[0]}, []mcl.Fr{r_r, neg_r_delta_3, neg_r_delta_4})

	P := make([]mcl.G1, 4)
	mcl.G1Mul(&P[0], &digest, &r_tau[0])
	mcl.G1Mul(&P[1], &self.A[0], &r_tau[2])
	mcl.G1Mul(&P[2], &self.A[0], &neg_r_delta_3)
	mcl.G1Mul(&P[3], &proof.B_bar[1], &r_r)
	Q := []mcl.G2{self.B[0], C_I.Com, self.PedVK[0], self.PedVK[0]}

	mcl.MillerLoopVec(&proof.R_3, P, Q)
	mcl.FinalExp(&proof.R_3, &proof.R_3)

	var c mcl.Fr
	c.SetHashOf(proof.FiatShamir(transcript))

	mcl.FrMul(&proof.s_r, &c, &C_I.R)
	mcl.FrMul(&proof.s_tau[0], &c, &tau[0])
	mcl.FrMul(&proof.s_tau[1], &c, &tau[1])
	mcl.FrMul(&proof.s_tau[2], &c, &tau[2])
	mcl.FrMul(&proof.s_tau[3], &c, &tau[3])
	mcl.FrMul(&proof.s_delta_3, &c, &delta_3)
	mcl.FrMul(&proof.s_delta_4, &c, &delta_4)

	mcl.FrAdd(&proof.s_r, &proof.s_r, &r_r)
	mcl.FrAdd(&proof.s_tau[0], &proof.s_tau[0], &r_tau[0])
	mcl.FrAdd(&proof.s_tau[1], &proof.s_tau[1], &r_tau[1])
	mcl.FrAdd(&proof.s_tau[2], &proof.s_tau[2], &r_tau[2])
	mcl.FrAdd(&proof.s_tau[3], &proof.s_tau[3], &r_tau[3])
	mcl.FrAdd(&proof.s_delta_3, &proof.s_delta_3, &r_delta_3)
	mcl.FrAdd(&proof.s_delta_4, &proof.s_delta_4, &r_delta_4)

	return proof

}

func (self *BpAcc) ZKNonMemVerifier(proof zkNonMemProof, digest mcl.G1, C_I mcl.G2, transcript [32]byte) bool {

	var status bool
	status = true

	var c, neg_c mcl.Fr
	c.SetHashOf(proof.FiatShamir(transcript))
	mcl.FrNeg(&neg_c, &c)

	var R_1 mcl.G2
	// Check R_1
	mcl.G2MulVec(&R_1, []mcl.G2{proof.A_bar[0], self.H, self.B[0]}, []mcl.Fr{neg_c, proof.s_tau[0], proof.s_tau[1]})
	status = status && R_1.IsEqual(&proof.R_1)

	var neg_s_delta_3, neg_s_delta_4 mcl.Fr
	mcl.FrNeg(&neg_s_delta_3, &proof.s_delta_3)
	mcl.FrNeg(&neg_s_delta_4, &proof.s_delta_4)

	var R_2 mcl.G1
	// Check R_2_1
	mcl.G1MulVec(&R_2, []mcl.G1{proof.B_bar[0], self.G, self.A[0]}, []mcl.Fr{neg_c, proof.s_tau[2], proof.s_tau[3]})
	status = status && R_2.IsEqual(&proof.R_2[0])

	// Check R_2_2
	mcl.G1MulVec(&R_2, []mcl.G1{proof.B_bar[0], self.G, self.A[0]}, []mcl.Fr{proof.s_r, neg_s_delta_3, neg_s_delta_4})

	status = status && R_2.IsEqual(&proof.R_2[1])

	var R_3 mcl.GT

	P := make([]mcl.G1, 7)
	mcl.G1Mul(&P[0], &digest, &proof.s_tau[0])
	mcl.G1Mul(&P[1], &self.A[0], &proof.s_tau[2])
	mcl.G1Mul(&P[2], &self.A[0], &neg_s_delta_3)
	mcl.G1Mul(&P[3], &proof.B_bar[1], &proof.s_r)
	mcl.G1Mul(&P[4], &digest, &neg_c)
	mcl.G1Mul(&P[5], &proof.B_bar[1], &neg_c)
	mcl.G1Mul(&P[6], &self.G, &c)

	Q := []mcl.G2{self.B[0], C_I, self.PedVK[0], self.PedVK[0], proof.A_bar[1], C_I, self.H}

	mcl.MillerLoopVec(&R_3, P, Q)
	mcl.FinalExp(&R_3, &R_3)

	status = status && proof.R_3.IsEqual(&R_3)

	return status
}
