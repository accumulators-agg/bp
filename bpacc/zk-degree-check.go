package bpacc

import (
	"encoding/binary"
	"fmt"

	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
)

func (self *BpAcc) ZKDegCheckElementsProver(C_I PedG2, elements []mcl.Fr, transcript [32]byte) ZKDegCheckProof {

	if uint64(len(elements)) > self.Q {
		panic(fmt.Sprintf("Wants to commit %d, but the accumulator supports only %d", len(elements), self.Q))
	}
	// Build the polynomial from the factors
	accPoly := fft.PolyTree(elements)

	fmt.Println("After PolyTree", len(accPoly))

	return self.ZKDegCheckProver(C_I, accPoly, transcript)
}

// Takes the polynomial I(x), rather than computing I(x) from I
func (self *BpAcc) ZKDegCheckProver(C_I PedG2, accPoly []mcl.Fr, transcript [32]byte) ZKDegCheckProof {

	var proof ZKDegCheckProof
	// Actual degree of the polynomial
	proof.D = uint64(len(accPoly)) - 1

	// Remove the highest degree coefficient
	accPoly = accPoly[:len(accPoly)-1]

	mcl.G2Sub(&proof.C_f, &C_I.Com, &self.VK[proof.D])

	// Fiat-Shamir
	var c mcl.Fr
	c.SetHashOf(proof.FiatShamir(transcript))

	accPolyCopy := make([]mcl.Fr, len(accPoly))
	for i := range accPoly {
		mcl.FrMul(&accPolyCopy[i], &accPoly[i], &c)
	}

	var zeros []mcl.Fr
	zeros = make([]mcl.Fr, self.Q-proof.D+1)
	accPolyCopy = append(zeros, accPolyCopy...)

	var rc mcl.Fr
	mcl.FrMul(&rc, &C_I.R, &c)

	C := self.PedersenG2(accPolyCopy, self.VK, rc, self.PedVK[self.Q-proof.D+1])
	Ca := self.PedersenG2(accPolyCopy, self.VKAlpha, rc, self.PedVKAlpha[self.Q-proof.D+1])

	proof.C = C
	proof.Ca = Ca
	return proof
}

func (self *BpAcc) ZKDegCheckVerifier(C_I mcl.G2, proof ZKDegCheckProof, transcript [32]byte) bool {

	status := true
	d_byte := make([]byte, 8)
	binary.LittleEndian.PutUint64(d_byte, proof.D)

	var c mcl.Fr
	c.SetHashOf(proof.FiatShamir(transcript))

	var tempG1 mcl.G1
	var tempG2 mcl.G2

	mcl.G2Add(&tempG2, &proof.C_f, &self.VK[proof.D])
	status = status && MultiPairing2(self.G, C_I, self.G, tempG2)

	mcl.G1Mul(&tempG1, &self.PK[self.Q-proof.D+1], &c)
	status = status && MultiPairing2(self.G, proof.C, tempG1, proof.C_f)

	status = status && MultiPairing2(self.G, proof.Ca, self.PKAlpha[0], proof.C)

	return status
}
