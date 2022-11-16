package bpacc

import (
	"fmt"
	"testing"

	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
)

func TestZKDegCheck(t *testing.T) {
	ell := []uint64{5}

	var n uint64
	n = uint64(1) << ell[len(ell)-1]
	elements := PopulateRandom(n)

	var acc BpAcc
	acc.KeyGenLoad(8, ell[len(ell)-1], "xyz", "../pkvk-21")

	var data []mcl.Fr
	var digest_XI mcl.G1 // Digest of the entire accumulator
	var digest_X mcl.G1  // Digest of the partial accumulator

	var memProofs_I []mcl.G1
	var X, I []mcl.Fr

	for _, i := range ell {

		n = uint64(1) << i
		data = elements[:n]
		X, I = data[:n/2], data[n/2:n]
		digest_XI, _ = acc.CommitFakeG1(data)
		fmt.Println("Done with commit (1/2).")

		digest_X, _ = acc.CommitFakeG1(X) // This is also the batch proof of set I
		fmt.Println("Done with commit (2/2).")

		memProofs_I = acc.ProveMemFake(X, I)
		batchProof_I := digest_X
		fmt.Println("Generated Membership.")

		t.Run(fmt.Sprintf("DegCheck"), func(t *testing.T) {
			transcript := [32]byte{}

			var random mcl.Fr
			random.Random()

			accPoly := fft.PolyTree(I)
			C_I := PedG2{acc.PedersenG2(accPoly, acc.VK, random, acc.PedVK[0]), random}

			var proof ZKDegCheckProof
			proof = acc.ZKDegCheckProver(C_I, accPoly, transcript)
			status := acc.ZKDegCheckVerifier(C_I.Com, proof, transcript)
			if status == false {
				t.Errorf("Degree check did not verify %d", i)
			}
		})
		fmt.Println(digest_XI.IsZero(), digest_X.IsZero(), len(memProofs_I), batchProof_I.IsZero())
	}
}

func TestZKAccMem(t *testing.T) {
	ell := []uint64{5}

	var n uint64
	n = uint64(1) << ell[len(ell)-1]
	elements := PopulateRandom(n)

	var acc BpAcc
	acc.KeyGenLoad(8, ell[len(ell)-1], "xyz", "../pkvk-21")

	var data []mcl.Fr
	var digest_XI mcl.G1 // Digest of the entire accumulator
	var digest_X mcl.G1  // Digest of the partial accumulator

	var X, I []mcl.Fr

	for _, i := range ell {

		n = uint64(1) << i
		data = elements[:n]
		X, I = data[:n/2], data[n/2:n]
		digest_XI, _ = acc.CommitFakeG1(data)
		fmt.Println("Done with commit (1/2).")

		digest_X, _ = acc.CommitFakeG1(X) // This is also the batch proof of set I
		fmt.Println("Done with commit (2/2).")

		batchProof_I := digest_X
		fmt.Println("Generated Membership.")

		t.Run(fmt.Sprintf("MemCheck"), func(t *testing.T) {
			transcript := [32]byte{}

			var random mcl.Fr
			random.Random()

			accPoly := fft.PolyTree(I)
			C_I := PedG2{acc.PedersenG2(accPoly, acc.VK, random, acc.PedVK[0]), random}

			var proof zkMemProof
			proof = acc.ZKMemProver(C_I, batchProof_I, transcript)
			status := acc.ZKMemVerifier(proof, digest_XI, C_I.Com, transcript)
			if status == false {
				t.Errorf("Degree check did not verify %d", i)
			}
		})
	}
}

func TestZKAccNonMem(t *testing.T) {
	ell := []uint64{5}

	var n uint64
	n = uint64(1) << ell[len(ell)-1]
	elements := PopulateRandom(n)

	var acc BpAcc
	acc.KeyGenLoad(8, ell[len(ell)-1], "xyz", "../pkvk-21")

	var data []mcl.Fr
	var digest_X mcl.G1 // Digest of the partial accumulator

	var X, I []mcl.Fr

	for _, i := range ell {

		n = uint64(1) << i
		data = elements[:n]
		X, I = data[:n/2], data[n/2:n]

		digest_X, _ = acc.CommitFakeG1(X) // This is also the batch proof of set I
		fmt.Println("Done with commit (1/1).")

		fmt.Println("Generated Batch Non-Membership.")

		t.Run(fmt.Sprintf("NonMemCheck"), func(t *testing.T) {
			transcript := [32]byte{}

			var random mcl.Fr
			random.Random()

			accPoly := fft.PolyTree(I)
			C_I := PedG2{acc.PedersenG2(accPoly, acc.VK, random, acc.PedVK[0]), random}

			A, B := acc.ProveBatchNonMemFake(X, I)

			var proof zkNonMemProof
			proof = acc.ZKNonMemProver(digest_X, C_I, A, B, transcript)
			status := acc.ZKNonMemVerifier(proof, digest_X, C_I.Com, transcript)
			if status == false {
				t.Errorf("Degree check did not verify %d", i)
			}
		})
	}
}
