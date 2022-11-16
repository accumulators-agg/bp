package bpacc

import (
	"testing"

	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
)

func TestMemProveVerify(t *testing.T) {

	l := uint64(8)
	var acc BpAcc
	acc.Setup(l, "xyz")
	n := uint64(1 << l)
	elements := PopulateRandom(n)
	digest, _ := acc.Commit(elements)

	X, I := elements[:n/2], elements[n/2:]
	proofs := acc.MemProve(X, I)

	status := true
	for k := range I {
		status = acc.MemVerifySingle(digest, I[k], proofs[k])
		if status == false {
			t.Errorf("Proof did not verify %d", k)
			break
		}
	}
}

func TestMemAggProveVerify(t *testing.T) {

	l := uint64(8)
	var acc BpAcc
	acc.Setup(l, "xyz")
	n := uint64(1 << 4)
	elements := PopulateRandom(n)

	X, I := elements[:n/2], elements[n/2:]
	digest, _ := acc.Commit(elements)
	proofs := acc.MemProve(X, I)

	proof, _ := acc.AggMemProve(I, proofs)

	status := acc.AggMemVerify(digest, I, proof)

	if status == false {
		t.Errorf("Aggregated membership proof verification failed.")
	}
}

func TestNonMemProveVerify(t *testing.T) {

	l := uint64(8)
	var acc BpAcc
	acc.Setup(l, "xyz")
	n := uint64(1 << 4)
	elements := PopulateRandom(n)

	X, I := elements[:n/2], elements[n/2:]
	digest, _ := acc.Commit(X)

	proofs := acc.NonMemProve(X, I)

	status := true
	for k := range I {
		status = acc.NonMemVerifySingle(digest, I[k], &proofs[k])
		if status == false {
			t.Errorf("Proof did not verify %d", k)
			break
		}
	}
}

func TestNonMemAggProveVerify(t *testing.T) {

	l := uint64(8)
	var acc BpAcc
	acc.Setup(l, "xyz")
	n := uint64(1 << 4)
	elements := PopulateRandom(n)

	X, I := elements[:n/2], elements[n/2:]
	digest, _ := acc.Commit(X)
	proofs := acc.NonMemProve(X, I)

	alphaOfS, betaOfS, _ := acc.AggNonMemProve(I, proofs)

	status := acc.AggNonMemVerify(digest, alphaOfS, betaOfS, I)

	if status == false {
		t.Errorf("Aggregated non-membership proof verification failed.")
	}
}

func TestPoEG2ProveVerify(t *testing.T) {

	l := uint64(8)
	var acc BpAcc
	acc.Setup(l, "xyz")
	n := uint64(1 << 6)
	elements := PopulateRandom(n)
	v := fft.PolyTree(elements)

	var w mcl.G2
	mcl.G2MulVec(&w, acc.VK[:len(v)], v)

	Q1, Q2 := acc.NiPoEProveG2(w, acc.H, v)
	status := acc.NiPoEVerifyG2(Q1, Q2, w, acc.H, v)

	if status == false {
		t.Errorf("PoE-G2: Proof verification failed.")
	}
}

func TestPoEG1ProveVerify(t *testing.T) {

	l := uint64(8)
	var acc BpAcc
	acc.Setup(l, "xyz")
	n := uint64(1 << 6)
	elements := PopulateRandom(n)
	v := fft.PolyTree(elements)

	var w mcl.G1
	mcl.G1MulVec(&w, acc.PK[:len(v)], v)

	Q1, Q2 := acc.NiPoEProveG1(w, acc.G, v)
	status := acc.NiPoEVerifyG1(Q1, Q2, w, acc.G, v)

	if status == false {
		t.Errorf("PoE-G1: Proof verification failed.")
	}
}

func TestNonMemBatchProveVerify(t *testing.T) {

	l := uint64(8)
	var acc BpAcc
	acc.Setup(l, "xyz")
	n := uint64(1 << 4)
	elements := PopulateRandom(n)

	X, I := elements[:n/2], elements[n/2:]
	digest, _ := acc.CommitFakeG1(X)

	alpha2, beta2 := acc.ProveBatchNonMemFake(X, I)

	status := acc.AggNonMemVerify(digest, alpha2, beta2, I)

	if status == false {
		t.Errorf("Batched non-membership proof verification failed.")
	}
}
