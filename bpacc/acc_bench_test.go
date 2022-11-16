package bpacc

import (
	"fmt"
	"testing"

	"github.com/alinush/go-mcl"
)

type AggNonMemProof struct {
	alpha mcl.G2
	beta  mcl.G1
}

func BenchmarkAccumulator(b *testing.B) {

	ell := []uint64{8}

	var acc BpAcc
	acc.KeyGenLoad(8, ell[len(ell)-1], "xyz", "../pkvk-21")

	var data []mcl.Fr
	var digest_XI mcl.G1 // Digest of the entire accumulator
	var digest_X mcl.G1  // Digest of the partial accumulator

	var memProofs_I []mcl.G1
	var nonmemProofs_I []NonMemProof
	var aggMemProof mcl.G1

	var X, I []mcl.Fr

	var set_size uint64
	max_set_size := uint64(1) << ell[len(ell)-1]
	elements := PopulateRandom(max_set_size)

	for _, i := range ell {
		set_size = uint64(1) << i
		batch_size := set_size / 2
		// log_set_size := i
		log_batch_size := i - 1
		data = elements[:set_size]
		X, I = data[:batch_size], data[batch_size:set_size]
		digest_XI, _ = acc.CommitFakeG1(data)
		fmt.Println("Done with commit (1/2).")

		digest_X, _ = acc.CommitFakeG1(X)
		fmt.Println("Done with commit (2/2).")

		memProofs_I = acc.ProveMemFake(X, I)
		fmt.Println("Generated Membership.")

		nonmemProofs_I = acc.ProveNonMemFake(X, I)
		fmt.Println("Generated Non-Membership.")

		b.Run(fmt.Sprintf("AggMemProve;2^%d", log_batch_size), func(t *testing.B) {
			t.ResetTimer()
			for j := 0; j < t.N; j++ {
				aggMemProof, _ = acc.AggMemProve(I, memProofs_I)
			}
		})

		b.Run(fmt.Sprintf("AggMemVerify;2^%d", log_batch_size), func(t *testing.B) {
			var status bool
			t.ResetTimer()
			for j := 0; j < t.N; j++ {
				status = acc.AggMemVerify(digest_XI, I, aggMemProof)
				if status == false {
					b.Errorf("AggMemVerify: Unexpected verification failed.")
				}
			}
		})

		var Q1 mcl.G1
		var Q2 mcl.G2
		b.Run(fmt.Sprintf("AggMemProvePoE;2^%d", log_batch_size), func(t *testing.B) {
			t.ResetTimer()
			for j := 0; j < t.N; j++ {
				_, Q1, Q2, _ = acc.AggMemProvePoE(digest_XI, I, memProofs_I)
			}
		})

		b.Run(fmt.Sprintf("AggMemVerifyPoE;2^%d", log_batch_size), func(t *testing.B) {
			var status bool
			t.ResetTimer()
			for j := 0; j < t.N; j++ {
				status = acc.AggMemVerifyPoE(digest_XI, I, aggMemProof, Q1, Q2)
				if status == false {
					b.Errorf("AggMemVerifyPoE: Unexpected verification failed.")
				}
			}
		})

		if i < 15 {
			var alpha mcl.G2
			var beta mcl.G1
			var Q1 mcl.G1
			var Q2 mcl.G1
			var w mcl.G2
			b.Run(fmt.Sprintf("AggNonMemProvePoE;2^%d", log_batch_size), func(t *testing.B) {
				t.ResetTimer()
				for j := 0; j < t.N; j++ {
					alpha, beta, Q1, Q2, w, _ = acc.AggNonMemProvePoE(I, nonmemProofs_I)
				}
			})

			b.Run(fmt.Sprintf("AggNonMemVerifyPoE;2^%d", log_batch_size), func(t *testing.B) {
				var status bool
				t.ResetTimer()
				for j := 0; j < t.N; j++ {
					status = acc.AggNonMemVerifyPoE(digest_X, alpha, beta, Q1, Q2, w, I)
					if status == false {
						b.Errorf("AggNonMemVerifyPoE: Unexpected verification failed.")
					}
				}
			})
			var aggNonMemProof AggNonMemProof
			b.Run(fmt.Sprintf("AggNonMemProve;2^%d", log_batch_size), func(t *testing.B) {
				t.ResetTimer()
				for j := 0; j < t.N; j++ {
					alpha, beta, _ := acc.AggNonMemProve(I, nonmemProofs_I)
					aggNonMemProof = AggNonMemProof{alpha, beta}
				}
			})

			b.Run(fmt.Sprintf("AggNonMemVerify;2^%d", log_batch_size), func(t *testing.B) {
				var status bool
				t.ResetTimer()
				for j := 0; j < t.N; j++ {
					status = acc.AggNonMemVerify(digest_X, aggNonMemProof.alpha, aggNonMemProof.beta, I)
					if status == false {
						b.Errorf("AggNonMemVerify: Unexpected verification failed.")
					}
				}
			})
		}

		b.Run(fmt.Sprintf("Commit;%d", log_batch_size), func(t *testing.B) {
			t.ResetTimer()
			for j := 0; j < t.N; j++ {
				digest_X, _ = acc.Commit(X)
			}
		})

		b.Run(fmt.Sprintf("MemVerify;2^%d", log_batch_size), func(t *testing.B) {
			var status bool
			t.ResetTimer()
			for j := 0; j < t.N; j++ {
				for k := range I {
					status = acc.MemVerifySingle(digest_XI, I[k], memProofs_I[k])
					if status == false {
						b.Errorf("MemVerify: Unexpected verification failed.")
					}
				}
			}
		})

		b.Run(fmt.Sprintf("NonMemVerify;2^%d", log_batch_size), func(t *testing.B) {
			var status bool
			t.ResetTimer()
			for j := 0; j < t.N; j++ {
				for k := range I {
					status = acc.NonMemVerifySingle(digest_X, I[k], &nonmemProofs_I[k])
					if status == false {
						b.Errorf("NonMemVerify: Unexpected verification failed.")
					}
				}
			}
		})
	}
}
