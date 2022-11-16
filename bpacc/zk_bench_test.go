package bpacc

import (
	"fmt"
	"testing"

	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
)

func BenchmarkZKAcc(b *testing.B) {

	ell := []uint64{10, 12, 14, 16}

	var n uint64
	n = uint64(1) << ell[len(ell)-1]
	elements := PopulateRandom(n)

	var acc BpAcc
	acc.KeyGenLoad(8, ell[len(ell)-1], "xyz", "../pkvk-21")

	var data []mcl.Fr
	var digest_XI mcl.G1 // Digest of the entire accumulator
	var digest_X mcl.G1  // Digest of the partial accumulator

	var X, I []mcl.Fr
	var random mcl.Fr
	var status bool

	var zk_mem_proof e2eMemProof
	var zk_mem_proofs []e2eMemProof

	var zk_non_mem_proof e2eNonMemProof
	var zk_non_mem_proofs []e2eNonMemProof

	var zkDegCheckProof ZKDegCheckProof
	var zkDegCheckProofs []ZKDegCheckProof

	var memProof zkMemProof
	var memProofs []zkMemProof

	var nonMemProof zkNonMemProof
	var nonMemProofs []zkNonMemProof

	for _, i := range ell {
		n = uint64(1) << i
		data = elements[:n]
		X, I = data[:n/2], data[n/2:n]

		digest_XI, _ = acc.CommitFakeG1(data)
		fmt.Println("Done with commit (1/2).")

		digest_X, _ = acc.CommitFakeG1(X) // This is also the batch proof of set I
		fmt.Println("Done with commit (2/2).")

		batchMemProof_I := digest_X
		fmt.Println("Generated Batch Membership.")

		A, B := acc.ProveBatchNonMemFake(X, I)
		fmt.Println("Generated Batch Non-Membership.")

		random.Random()
		I_x := fft.PolyTree(I)
		C_I := PedG2{acc.PedersenG2(I_x, acc.VK, random, acc.PedVK[0]), random}

		b.Run(fmt.Sprintf("ZkE2EMem/Prover;%02d", i-1), func(t *testing.B) {
			transcript := [32]byte{}
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {

				t.StartTimer()
				zk_mem_proof.zk_mem_proof = acc.ZKMemProver(C_I, batchMemProof_I, transcript)
				zk_mem_proof.zk_deg_proof = acc.ZKDegCheckProver(C_I, I_x, zk_mem_proof.zk_mem_proof.HashProof(transcript))
				//
				t.StopTimer()
				zk_mem_proofs = append(zk_mem_proofs, zk_mem_proof)
			}
		})

		b.Run(fmt.Sprintf("ZkE2EMem/Verifier;%02d", i-1), func(t *testing.B) {
			transcript := [32]byte{}
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {
				zk_mem_proof, zk_mem_proofs = zk_mem_proofs[0], zk_mem_proofs[1:]
				status = true
				t.StartTimer()
				status = status && acc.ZKMemVerifier(zk_mem_proof.zk_mem_proof, digest_XI, C_I.Com, transcript)
				status = status && acc.ZKDegCheckVerifier(C_I.Com, zk_mem_proof.zk_deg_proof, zk_mem_proof.zk_mem_proof.HashProof(transcript))
				t.StopTimer()
				if status == false {
					b.Errorf("Verifier-Mem failed")
				}
			}
		})

		b.Run(fmt.Sprintf("ZkE2ENonMem/Prover;%02d", i-1), func(t *testing.B) {

			transcript := [32]byte{}
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {
				t.StartTimer()
				zk_non_mem_proof.zk_non_mem_proof = acc.ZKNonMemProver(digest_X, C_I, A, B, transcript)
				zk_non_mem_proof.zk_deg_proof = acc.ZKDegCheckProver(C_I, I_x, zk_non_mem_proof.zk_non_mem_proof.HashProof(transcript))
				t.StopTimer()
				zk_non_mem_proofs = append(zk_non_mem_proofs, zk_non_mem_proof)
			}
		})

		b.Run(fmt.Sprintf("ZkE2ENonMem/Verifier;%02d", i-1), func(t *testing.B) {

			transcript := [32]byte{}
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {
				zk_non_mem_proof, zk_non_mem_proofs = zk_non_mem_proofs[0], zk_non_mem_proofs[1:]
				status = true
				t.StartTimer()
				status = status && acc.ZKNonMemVerifier(zk_non_mem_proof.zk_non_mem_proof, digest_X, C_I.Com, transcript)
				status = status && acc.ZKDegCheckVerifier(C_I.Com, zk_non_mem_proof.zk_deg_proof, zk_non_mem_proof.zk_non_mem_proof.HashProof(transcript))
				t.StopTimer()
				if status == false {
					b.Errorf("Verifier-NonMem failed")
				}
			}
		})

		b.Run(fmt.Sprintf("DegCheck/Prover;%02d", i-1), func(t *testing.B) {
			transcript := [32]byte{}
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {
				t.StartTimer()
				zkDegCheckProof = acc.ZKDegCheckProver(C_I, I_x, transcript)
				t.StopTimer()
				zkDegCheckProofs = append(zkDegCheckProofs, zkDegCheckProof)
			}
		})

		b.Run(fmt.Sprintf("DegCheck/Verifier;%02d", i-1), func(t *testing.B) {

			transcript := [32]byte{}
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {
				zkDegCheckProof, zkDegCheckProofs = zkDegCheckProofs[0], zkDegCheckProofs[1:]
				status = true
				t.StartTimer()
				status = status && acc.ZKDegCheckVerifier(C_I.Com, zkDegCheckProof, transcript)
				t.StopTimer()
				if status == false {
					b.Errorf("Verifier-DegCheck failed")
				}
			}
		})

		b.Run(fmt.Sprintf("PureMem/Prover;%02d", i-1), func(t *testing.B) {
			transcript := [32]byte{}
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {

				t.StartTimer()
				memProof = acc.ZKMemProver(C_I, batchMemProof_I, transcript)
				t.StopTimer()
				memProofs = append(memProofs, memProof)
			}
		})

		b.Run(fmt.Sprintf("PureMem/Verifier;%02d", i-1), func(t *testing.B) {
			transcript := [32]byte{}
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {
				memProof, memProofs = memProofs[0], memProofs[1:]
				status = true
				t.StartTimer()
				status = status && acc.ZKMemVerifier(memProof, digest_XI, C_I.Com, transcript)
				t.StopTimer()
				if status == false {
					b.Errorf("Verifier-PureMem failed")
				}
			}
		})

		b.Run(fmt.Sprintf("PureNonMem/Prover;%02d", i-1), func(t *testing.B) {
			transcript := [32]byte{}
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {

				t.StartTimer()
				nonMemProof = acc.ZKNonMemProver(digest_X, C_I, A, B, transcript)
				t.StopTimer()
				nonMemProofs = append(nonMemProofs, nonMemProof)
			}
		})

		b.Run(fmt.Sprintf("PureNonMem/Verifier;%02d", i-1), func(t *testing.B) {
			transcript := [32]byte{}
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {
				nonMemProof, nonMemProofs = nonMemProofs[0], nonMemProofs[1:]
				status = true
				t.StartTimer()
				status = status && acc.ZKNonMemVerifier(nonMemProof, digest_X, C_I.Com, transcript)
				t.StopTimer()
				if status == false {
					b.Errorf("Verifier-PureNonMem failed")
				}
			}
		})

		b.Run(fmt.Sprintf("Pedersen/Commit;%02d", i-1), func(t *testing.B) {
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {
				var rc mcl.Fr
				rc.Random()
				t.StartTimer()
				acc.PedersenG2(I_x, acc.VK, rc, acc.PedVK[0])
				t.StopTimer()
			}
		})
	}

	fmt.Println("SizeOf E2EMem:", zk_mem_proof.ByteSize(), "bytes =", fmt.Sprintf("%.2f", float64(zk_mem_proof.ByteSize())/1024.0), "KiB")
	fmt.Println("SizeOf E2ENonMem:", zk_non_mem_proof.ByteSize(), "bytes =", fmt.Sprintf("%.2f", float64(zk_non_mem_proof.ByteSize())/1024.0), "KiB")
	fmt.Println("SizeOf DegCheck:", zkDegCheckProof.ByteSize(), "bytes =", fmt.Sprintf("%.2f", float64(zkDegCheckProof.ByteSize())/1024.0), "KiB")
	fmt.Println("SizeOf PureMem:", memProof.ByteSize(), "bytes =", fmt.Sprintf("%.2f", float64(memProof.ByteSize())/1024.0), "KiB")
	fmt.Println("SizeOf PureNonMem:", nonMemProof.ByteSize(), "bytes =", fmt.Sprintf("%.2f", float64(nonMemProof.ByteSize())/1024.0), "KiB")
}

func BenchmarkZKAccWitness(b *testing.B) {

	ell := []uint64{5, 6, 7, 8, 9, 10, 11, 12}

	var acc BpAcc
	acc.KeyGenLoad(8, ell[len(ell)-1], "xyz", "../pkvk-21")

	var data []mcl.Fr

	var memProofs_I []mcl.G1
	var nonmemProofs_I []NonMemProof

	var random mcl.Fr

	var X, I []mcl.Fr
	var I_x []mcl.Fr
	var C_I PedG2
	var ped mcl.G2
	var zk_mem_proof e2eMemProof
	var zk_mem_proofs []e2eMemProof

	var zk_non_mem_proof e2eNonMemProof
	var zk_non_mem_proofs []e2eNonMemProof

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

		memProofs_I = acc.ProveMemFake(X, I)
		fmt.Println("Generated Membership.")

		nonmemProofs_I = acc.ProveNonMemFake(X, I)
		fmt.Println("Generated Non-Membership.")

		batchMemProof_I, _ := acc.CommitFakeG1(X) // This is also the digest of X
		A, B := acc.ProveBatchNonMemFake(X, I)
		fmt.Println("Generated batch proofs.")

		random.Random()
		I_x = fft.PolyTree(I)

		b.Run(fmt.Sprintf("Pedersen-commit;%02d", log_batch_size), func(t *testing.B) {
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {
				t.StartTimer()
				ped = acc.PedersenG2(I_x, acc.VK, random, acc.PedVK[0])
				t.StopTimer()
			}
		})
		C_I = PedG2{ped, random}

		b.Run(fmt.Sprintf("AggMemProve;%02d", log_batch_size), func(t *testing.B) {
			t.ResetTimer()
			for j := 0; j < t.N; j++ {
				_, I_x = acc.AggMemProve(I, memProofs_I)
			}
		})

		b.Run(fmt.Sprintf("FullE2EMem-prover;%02d", log_batch_size), func(t *testing.B) {
			transcript := [32]byte{}
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {

				t.StartTimer()
				// Commit
				ped = acc.PedersenG2(I_x, acc.VK, random, acc.PedVK[0])
				C_I = PedG2{ped, random}

				// Generate witness
				_, I_x = acc.AggMemProve(I, memProofs_I)

				// Generate zk batch proof
				zk_mem_proof.zk_mem_proof = acc.ZKMemProver(C_I, batchMemProof_I, transcript)
				zk_mem_proof.zk_deg_proof = acc.ZKDegCheckProver(C_I, I_x, zk_mem_proof.zk_mem_proof.HashProof(transcript))
				//
				t.StopTimer()
				zk_mem_proofs = append(zk_mem_proofs, zk_mem_proof)
			}
		})

		if i < 15 {
			b.Run(fmt.Sprintf("AggNonMemProve;%02d", log_batch_size), func(t *testing.B) {
				t.ResetTimer()
				for j := 0; j < t.N; j++ {
					alpha, beta, _ := acc.AggNonMemProve(I, nonmemProofs_I)
					_ = AggNonMemProof{alpha, beta}
				}
			})

		}

		b.Run(fmt.Sprintf("FullE2ENonMem-prover;%02d", log_batch_size), func(t *testing.B) {

			transcript := [32]byte{}
			t.ResetTimer()
			for tn := 0; tn < t.N; tn++ {
				t.StartTimer()
				// Commit
				ped = acc.PedersenG2(I_x, acc.VK, random, acc.PedVK[0])
				C_I = PedG2{ped, random}

				// Generate witness
				alpha, beta, _ := acc.AggNonMemProve(I, nonmemProofs_I)
				_ = AggNonMemProof{alpha, beta}

				// ZK batch prove
				zk_non_mem_proof.zk_non_mem_proof = acc.ZKNonMemProver(batchMemProof_I, C_I, A, B, transcript)
				zk_non_mem_proof.zk_deg_proof = acc.ZKDegCheckProver(C_I, I_x, zk_non_mem_proof.zk_non_mem_proof.HashProof(transcript))
				t.StopTimer()
				zk_non_mem_proofs = append(zk_non_mem_proofs, zk_non_mem_proof)
			}
		})
		fmt.Sprintf("%d, %d", len(memProofs_I), len(nonmemProofs_I))
	}
}
