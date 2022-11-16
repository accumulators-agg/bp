package bpacc

import (
	"encoding/binary"

	"github.com/alinush/go-mcl"
	"golang.org/x/crypto/blake2b"
)

type zkMemProof struct {
	Pi_I_1 mcl.G1
	Pi_I_2 mcl.G1
	R_1    mcl.G1
	R_2    mcl.G1
	R_3    mcl.GT

	s_r       mcl.Fr
	s_tau_1   mcl.Fr
	s_tau_2   mcl.Fr
	s_delta_1 mcl.Fr
	s_delta_2 mcl.Fr
}

func (self *zkMemProof) FiatShamir(transcript [32]byte) []byte {
	data := make([]byte, 0)
	data = append(data, transcript[:]...)
	data = append(data, self.Pi_I_1.Serialize()...)
	data = append(data, self.Pi_I_2.Serialize()...)
	data = append(data, self.R_1.Serialize()...)
	data = append(data, self.R_2.Serialize()...)
	data = append(data, self.R_3.Serialize()...)
	hash := blake2b.Sum256(data)
	return hash[:]
}

func (self *zkMemProof) HashProof(transcript [32]byte) [32]byte {
	data := make([]byte, 0)
	data = append(data, transcript[:]...)
	data = append(data, self.Pi_I_1.Serialize()...)
	data = append(data, self.Pi_I_2.Serialize()...)
	data = append(data, self.R_1.Serialize()...)
	data = append(data, self.R_2.Serialize()...)
	data = append(data, self.R_3.Serialize()...)
	data = append(data, self.s_r.Serialize()...)
	data = append(data, self.s_tau_1.Serialize()...)
	data = append(data, self.s_tau_2.Serialize()...)
	data = append(data, self.s_delta_1.Serialize()...)
	data = append(data, self.s_delta_2.Serialize()...)

	hash := blake2b.Sum256(data)
	return hash
}

func (self *zkMemProof) ByteSize() uint64 {

	var total uint64
	total = 0
	total += uint64(GetG1ByteSize()) // Pi_I_1
	total += uint64(GetG1ByteSize()) // Pi_I_2
	total += uint64(GetG1ByteSize()) // R_1
	total += uint64(GetG1ByteSize()) // R_2

	total += uint64(GetGTByteSize()) // R_3

	total += uint64(GetFrByteSize()) // s_r
	total += uint64(GetFrByteSize()) // s_tau_1
	total += uint64(GetFrByteSize()) // s_tau_2
	total += uint64(GetFrByteSize()) // s_delta_1
	total += uint64(GetFrByteSize()) // s_delta_2

	return total
}

type zkNonMemProof struct {
	A_bar []mcl.G2
	B_bar []mcl.G1
	R_1   mcl.G2
	R_2   []mcl.G1
	R_3   mcl.GT

	s_r       mcl.Fr
	s_tau     []mcl.Fr
	s_delta_3 mcl.Fr
	s_delta_4 mcl.Fr
}

func (self *zkNonMemProof) Setup() {

	self.A_bar = make([]mcl.G2, 2)
	self.B_bar = make([]mcl.G1, 2)
	self.R_2 = make([]mcl.G1, 2)
	self.s_tau = make([]mcl.Fr, 4)
}

func (self *zkNonMemProof) FiatShamir(transcript [32]byte) []byte {

	data := make([]byte, 0)
	data = append(data, transcript[:]...)
	data = append(data, self.A_bar[0].Serialize()...)
	data = append(data, self.A_bar[1].Serialize()...)
	data = append(data, self.B_bar[0].Serialize()...)
	data = append(data, self.B_bar[1].Serialize()...)
	data = append(data, self.R_1.Serialize()...)
	data = append(data, self.R_2[0].Serialize()...)
	data = append(data, self.R_2[1].Serialize()...)
	data = append(data, self.R_3.Serialize()...)
	hash := blake2b.Sum256(data)

	return hash[:]
}

func (self *zkNonMemProof) HashProof(transcript [32]byte) [32]byte {
	data := make([]byte, 0)
	data = append(data, transcript[:]...)
	data = append(data, self.A_bar[0].Serialize()...)
	data = append(data, self.A_bar[1].Serialize()...)
	data = append(data, self.B_bar[0].Serialize()...)
	data = append(data, self.B_bar[1].Serialize()...)
	data = append(data, self.R_1.Serialize()...)
	data = append(data, self.R_2[0].Serialize()...)
	data = append(data, self.R_2[1].Serialize()...)
	data = append(data, self.R_3.Serialize()...)

	data = append(data, self.s_r.Serialize()...)
	data = append(data, self.s_tau[0].Serialize()...)
	data = append(data, self.s_tau[1].Serialize()...)
	data = append(data, self.s_tau[2].Serialize()...)
	data = append(data, self.s_tau[3].Serialize()...)
	data = append(data, self.s_delta_3.Serialize()...)
	data = append(data, self.s_delta_4.Serialize()...)

	hash := blake2b.Sum256(data)
	return hash
}

func (self *zkNonMemProof) ByteSize() uint64 {

	var total uint64
	total = 0

	total += uint64(GetG2ByteSize())                   // A_bar_2
	total += uint64(len(self.B_bar) * GetG1ByteSize()) // B_bar
	// total += uint64(GetG2ByteSize())                   // R_1
	total += uint64(len(self.R_2) * GetG1ByteSize()) // R_2
	total += uint64(GetGTByteSize())                 // R_3

	total += uint64(GetFrByteSize()) // s_r
	total += uint64(GetFrByteSize()) // s_tau_1
	total += uint64(GetFrByteSize()) // s_tau_3
	total += uint64(GetFrByteSize()) // s_tau_4
	total += uint64(GetFrByteSize()) // s_delta_3
	total += uint64(GetFrByteSize()) // s_delta_4

	return total
}

type ZKDegCheckProof struct {
	D   uint64
	C_f mcl.G2
	C   mcl.G2
	Ca  mcl.G2
}

func (self *ZKDegCheckProof) FiatShamir(transcript [32]byte) []byte {

	d_byte := make([]byte, 8)
	binary.LittleEndian.PutUint64(d_byte, self.D)
	data := make([]byte, 0)
	data = append(data, transcript[:]...)
	data = append(data, d_byte...)
	data = append(data, self.C_f.Serialize()...)
	hash := blake2b.Sum256(data)
	return hash[:]
}

func (self *ZKDegCheckProof) ByteSize() uint64 {

	var total uint64
	total = 0
	total += 8                       // D
	total += uint64(GetG2ByteSize()) // C_f
	total += uint64(GetG2ByteSize()) // C
	total += uint64(GetG2ByteSize()) // Ca

	return total
}

type e2eMemProof struct {
	zk_mem_proof zkMemProof
	zk_deg_proof ZKDegCheckProof
}

func (self *e2eMemProof) ByteSize() uint64 {

	var total uint64
	total = 0
	total += self.zk_mem_proof.ByteSize()
	total += self.zk_deg_proof.ByteSize()

	return total
}

type e2eNonMemProof struct {
	zk_non_mem_proof zkNonMemProof
	zk_deg_proof     ZKDegCheckProof
}

func (self *e2eNonMemProof) ByteSize() uint64 {

	var total uint64
	total = 0
	total += self.zk_non_mem_proof.ByteSize()
	total += self.zk_deg_proof.ByteSize()

	return total
}
