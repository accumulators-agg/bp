package bpacc

import (
	"math"
	"path/filepath"
	"sync"

	"github.com/alinush/go-mcl"
)

const TRAPDOORNAME = "/trapdoors.data"
const PRK_NAME = "/prk-%02d.data"
const VRK_NAME = "/vrk-%02d.data"
const VRK_KEA_NAME = "/vrk-kea-%02d.data"
const PED_VRK_NAME = "/ped-vrk-%02d.data"
const PED_VRK_KEA_NAME = "/ped-vrk-kea-%02d.data"

const NFILES = 16
const SPARE = 10

var NCORES uint8

type BpAcc struct {
	seed string

	ELL uint64
	Q   uint64 // Limit on the q-SDH, thus degree bound is q+1
	S   mcl.Fr // Trapdoor

	G mcl.G1 // Generator for G1
	H mcl.G2 // Generator for G2

	Gneg    mcl.G1 // Contains g^{-1}
	Hneg    mcl.G2 // Contains h^{-1}H
	IdGT    mcl.GT // Contains e(g, h)
	InvIdGT mcl.GT // Contains e(g, h)^-1

	// Probably a misnomer
	PK []mcl.G1 // g, g^s, g^s^2, g^s^3 .... g^s^q
	VK []mcl.G2 // h, h^s, h^s^2, h^s^3 .... h^s^q

	// digest mcl.G1 // g^f(s), where f(x) is a polynomial and s is the trapdoor.
	folderPath string

	Alpha mcl.Fr // KEA

	PKAlpha []mcl.G1 // Going to store only g^a aka this is going to be size 1.
	VKAlpha []mcl.G2 // h^a, h^s^a, h^s^2^a, h^s^3^a .... h^s^q^a

	PedH       mcl.G2   // Generator for Ped. Only fo internal uses.
	PedVK      []mcl.G2 // h_x, h_x^s, h_x^s^2, h_x^s^3 .... h_x^s^q
	PedVKAlpha []mcl.G2 // h_x^a, h_x^s^a, h_x^s^2^a, h_x^s^3^a .... h_x^s^q^a

	// Extra generators
	A []mcl.G1
	B []mcl.G2
}

type NonMemProof struct {
	Alpha mcl.Fr // Variable is exported, thus Alpha, not alpha
	Beta  mcl.G1 // Variable is exported, thus Beta, not beta
}

// Single threaded version.
// Defunct now. Since parallel save and load performs the same role.
func (self *BpAcc) Setup(l uint64, seed string) {

	self.ELL = l
	self.Q = uint64(1) << self.ELL
	self.seed = seed
	self.S = SeedToFr(self.seed) // Use the seed to generate the trapdoor
	self.G, self.H = initG1G2()
	mcl.G1Neg(&self.Gneg, &self.G)
	mcl.G2Neg(&self.Hneg, &self.H)
	mcl.Pairing(&self.IdGT, &self.G, &self.H)
	mcl.GTInv(&self.InvIdGT, &self.IdGT)

	self.PK = make([]mcl.G1, self.Q+1) // A degree q polynomial has q + 1 coefficients
	self.VK = make([]mcl.G2, self.Q+1) // A degree q polynomial has q + 1 coefficients

	self.PK[0] = self.G
	self.VK[0] = self.H

	powS := self.S
	for i := uint64(1); i < uint64(len(self.PK)); i++ {
		mcl.G1Mul(&self.PK[i], &self.G, &powS)
		mcl.G2Mul(&self.VK[i], &self.H, &powS)
		mcl.FrMul(&powS, &powS, &self.S)
	}
}

func (self *BpAcc) Init(L uint64, seed string, folderPath string) {
	self.seed = seed
	self.ELL = L
	self.Q = uint64(1) << self.ELL

	// A degree q polynomial has q + 1 coefficients
	self.PK = make([]mcl.G1, self.Q+1)
	self.VK = make([]mcl.G2, self.Q+1)

	// (NOTE): Currently our protocol needs only g^a. No higher powers of s needs to multiplied by Alpha.
	self.PKAlpha = make([]mcl.G1, 1)

	// Computes the KEA of VK
	self.VKAlpha = make([]mcl.G2, self.Q+1)

	// Generators for Pedersen vector commitment
	self.PedVK = make([]mcl.G2, self.Q+1)

	// KEA of Pedersen vector commitment parameters
	self.PedVKAlpha = make([]mcl.G2, self.Q+1)

	self.A = make([]mcl.G1, SPARE)
	self.B = make([]mcl.G2, SPARE)

	self.folderPath = folderPath
}

func (self *BpAcc) TrapdoorsGen() {
	self.S = SeedToFr(self.seed)                 // Use the seed to generate the trapdoor
	self.Alpha = SeedToFr(self.seed + "+ Alpha") // Generate the alpha for the KEA

	self.G, self.H = initG1G2()
	mcl.G1Neg(&self.Gneg, &self.G)
	mcl.G2Neg(&self.Hneg, &self.H)
	mcl.Pairing(&self.IdGT, &self.G, &self.H)
	mcl.GTInv(&self.InvIdGT, &self.IdGT)

	self.PedH.Random()
	for i := range self.A {
		self.A[i].Random()
		self.B[i].Random()
	}

	// Breaking the convention here to save this value along with trapdoors
	mcl.G1Mul(&self.PKAlpha[0], &self.G, &self.Alpha)
	self.SaveTrapdoor()
}

func (self *BpAcc) PrkVrkGen() {
	var wg sync.WaitGroup

	num := self.Q + 1 // Note that PK and VK has Q+1 terms
	start := uint64(0)
	step := uint64(math.Ceil(float64(num) / float64(NFILES)))
	stop := step

	for i := uint8(0); i < NFILES; i++ {
		wg.Add(1)
		go self.PrkVrkParallel(i, start, stop, &wg)

		start += step
		stop += step
		stop = minUint64(stop, num)

		if (i+1)%NCORES == 0 {
			wg.Wait()
		}
	}
	wg.Wait()
}

func (self *BpAcc) KeyGen(ncores uint8,
	L uint64, seed string, folderPath string) {
	NCORES = ncores
	self.Init(L, seed, folderPath)
	self.TrapdoorsGen()
	self.PrkVrkGen()
}

func (self *BpAcc) KeyGenLoad(ncores uint8,
	L uint64, seed string, folderPath string) {
	NCORES = ncores
	self.Init(L, seed, folderPath)
	self.LoadTrapdoor(L)

	var files []string
	var err error

	files, err = filepath.Glob(self.folderPath + "/prk-[0-9][0-9].data")
	check(err)
	self.G1Load(files, self.PK)
	files = make([]string, 0)

	files, err = filepath.Glob(self.folderPath + "/vrk-[0-9][0-9].data")
	check(err)
	self.G2Load(files, self.VK)
	files = make([]string, 0)

	files, err = filepath.Glob(self.folderPath + "/vrk-kea-[0-9][0-9].data")
	check(err)
	self.G2Load(files, self.VKAlpha)
	files = make([]string, 0)

	files, err = filepath.Glob(self.folderPath + "/ped-vrk-[0-9][0-9].data")
	check(err)
	self.G2Load(files, self.PedVK)
	files = make([]string, 0)

	files, err = filepath.Glob(self.folderPath + "/ped-vrk-kea-[0-9][0-9].data")
	check(err)
	self.G2Load(files, self.PedVKAlpha)
	files = make([]string, 0)
}
