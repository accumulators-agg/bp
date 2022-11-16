package bpacc

import (
	"fmt"
	"log"
	"math/bits"
	"os"

	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
)

// Converts a string to Fr element
func SeedToFr(seed string) mcl.Fr {
	var s mcl.Fr

	seedBytes := []byte(seed)
	status := s.SetHashOf(seedBytes)

	for i := int64(12); !status || s.IsZero(); i++ { // This !status is forced by golang static checker
		s.SetInt64(i)
		status = true
	}
	return s
}

// Some default generators. Not relevant for this project.
// But a pre-agreed generator is used so that prover and verifier can get to business without making sure that they have the same parameters.
func initG1G2() (mcl.G1, mcl.G2) {
	var GenG1 mcl.G1
	var GenG2 mcl.G2
	GenG1.X.SetString("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507", 10)
	GenG1.Y.SetString("1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569", 10)
	GenG1.Z.SetInt64(1)

	GenG2.X.D[0].SetString("352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160", 10)
	GenG2.X.D[1].SetString("3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758", 10)
	GenG2.Y.D[0].SetString("1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905", 10)
	GenG2.Y.D[1].SetString("927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582", 10)
	GenG2.Z.D[0].SetInt64(1)
	GenG2.Z.D[1].Clear()

	GenG1.Random()
	GenG2.Random()
	return GenG1, GenG2
}

func GetFrByteSize() int {
	return 32
}

func GetG1ByteSize() int {
	return 48
}

func GetG2ByteSize() int {
	return 96
}

func GetGTByteSize() int {
	return 576
}

func BoundsPrint(start, stop uint64) string {
	return fmt.Sprintf("%10d %10d", start, stop)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func minUint64(a uint64, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		log.Fatal(err)
	}
	return fi.Size()
}

// Computes the a^x, where a is mcl.Fr and x is int64
func FrPow(a mcl.Fr, n int64) mcl.Fr { // n has to be signed

	var x, y mcl.Fr
	x = a

	if n == 0 {
		x.SetInt64(1)
		return x
	}

	if n < 0 {
		mcl.FrInv(&x, &x)
		n = -n
	}

	y.SetInt64(1)
	for n > 1 {
		if n%2 == 0 {
			mcl.FrSqr(&x, &x)
			n = n / 2
		} else {
			mcl.FrMul(&y, &x, &y)
			mcl.FrSqr(&x, &x)
			n = (n - 1) / 2
		}
	}
	mcl.FrMul(&y, &x, &y)
	return y
}

func NextPowOf2(v uint64) uint64 {
	if v == 0 {
		return 1
	}
	return uint64(1) << bits.Len64(v-1)
}

func IsPowOf2(m uint64) bool {
	flag := m & (m - 1)
	if m > 0 && flag == 0 {
		return true // It is a power of two
	} else {
		return false // NOT a power of two
	}
}

// For a give N, compute N uniquely random field elements
func PopulateRandom(n uint64) []mcl.Fr {

	hashTable := map[mcl.Fr]bool{}
	var x mcl.Fr

	for len(hashTable) < int(n) {
		x.Random()
		if _, ok := hashTable[x]; !ok {
			// golang hashes the contents of x, rather than the memlocation.
			hashTable[x] = true
		}
	}

	keys := []mcl.Fr{}
	for k := range hashTable {
		keys = append(keys, k)
	}

	return keys
}

func FrInvVec(a []mcl.Fr) []mcl.Fr {
	for i := range a {
		mcl.FrInv(&a[i], &a[i])
	}
	return a
}

func PolyMulScalar(a []mcl.Fr, b *mcl.Fr) []mcl.Fr {
	for i := range a {
		mcl.FrMul(&a[i], &a[i], b)
	}
	return a
}

// Given a_1, a_2, a_3, a_4. Let A = a_1 * a_2 * a_3 * a_4.
// Computes Y_1 = A / a_1, Y_2 = A / a_2, Y_3 = A / a_3, Y_4 = A / a_4
func ComputeYs(product mcl.Fr, I []mcl.Fr) []mcl.Fr {
	N := len(I)
	if N == 0 || IsPowOf2(uint64(N)) == false {
		panic("Exception: ComputeYs: Not a power of two")
	}
	var Y []mcl.Fr
	if N == 1 {
		Y = append(Y, product)
	} else {
		mid := N / 2

		I_left := I[:mid]
		I_right := I[mid:]
		product_left := FrMulVec(I_left)
		product_right := FrMulVec(I_right)

		mcl.FrMul(&product_left, &product_left, &product)
		mcl.FrMul(&product_right, &product_right, &product)

		left := ComputeYs(product_right, I_left)
		right := ComputeYs(product_left, I_right)
		Y = append(Y, left...)
		Y = append(Y, right...)
	}
	return Y
}

// Compute \prod_{i=0}^{N-1}I_i
func FrMulVec(I []mcl.Fr) mcl.Fr {
	var prod mcl.Fr
	prod.SetInt64(1)
	for i := range I {
		mcl.FrMul(&prod, &prod, &I[i])
	}
	return prod
}

// Turns out this is slower than naively using compting I(s) and dividing by y_i.
// Similar to ComputeYs. However each a_i is a monomials of the form (x - a_i)
// Assumed that subproduct tree is correct.
func ComputeYsVec(subProdTree [][][]mcl.Fr) [][]mcl.Fr {
	N := uint64(len(subProdTree[0]))
	if N == 0 || IsPowOf2(uint64(N)) == false {
		panic("Exception: ComputeYsVec: Not a power of two")
	}

	l := uint8(bits.Len64(uint64(N))) - 1

	var M [][]mcl.Fr // It is not [][][]mcl.Fr, as we are going to flatten the subprod tree.
	M = make([][]mcl.Fr, 0, 2*N-1)
	for i := len(subProdTree) - 1; i >= 0; i-- {
		M = append(M, subProdTree[i]...)
	}

	var Y map[uint64][]mcl.Fr // Final variable Ys
	var y map[uint64][]mcl.Fr // Temp variable Ys

	Y = make(map[uint64][]mcl.Fr)
	y = make(map[uint64][]mcl.Fr)

	tmpPoly := make([]mcl.Fr, 1)
	tmpPoly[0].SetInt64(1)
	Y[0] = tmpPoly

	// Put the subprod tree and destination tree next to each other to see why:
	// dst_left := fft.PolyMul(current, M[2*i+2])
	// dst_right := fft.PolyMul(current, M[2*i+1])
	// y[2*i+1] = dst_left
	// y[2*i+2] = dst_right
	index := uint64(1)
	for i := uint64(0); i < N-1; i++ {
		current, ok := Y[i]
		if !ok {
			fmt.Println("Missing key:", i)
			panic("ComputeYsVec: Did not find the key")
		}
		dst_left := fft.PolyMul(current, M[2*i+2])
		dst_right := fft.PolyMul(current, M[2*i+1])

		y[2*i+1] = dst_left
		y[2*i+2] = dst_right

		index += 1
		if IsPowOf2(index) {
			Y = y
			y = make(map[uint64][]mcl.Fr)
		}
	}

	result := make([][]mcl.Fr, 0, N)
	for i := uint64(1)<<(l) - 1; i < 2*N-1; i++ {
		value, ok := Y[i]
		if !ok {
			panic("ComputeYsVec: Result is not found in the hashmap")
		}
		result = append(result, value)
	}
	return result
}

// Goal is to check if e(P1, Q1) = e(P2, Q2).
// It converts it into: e(P1, Q1) e(P2, Q2^{-1}) = 1.
// This uses multi-pairing
// No need to use this for mem verify. Mem-verify is already hand optimized.
func MultiPairing2(P1 mcl.G1, Q1 mcl.G2, P2 mcl.G1, Q2 mcl.G2) bool {

	var h mcl.G2
	mcl.G2Neg(&h, &Q2)

	P := []mcl.G1{P1, P2}
	Q := []mcl.G2{Q1, h}

	var e mcl.GT
	mcl.MillerLoopVec(&e, P, Q)
	mcl.FinalExp(&e, &e)

	return e.IsOne()
}

// Goal is to check if e(P0, Q0) = e(P1, Q1)e(P2, Q2)e(P3, Q4)...e(PN, QN)
// It converts it into: e(P0, Q0^{-1})e(P1, Q1)e(P2, Q2)e(P3, Q4)...e(PN, QN) = 1.
// This uses multi-pairing
func MultiPairingN(P0 mcl.G1, Q0 mcl.G2, Ps []mcl.G1, Qs []mcl.G2) bool {

	if len(Ps) != len(Qs) {
		panic("Exception: MultiPairingN: len(Ps) != len(Qs)")
	}
	var h mcl.G2
	mcl.G2Neg(&h, &Q0)

	P := append([]mcl.G1{P0}, Ps...)
	Q := append([]mcl.G2{h}, Qs...)

	var e mcl.GT
	mcl.MillerLoopVec(&e, P, Q)
	mcl.FinalExp(&e, &e)

	return e.IsOne()
}
