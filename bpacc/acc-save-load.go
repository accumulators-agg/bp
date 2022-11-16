package bpacc

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"

	"github.com/alinush/go-mcl"
)

func (self *BpAcc) SaveTrapdoor() {

	fmt.Println("Saving data to:", self.folderPath+TRAPDOORNAME)

	os.MkdirAll(self.folderPath, os.ModePerm)
	f, err := os.Create(self.folderPath + TRAPDOORNAME)
	check(err)

	// Report the size.
	LBytes := make([]byte, 8) // Enough space for 64 bits of interger
	binary.LittleEndian.PutUint64(LBytes, uint64(self.ELL))
	_, err = f.Write(LBytes)
	check(err)

	// Write the trapdoor
	_, err = f.Write(self.S.Serialize())
	check(err)

	// Write the Generator to the file
	_, err = f.Write(self.G.Serialize())
	check(err)
	_, err = f.Write(self.H.Serialize())
	check(err)

	_, err = f.Write(self.Gneg.Serialize())
	check(err)
	_, err = f.Write(self.Hneg.Serialize())
	check(err)

	_, err = f.Write(self.IdGT.Serialize())
	check(err)
	_, err = f.Write(self.InvIdGT.Serialize())
	check(err)

	// Write the KEA
	_, err = f.Write(self.Alpha.Serialize())
	check(err)

	// Write Ped generator
	_, err = f.Write(self.PedH.Serialize())
	check(err)

	for i := range self.A {
		_, err = f.Write(self.A[i].Serialize())
		check(err)
	}

	for i := range self.B {
		_, err = f.Write(self.B[i].Serialize())
		check(err)
	}

	// Lastly, write the PKAlpha, as it is just one value.
	// When/If PKAlpha is of size Q+1, then it will be saved and loaded along with VRK
	_, err = f.Write(self.PKAlpha[0].Serialize())
	check(err)

	defer f.Close()
}

func (self *BpAcc) LoadTrapdoor(L uint64) {

	fileName := self.folderPath + TRAPDOORNAME
	f, err := os.Open(self.folderPath + TRAPDOORNAME)
	check(err)

	var data []byte
	data = make([]byte, 8)

	fmt.Println(fileName)
	_, err = f.Read(data)
	check(err)
	reportedEll := binary.LittleEndian.Uint64(data)

	if reportedEll < L {
		// Assumes SaveTrapdoor is honest
		panic(fmt.Sprintf("There is not enough to read! Found: %d, Wants: %d", L, reportedEll))
	}

	data = make([]byte, GetFrByteSize())
	_, err = f.Read(data)
	check(err)
	self.S.Deserialize(data)

	data = make([]byte, GetG1ByteSize())
	_, err = f.Read(data)
	check(err)
	self.G.Deserialize(data)

	data = make([]byte, GetG2ByteSize())
	_, err = f.Read(data)
	check(err)
	self.H.Deserialize(data)

	data = make([]byte, GetG1ByteSize())
	_, err = f.Read(data)
	check(err)
	self.Gneg.Deserialize(data)

	data = make([]byte, GetG2ByteSize())
	_, err = f.Read(data)
	check(err)
	self.Hneg.Deserialize(data)

	data = make([]byte, GetGTByteSize())
	_, err = f.Read(data)
	check(err)
	self.IdGT.Deserialize(data)

	data = make([]byte, GetGTByteSize())
	_, err = f.Read(data)
	check(err)
	self.InvIdGT.Deserialize(data)

	// Read the KEA
	data = make([]byte, GetFrByteSize())
	_, err = f.Read(data)
	check(err)
	self.Alpha.Deserialize(data)

	// Load Ped generator
	data = make([]byte, GetG2ByteSize())
	_, err = f.Read(data)
	check(err)
	self.PedH.Deserialize(data)

	for i := range self.A {
		data = make([]byte, GetG1ByteSize())
		_, err = f.Read(data)
		check(err)
		self.A[i].Deserialize(data)
	}

	for i := range self.B {
		data = make([]byte, GetG2ByteSize())
		_, err = f.Read(data)
		check(err)
		self.B[i].Deserialize(data)
	}

	data = make([]byte, GetG1ByteSize())
	_, err = f.Read(data)
	check(err)
	self.PKAlpha[0].Deserialize(data)

	f.Close()
}

func (self *BpAcc) PrkVrkParallel(
	index uint8, start uint64, stop uint64, wg *sync.WaitGroup) {

	os.MkdirAll(self.folderPath, os.ModePerm)
	fileNamePK := self.folderPath + fmt.Sprintf(PRK_NAME, index)
	fileNameVK := self.folderPath + fmt.Sprintf(VRK_NAME, index)

	fileNameVKAlpha := self.folderPath + fmt.Sprintf(VRK_KEA_NAME, index)
	fileNamePedVK := self.folderPath + fmt.Sprintf(PED_VRK_NAME, index)
	fileNamePedVKAlpha := self.folderPath + fmt.Sprintf(PED_VRK_KEA_NAME, index)
	// const PED_NAME = "/ped-vrk-%02d.data"
	// const PED_ALPHA_NAME = "/kea-ped-vrk-%02d.data"

	fmt.Println("Saving data to:", fileNamePK, fileNameVK, fileNameVKAlpha, fileNamePedVK, fileNamePedVKAlpha)
	f1, err := os.Create(fileNamePK)
	check(err)
	f2, err := os.Create(fileNameVK)
	check(err)

	f3, err := os.Create(fileNameVKAlpha)
	check(err)
	f4, err := os.Create(fileNamePedVK)
	check(err)
	f5, err := os.Create(fileNamePedVKAlpha)
	check(err)

	a := FrPow(self.S, int64(start))
	var gTmp mcl.G1
	var hTmp mcl.G2
	var hAlphaTmp mcl.G2
	for i := start; i < stop; i++ {
		mcl.G1Mul(&gTmp, &self.G, &a)
		mcl.G2Mul(&hTmp, &self.H, &a)
		mcl.G2Mul(&hAlphaTmp, &hTmp, &self.Alpha)

		_, err = f1.Write(gTmp.Serialize())
		check(err)
		_, err = f2.Write(hTmp.Serialize())
		check(err)
		_, err = f3.Write(hAlphaTmp.Serialize())
		check(err)

		self.PK[i] = gTmp
		self.VK[i] = hTmp
		self.VKAlpha[i] = hAlphaTmp

		mcl.G2Mul(&hTmp, &self.PedH, &a)
		mcl.G2Mul(&hAlphaTmp, &hTmp, &self.Alpha)

		_, err = f4.Write(hTmp.Serialize())
		check(err)
		_, err = f5.Write(hAlphaTmp.Serialize())
		check(err)
		self.PedVK[i] = hTmp
		self.PedVKAlpha[i] = hAlphaTmp

		mcl.FrMul(&a, &a, &self.S)
	}
	defer f1.Close()
	defer f2.Close()
	defer f3.Close()
	defer f4.Close()
	defer f5.Close()
	defer wg.Done()
}

func (self *BpAcc) G1ParallelLoad(
	fileName string,
	varG []mcl.G1,
	index uint8,
	start uint64,
	stop uint64,
	wg *sync.WaitGroup) {

	f, err := os.Open(fileName)
	check(err)

	dataG1 := make([]byte, GetG1ByteSize())

	var resultG1 mcl.G1

	for j := start; j < stop; j++ {

		_, err = f.Read(dataG1)
		check(err)
		resultG1.Deserialize(dataG1)
		varG[j] = resultG1
	}
	fmt.Println("Read ", fileName, BoundsPrint(start, stop))
	defer f.Close()
	defer wg.Done()
}

func (self *BpAcc) G1Load(files []string, varG []mcl.G1) {

	var wg sync.WaitGroup
	var step, start, stop uint64
	var total, totalBytes int64
	var i uint8

	if len(files) == 0 {
		panic("Could not find the G1 files.")
	}

	sort.Strings(files)

	totalBytes = int64(0)
	for i := range files {
		totalBytes += fileSize(files[i])
	}

	fmt.Println("Total bytes", totalBytes)
	total = totalBytes / int64(GetG1ByteSize())
	step = uint64(math.Ceil(float64(total) / float64(NFILES)))

	num := self.Q + 1
	start = uint64(0)
	stop = step
	stop = minUint64(stop, num)

	i = uint8(0)
	for start < num {
		wg.Add(1)
		fileName := files[i]
		go self.G1ParallelLoad(fileName, varG, i, start, stop, &wg)
		fmt.Println(fileName, i, start, stop)
		start += step
		stop += step
		stop = minUint64(stop, num)
		i++
	}
	wg.Wait()
}

func (self *BpAcc) G2ParallelLoad(
	fileName string,
	varH []mcl.G2,
	index uint8,
	start uint64,
	stop uint64,
	wg *sync.WaitGroup) {

	f, err := os.Open(fileName)
	check(err)

	dataG2 := make([]byte, GetG2ByteSize())

	var resultG2 mcl.G2

	for j := start; j < stop; j++ {

		_, err = f.Read(dataG2)
		check(err)
		resultG2.Deserialize(dataG2)
		varH[j] = resultG2
	}
	fmt.Println("Read ", fileName, BoundsPrint(start, stop))
	defer f.Close()
	defer wg.Done()
}

func (self *BpAcc) G2Load(files []string, varH []mcl.G2) {
	var wg sync.WaitGroup
	var step, start, stop uint64
	var total, totalBytes int64
	var i uint8

	if len(files) == 0 {
		panic("Could not find G2 files.")
	}

	sort.Strings(files)

	totalBytes = int64(0)
	for i := range files {
		totalBytes += fileSize(files[i])
	}

	fmt.Println("Total bytes", totalBytes)
	total = totalBytes / int64(GetG2ByteSize())
	step = uint64(math.Ceil(float64(total) / float64(NFILES)))

	num := self.Q + 1
	start = uint64(0)
	stop = step
	stop = minUint64(stop, num)

	i = uint8(0)
	for start < num {
		wg.Add(1)
		fileName := files[i]
		go self.G2ParallelLoad(fileName, varH, i, start, stop, &wg)
		fmt.Println(fileName, i, start, stop)
		start += step
		stop += step
		stop = minUint64(stop, num)
		i++
	}
	wg.Wait()
}

func (self *BpAcc) IsParamsCorrect() bool {

	if self.Q != uint64(1)<<self.ELL {
		out_str := fmt.Sprintf("Q vs ELL: %d vs %d", self.Q, self.ELL)
		fmt.Println(out_str)
		return false
	}

	if self.S.IsZero() == true {
		out_str := fmt.Sprintf("Trapdoor S is zero.")
		fmt.Println(out_str)
		return false
	}

	if self.Alpha.IsZero() == true {
		out_str := fmt.Sprintf("KEA trapdoor Alpha is zero.")
		fmt.Println(out_str)
		return false
	}

	if self.Q+1 != uint64(len(self.PK)) {
		out_str := fmt.Sprintf("Q + 1 != len(PK): %d vs %d", self.Q, len(self.PK))
		fmt.Println(out_str)
		return false
	}

	if len(self.PKAlpha) != 1 {
		out_str := fmt.Sprintf("len(PK) != 1: %d vs 1", len(self.PKAlpha))
		fmt.Println(out_str)
		return false
	}

	if len(self.PK) != len(self.VK) {
		out_str := fmt.Sprintf("len(PK) != len(VK): %d vs %d", len(self.PK), len(self.VK))
		fmt.Println(out_str)
		return false
	}

	if len(self.VK) != len(self.VKAlpha) {
		out_str := fmt.Sprintf("len(self.VK) != len(self.VKAlpha): %d vs %d", len(self.VK), len(self.VKAlpha))
		fmt.Println(out_str)
		return false
	}

	if len(self.VK) != len(self.PedVK) {
		out_str := fmt.Sprintf("len(self.VK) != len(self.PedVK): %d vs %d", len(self.VK), len(self.PedVK))
		fmt.Println(out_str)
		return false
	}

	if len(self.PedVK) != len(self.PedVKAlpha) {
		out_str := fmt.Sprintf("len(self.PedVK) != len(self.PedVKAlpha): %d vs %d", len(self.PedVK), len(self.PedVKAlpha))
		fmt.Println(out_str)
		return false
	}

	if self.G.IsZero() {
		return false
	}
	if self.H.IsZero() {
		return false
	}
	if !self.G.IsEqual(&self.PK[0]) {
		return false
	}
	if !self.H.IsEqual(&self.VK[0]) {
		return false
	}

	if self.PedH.IsZero() {
		return false
	}

	var g1Tmp mcl.G1
	var g2Tmp mcl.G2

	for i := 1; i < len(self.PK); i++ {
		mcl.G1Mul(&g1Tmp, &self.PK[i-1], &self.S)
		mcl.G2Mul(&g2Tmp, &self.VK[i-1], &self.S)

		if !g1Tmp.IsEqual(&self.PK[i]) {
			out_str := fmt.Sprintf("PK error at index %d", i)
			fmt.Println(out_str)
			return false
		}
		if !g2Tmp.IsEqual(&self.VK[i]) {
			out_str := fmt.Sprintf("VK error at index %d", i)
			fmt.Println(out_str)
			return false
		}

		mcl.G2Mul(&g2Tmp, &self.VK[i], &self.Alpha)
		if !g2Tmp.IsEqual(&self.VKAlpha[i]) {
			out_str := fmt.Sprintf("KEA VKAlpha error at index %d", i)
			fmt.Println(out_str)
			return false
		}

		mcl.G2Mul(&g2Tmp, &self.VKAlpha[i-1], &self.S)
		if !g2Tmp.IsEqual(&self.VKAlpha[i]) {
			out_str := fmt.Sprintf("VKAlpha error at index %d", i)
			fmt.Println(out_str)
			return false
		}

		mcl.G2Mul(&g2Tmp, &self.PedVK[i-1], &self.S)
		if !g2Tmp.IsEqual(&self.PedVK[i]) {
			out_str := fmt.Sprintf("PedVK error at index %d", i)
			fmt.Println(out_str)
			return false
		}

		mcl.G2Mul(&g2Tmp, &self.PedVK[i], &self.Alpha)
		if !g2Tmp.IsEqual(&self.PedVKAlpha[i]) {
			out_str := fmt.Sprintf("PedVKAlpha error at index %d", i)
			fmt.Println(out_str)
			return false
		}

		if self.PK[i].IsZero() == true || self.VK[i].IsZero() == true || self.VKAlpha[i].IsZero() == true || self.PedVK[i].IsZero() == true || self.PedVKAlpha[i].IsZero() == true {
			out_str := fmt.Sprintf("One of the PP is zero.")
			fmt.Println(out_str)
			return false
		}
	}

	return true
}
