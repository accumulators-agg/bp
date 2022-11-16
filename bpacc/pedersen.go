package bpacc

import (
	"fmt"

	"github.com/alinush/go-mcl"
)

type PedG2 struct {
	Com mcl.G2
	R   mcl.Fr
}

func (self *BpAcc) PedersenG2(elements []mcl.Fr, G []mcl.G2, random mcl.Fr, h mcl.G2) mcl.G2 {

	l := len(elements)
	if uint64(l) > (self.Q+1) || l > len(G) {
		panic(fmt.Sprintf("Wants to Perdesen worker %d, but the accumulator supports only %d", len(elements), self.Q))
	}

	var digest, digest1, digest2 mcl.G2
	mcl.G2Mul(&digest1, &h, &random)
	mcl.G2MulVec(&digest2, G[:len(elements)], elements)
	mcl.G2Add(&digest, &digest1, &digest2)
	return digest
}
