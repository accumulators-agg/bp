package main

import (
	"fmt"

	"github.com/accumulators-agg/bp/bpacc"
	"github.com/accumulators-agg/go-poly/ff"
	"github.com/alinush/go-mcl"
)

func main() {
	mcl.InitFromString("bls12-381")
	fmt.Println("Hello, World!")
	_ = ff.RandomFr()
	var acc1 bpacc.BpAcc
	acc1.KeyGen(8, 21, "xyz", "pkvk-21")
}
