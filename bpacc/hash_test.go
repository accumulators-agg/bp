package bpacc

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/alinush/go-mcl"
)

func BenchmarkHash(b *testing.B) {

	ell := []uint64{9, 11, 13, 15, 17}
	for _, i := range ell {
		n := uint64(1) << i
		b.Run(fmt.Sprintf("SetHashOf;2^%d", i), func(b *testing.B) {
			var x mcl.Fr
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				for k := uint64(0); k < n; k++ {
					b.StopTimer()
					token := make([]byte, 32)
					rand.Read(token)
					b.StartTimer()
					x.SetHashOf(token)
				}
			}
		})
	}
}
