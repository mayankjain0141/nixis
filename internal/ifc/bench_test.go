package ifc

import (
	"testing"

	"github.com/mayankjain0141/nixis/pkg/nixis"
)

var (
	sinkBool  bool
	sinkLabel nixis.SecurityLabel
)

func BenchmarkIFC_Dominates(b *testing.B) {
	subject := nixis.SecurityLabel{Confidentiality: 100, Integrity: 100, Category: CatCredentials | CatFinance}
	object := nixis.SecurityLabel{Confidentiality: 50, Integrity: 50, Category: CatCredentials}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkBool = Dominates(subject, object)
	}
}

func BenchmarkIFC_Join(b *testing.B) {
	a := nixis.SecurityLabel{Confidentiality: 100, Integrity: 80, Category: CatCredentials}
	bLabel := nixis.SecurityLabel{Confidentiality: 50, Integrity: 100, Category: CatFinance}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkLabel = Join(a, bLabel)
	}
}

func BenchmarkIFC_Meet(b *testing.B) {
	a := nixis.SecurityLabel{Confidentiality: 100, Integrity: 80, Category: CatCredentials}
	bLabel := nixis.SecurityLabel{Confidentiality: 50, Integrity: 100, Category: CatFinance}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkLabel = Meet(a, bLabel)
	}
}

func BenchmarkIFC_Elevate(b *testing.B) {
	s := &SessionLabels{}
	resource := nixis.SecurityLabel{Confidentiality: 50, Integrity: 50, Category: CatCredentials}
	// Pre-create session so getOrCreate doesn't dominate timing.
	s.getOrCreate("bench-sess")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkLabel = s.Elevate("bench-sess", resource)
	}
}
