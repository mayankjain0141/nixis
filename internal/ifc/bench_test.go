package ifc

import (
	"testing"

	"github.com/mayjain/aegis/pkg/aegis"
)

var (
	sinkBool  bool
	sinkLabel aegis.SecurityLabel
)

func BenchmarkIFC_Dominates(b *testing.B) {
	subject := aegis.SecurityLabel{Confidentiality: 100, Integrity: 100, Category: CatCredentials | CatFinance}
	object := aegis.SecurityLabel{Confidentiality: 50, Integrity: 50, Category: CatCredentials}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkBool = Dominates(subject, object)
	}
}

func BenchmarkIFC_Join(b *testing.B) {
	a := aegis.SecurityLabel{Confidentiality: 100, Integrity: 80, Category: CatCredentials}
	bLabel := aegis.SecurityLabel{Confidentiality: 50, Integrity: 100, Category: CatFinance}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkLabel = Join(a, bLabel)
	}
}

func BenchmarkIFC_Meet(b *testing.B) {
	a := aegis.SecurityLabel{Confidentiality: 100, Integrity: 80, Category: CatCredentials}
	bLabel := aegis.SecurityLabel{Confidentiality: 50, Integrity: 100, Category: CatFinance}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkLabel = Meet(a, bLabel)
	}
}

func BenchmarkIFC_Elevate(b *testing.B) {
	s := &SessionLabels{}
	resource := aegis.SecurityLabel{Confidentiality: 50, Integrity: 50, Category: CatCredentials}
	// Pre-create session so loadOrCreate doesn't dominate timing.
	s.loadOrCreate("bench-sess")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkLabel = s.Elevate("bench-sess", resource)
	}
}
