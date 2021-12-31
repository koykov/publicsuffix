package mpsl

import (
	"testing"
	"time"

	"github.com/koykov/hash/fnv"
)

func TestIO(t *testing.T) {
	loadFn := func(tb testing.TB, dbFile string) {
		var (
			psdb *DB
			err  error
		)
		if psdb, err = New(fnv.BHasher{}); err != nil {
			t.Error(err)
		}
		if err = psdb.Load(dbFile); err != nil {
			t.Error(err)
		}
	}
	fetchFn := func(tb testing.TB, dbURL string) {
		var (
			psdb *DB
			err  error
		)
		if psdb, err = New(fnv.BHasher{}); err != nil {
			t.Error(err)
		}
		if err = psdb.Fetch(dbURL); err != nil {
			t.Error(err)
		}
	}
	t.Run("load small", func(t *testing.T) { loadFn(t, "testdata/small.psdb") })
	t.Run("load full", func(t *testing.T) { loadFn(t, "testdata/full.psdb") })
	t.Run("fetch small", func(t *testing.T) {
		fetchFn(t, "https://raw.githubusercontent.com/koykov/publicsuffix/master/testdata/small.psdb")
	})
	t.Run("fetch full", func(t *testing.T) {
		fetchFn(t, "https://raw.githubusercontent.com/koykov/publicsuffix/master/testdata/full.psdb")
	})
	t.Run("load or fetch", func(t *testing.T) {
		var (
			psdb *DB
			err  error
		)
		if psdb, err = New(fnv.BHasher{}); err != nil {
			t.Error(err)
		}
		if err = psdb.LoadOrFetchFullIf("testdata/lof.tmp", time.Second); err != nil {
			t.Error(err)
		}
	})
}

func TestGet(t *testing.T) {
	type stage struct {
		hostname,
		tld, etld, etld1 string
		icann bool
	}

	stages := []stage{
		{hostname: "google.org.ac", tld: "ac", etld: "org.ac", etld1: "google.org.ac", icann: false},
		{hostname: "github.ae", tld: "ae", etld: "", etld1: "github.ae", icann: false},
		{hostname: "unknown.no-tld", tld: "", etld: "", etld1: "", icann: false},
		{hostname: "go.dev", tld: "dev", etld: "", etld1: "go.dev", icann: false},
		{hostname: "verylongverylongverylongverylongverylongverylonghostname.ipa.xyz", tld: "xyz", etld: "", etld1: "ipa.xyz", icann: false},
	}

	var (
		psdb *DB
		err  error
	)
	if psdb, err = New(fnv.BHasher{}); err != nil {
		t.Error(err)
	}
	if err = psdb.Load("testdata/full.psdb"); err != nil {
		t.Error(err)
	}

	for _, s := range stages {
		t.Run(s.hostname, func(t *testing.T) {
			tld, etld, etld1, icann := psdb.SGet(s.hostname)
			if tld != s.tld {
				t.Errorf("tld mismatch: need '%s', got '%s'", s.tld, tld)
			}
			if etld != s.etld {
				t.Errorf("etld mismatch: need '%s', got '%s'", s.etld, etld)
			}
			if etld1 != s.etld1 {
				t.Errorf("etld+1 mismatch: need '%s', got '%s'", s.etld1, etld1)
			}
			_, _, _ = etld, etld1, icann
		})
	}
}

// func BenchmarkDB(b *testing.B) {
// 	var (
// 		psdb *DB
// 		err  error
// 	)
// 	if psdb, err = New(fnv.BHasher{}); err != nil {
// 		b.Error(err)
// 	}
// 	if err = psdb.Load("testdata/full.psdb"); err != nil {
// 		b.Error(err)
// 		return
// 	}
//
// 	type stage struct {
// 		hostname, ps string
// 		pos          int
// 	}
// 	stages := []stage{
// 		{hostname: "go.dev", ps: "dev", pos: 3},
// 		{hostname: "verylongverylongverylongverylongverylongverylonghostname.fhv.se", ps: "fhv.se", pos: 57},
// 		{hostname: "www.adobe.xyz", ps: "xyz", pos: 10},
// 		{hostname: "foobar.ru", ps: "ru", pos: 7},
// 		{hostname: "спб.рф", ps: "рф", pos: 7},
// 	}
// 	for i, s := range stages {
// 		b.Run(strconv.Itoa(i), func(b *testing.B) {
// 			b.ReportAllocs()
// 			for i := 0; i < b.N; i++ {
// 				ps, pos := psdb.GetStrWP(s.hostname)
// 				if ps != s.ps || pos != s.pos {
// 					b.Errorf("ps get fail: need '%s'/%d, got '%s'/%d", s.ps, s.pos, ps, pos)
// 				}
// 			}
// 		})
// 	}
// }
