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
		{hostname: "google.org.ac", tld: "ac", etld: "org.ac", etld1: "google.org.ac", icann: true},
		{hostname: "github.ae", tld: "ae", etld: "", etld1: "github.ae", icann: true},
		{hostname: "unknown.no-tld", tld: "", etld: "", etld1: "", icann: false},
		{hostname: "go.dev", tld: "dev", etld: "", etld1: "go.dev", icann: true},
		{hostname: "verylongverylongverylongverylongverylongverylonghostname.ipa.xyz", tld: "xyz", etld: "", etld1: "ipa.xyz", icann: true},
		{hostname: "example.com", tld: "com", etld: "", etld1: "example.com", icann: true},
		{hostname: "example.id.au", tld: "au", etld: "id.au", etld1: "example.id.au", icann: true},
		{hostname: "www.ck", tld: "ck", etld: "", etld1: "www.ck", icann: true},
		{hostname: "foo.bar.xn--55qx5d.cn", tld: "cn", etld: "xn--55qx5d.cn", etld1: "bar.xn--55qx5d.cn", icann: true},
		{hostname: "a.b.c.minami.fukuoka.jp", tld: "jp", etld: "minami.fukuoka.jp", etld1: "c.minami.fukuoka.jp", icann: true},
		{hostname: "posts-and-telecommunications.museum", tld: "museum", etld: "", etld1: "posts-and-telecommunications.museum", icann: true},
		{hostname: "www.example.pvt.k12.ma.us", tld: "us", etld: "pvt.k12.ma.us", etld1: "example.pvt.k12.ma.us", icann: true},
		{hostname: "many.lol", tld: "lol", etld: "", etld1: "many.lol", icann: true},
		{hostname: "the.russian.for.moscow.is.xn--80adxhks", tld: "xn--80adxhks", etld: "", etld1: "is.xn--80adxhks", icann: true},
		{hostname: "blah.blah.s3-us-west-1.amazonaws.com", tld: "com", etld: "s3-us-west-1.amazonaws.com", etld1: "blah.s3-us-west-1.amazonaws.com", icann: false},
		{hostname: "thing.dyndns.org", tld: "org", etld: "dyndns.org", etld1: "thing.dyndns.org", icann: false},
		{hostname: "nosuchtld", tld: "", etld: "", etld1: ""},
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
			if icann != s.icann {
				t.Errorf("icann mismatch: need '%t', got '%t'", s.icann, icann)
			}
		})
	}
}

func BenchmarkDB(b *testing.B) {
	var (
		psdb *DB
		err  error
	)
	if psdb, err = New(fnv.BHasher{}); err != nil {
		b.Error(err)
	}
	if err = psdb.Load("testdata/full.psdb"); err != nil {
		b.Error(err)
		return
	}

	type stage struct {
		hostname,
		tld, etld, etld1 string
		icann bool
	}
	stages := []stage{
		{hostname: "go.dev", tld: "dev", etld: "", etld1: "go.dev", icann: true},
		{hostname: "verylongverylongverylongverylongverylongverylonghostname.ipa.xyz", tld: "xyz", etld: "", etld1: "ipa.xyz", icann: true},
		{hostname: "www.adobe.xyz", tld: "xyz", etld: "", etld1: "adobe.xyz", icann: true},
		{hostname: "foobar.ru", tld: "ru", etld: "", etld1: "foobar.ru", icann: true},
		{hostname: "спб.рф", tld: "рф", etld: "", etld1: "спб.рф", icann: true},

		{hostname: "example.com", tld: "com", etld: "", etld1: "example.com", icann: true},
		{hostname: "example.id.au", tld: "au", etld: "id.au", etld1: "example.id.au", icann: true},
		{hostname: "www.ck", tld: "ck", etld: "", etld1: "www.ck", icann: true},
		// {hostname: "foo.bar.xn--55qx5d.cn", tld: "cn", etld: "", etld1: "bar.xn--55qx5d.cn", icann: true},
		{hostname: "a.b.c.minami.fukuoka.jp", tld: "jp", etld: "minami.fukuoka.jp", etld1: "c.minami.fukuoka.jp", icann: true},
		{hostname: "posts-and-telecommunications.museum", tld: "museum", etld: "", etld1: "posts-and-telecommunications.museum", icann: true},
		{hostname: "www.example.pvt.k12.ma.us", tld: "us", etld: "pvt.k12.ma.us", etld1: "example.pvt.k12.ma.us", icann: true},
		{hostname: "many.lol", tld: "lol", etld: "", etld1: "many.lol", icann: true},
		// {hostname: "the.russian.for.moscow.is.xn--80adxhks", "is.xn--80adxhks",
		{hostname: "blah.blah.s3-us-west-1.amazonaws.com", tld: "com", etld: "s3-us-west-1.amazonaws.com", etld1: "blah.s3-us-west-1.amazonaws.com", icann: false},
		{hostname: "thing.dyndns.org", tld: "org", etld: "dyndns.org", etld1: "thing.dyndns.org", icann: false},
		{hostname: "nosuchtld", tld: "", etld: "", etld1: ""},
	}
	for _, s := range stages {
		b.Run(s.hostname, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tld, etld, etld1, icann := psdb.SGet(s.hostname)
				if tld != s.tld {
					b.Errorf("tld mismatch: need '%s', got '%s'", s.tld, tld)
				}
				if etld != s.etld {
					b.Errorf("etld mismatch: need '%s', got '%s'", s.etld, etld)
				}
				if etld1 != s.etld1 {
					b.Errorf("etld+1 mismatch: need '%s', got '%s'", s.etld1, etld1)
				}
				if icann != s.icann {
					b.Errorf("icann mismatch: need '%t', got '%t'", s.icann, icann)
				}
			}
		})
	}
}

// func BenchmarkASCII(b *testing.B) {
//
// }
