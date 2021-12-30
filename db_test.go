package publicsuffix

import (
	"strconv"
	"testing"
)

func TestDB(t *testing.T) {
	type stage struct {
		hostname, ps string
		pos          int
	}

	small := []stage{
		{hostname: "google.org.ac", ps: "org.ac", pos: 7},
		{hostname: "github.ae", ps: "ae", pos: 7},
		{hostname: "unknown.no-ps", ps: "", pos: 0},
	}
	full := []stage{
		{hostname: "go.dev", ps: "dev", pos: 3},
		{hostname: "verylongverylongverylongverylongverylongverylonghostname.ipa.xyz", ps: "xyz", pos: 61},
	}

	loadFn := func(tb testing.TB, dbFile string, stages []stage) {
		var (
			psdb DB
			err  error
		)
		if err = psdb.Load(dbFile); err != nil {
			t.Error(err)
		}
		for _, s := range stages {
			ps, pos := psdb.GetStrWP(s.hostname)
			if ps != s.ps || pos != s.pos {
				t.Errorf("ps get fail: need '%s'/%d, got '%s'/%d", s.ps, s.pos, ps, pos)
			}
		}
	}
	fetchFn := func(tb testing.TB, dbURL string, stages []stage) {
		var (
			psdb DB
			err  error
		)
		if err = psdb.Fetch(dbURL); err != nil {
			t.Error(err)
		}
		for _, s := range stages {
			ps, pos := psdb.GetStrWP(s.hostname)
			if ps != s.ps || pos != s.pos {
				t.Errorf("ps get fail: need '%s'/%d, got '%s'/%d", s.ps, s.pos, ps, pos)
			}
		}
	}
	t.Run("load small", func(t *testing.T) { loadFn(t, "testdata/small.psdb", small) })
	t.Run("load full", func(t *testing.T) { loadFn(t, "testdata/full.psdb", full) })
	t.Run("fetch small", func(t *testing.T) {
		fetchFn(t, "https://raw.githubusercontent.com/koykov/publicsuffix/master/testdata/small.psdb", small)
	})
	t.Run("fetch full", func(t *testing.T) {
		fetchFn(t, "https://raw.githubusercontent.com/koykov/publicsuffix/master/testdata/full.psdb", full)
	})
}

func BenchmarkDB(b *testing.B) {
	var (
		psdb DB
		err  error
	)
	if err = psdb.Load("testdata/full.psdb"); err != nil {
		b.Error(err)
		return
	}

	type stage struct {
		hostname, ps string
		pos          int
	}
	stages := []stage{
		{hostname: "go.dev", ps: "dev", pos: 3},
		{hostname: "verylongverylongverylongverylongverylongverylonghostname.fhv.se", ps: "fhv.se", pos: 57},
		{hostname: "www.adobe.xyz", ps: "xyz", pos: 10},
		{hostname: "foobar.ru", ps: "ru", pos: 7},
		{hostname: "спб.рф", ps: "рф", pos: 7},
	}
	for i, s := range stages {
		b.Run(strconv.Itoa(i), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ps, pos := psdb.GetStrWP(s.hostname)
				if ps != s.ps || pos != s.pos {
					b.Errorf("ps get fail: need '%s'/%d, got '%s'/%d", s.ps, s.pos, ps, pos)
				}
			}
		})
	}
}
