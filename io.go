package mpsl

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
	"unicode"

	"github.com/koykov/bytealg"
	"github.com/koykov/fastconv"
	"golang.org/x/net/idna"
)

// Load extracts PSL data from the local file.
func (db *DB) Load(dbFile string) (err error) {
	if err = db.checkStatus(); err != nil {
		return err
	}

	db.mux.Lock()
	defer db.mux.Unlock()

	var file *os.File
	if file, err = os.OpenFile(dbFile, os.O_RDONLY, os.ModePerm); err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	return db.scan(scanner)
}

// Fetch loads PSL data from given URL.
func (db *DB) Fetch(dbURL string) (err error) {
	if err = db.checkStatus(); err != nil {
		return err
	}

	db.mux.Lock()
	defer db.mux.Unlock()

	var resp *http.Response
	if resp, err = http.Get(dbURL); err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()

	scanner := bufio.NewScanner(resp.Body)
	return db.scan(scanner)
}

// Internal scanner method.
func (db *DB) scan(scanner *bufio.Scanner) error {
	icann := false
	for scanner.Scan() {
		line := bytealg.TrimLeft(scanner.Bytes(), bSpace)
		if bytes.Equal(line, bBeginICANN) {
			icann = true
		}
		if bytes.Equal(line, bEndICANN) {
			icann = false
		}
		if psMustSkip(line) {
			continue
		}
		var (
			typ uint8
			off int
		)
		switch line[0] {
		case '*':
			typ = typeWildcard
			off = 2
		case '!':
			typ = typeException
			off = 1
		default:
			typ = typeRule
		}
		db.addLF(line[off:], icann, typ)
	}
	return scanner.Err()
}

// FetchFull loads full known PSL data from publicsuffix.org github profile.
func (db *DB) FetchFull() error {
	return db.Fetch(FullURL)
}

// LoadOrFetchIf loads PSL data from local file (if file is younger than expire param) or load data from given URL.
//
// After fetching from URL raw PSL data will be stored to local file (if possible).
func (db *DB) LoadOrFetchIf(dbFile, dbURL string, expire time.Duration) error {
	var fetch bool
	if stat, err := os.Stat(dbFile); errors.Is(err, os.ErrNotExist) || time.Since(stat.ModTime()) > expire {
		fetch = true
	}
	if fetch {
		if err := db.dl(dbURL, dbFile); err != nil {
			return err
		}
	}
	return db.Load(dbFile)
}

// LoadOrFetchFullIf is similar to LoadOrFetchIf but loads data from full URL.
func (db *DB) LoadOrFetchFullIf(dbFile string, expire time.Duration) error {
	return db.LoadOrFetchIf(dbFile, FullURL, expire)
}

// Internal downloader method.
func (db *DB) dl(src, dst string) error {
	dstt := dst + ".tmp"
	out, err := os.Create(dstt)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	resp, err := http.Get(src)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	var n int64
	if n, err = io.Copy(out, resp.Body); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("empty response: %s", src)
	}
	if err = os.Remove(dst); err != nil {
		return err
	}
	return os.Rename(dstt, dst)
}

// Add new rule to the index/buffer in lock-free mode.
func (db *DB) addLF(ps []byte, icann bool, typ uint8) {
	if len(ps) > 1 && bytes.Equal(ps[:2], bMaskAll) {
		ps = ps[2:]
	}
	psl := len(ps)
	if psl == 0 {
		return
	}

	h := db.hasher.Sum64(ps)

	lo := uint32(len(db.buf))
	hi := uint32(len(ps)) + lo
	switch typ {
	case typeException:
		// Exception rules stores in separate index.
		db.neg.set(h, lo, hi, icann, typ)
	default:
		db.idx.set(h, lo, hi, icann, typ)
	}
	db.buf = append(db.buf, ps...)

	// Check if need to punycode the rule.
	if !checkASCII(ps) {
		if ps1, err := idna.ToASCII(fastconv.B2S(ps)); err == nil {
			db.addLF(fastconv.S2B(ps1), icann, typ)
		}
	}

	return
}

// Check if line must be skip.
func psMustSkip(line []byte) bool {
	if len(line) == 0 || line[0] == '/' {
		return true
	}
	return false
}

// Check if line contain only ASCII chars.
func checkASCII(p []byte) bool {
	pl := len(p)
	var i int
loop:
	if p[i] > unicode.MaxASCII {
		return false
	}
	if i += 1; i < pl {
		goto loop
	}
	return true
}
