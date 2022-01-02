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

	"github.com/koykov/bytealg"
	"github.com/koykov/fastconv"
	"github.com/koykov/policy"
	"golang.org/x/net/idna"
)

func (db *DB) Load(dbFile string) (err error) {
	if err = db.checkStatus(); err != nil {
		return err
	}

	db.SetPolicy(policy.Locked)
	db.Lock()
	defer func() {
		db.Unlock()
		db.SetPolicy(policy.LockFree)
	}()

	var file *os.File
	if file, err = os.OpenFile(dbFile, os.O_RDONLY, os.ModePerm); err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	return db.scan(scanner)
}

func (db *DB) Fetch(dbURL string) (err error) {
	if err = db.checkStatus(); err != nil {
		return err
	}

	db.SetPolicy(policy.Locked)
	db.Lock()
	defer func() {
		db.Unlock()
		db.SetPolicy(policy.LockFree)
	}()

	var resp *http.Response
	if resp, err = http.Get(dbURL); err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()

	scanner := bufio.NewScanner(resp.Body)
	return db.scan(scanner)
}

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
		db.addLF(line, icann)
	}
	return scanner.Err()
}

func (db *DB) FetchFull() error {
	return db.Fetch(FullURL)
}

func (db *DB) LoadOrFetchIf(dbFile, dbURL string, expire time.Duration) error {
	var fetch bool
	if stat, err := os.Stat(dbFile); errors.Is(err, os.ErrNotExist) || time.Since(stat.ModTime()) > expire {
		fetch = true
	}
	if fetch {
		_ = db.dl(dbURL, dbFile)
	}
	return db.Load(dbFile)
}

func (db *DB) dl(src, dst string) error {
	out, err := os.Create(dst)
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

	_, err = io.Copy(out, resp.Body)
	return err
}

func (db *DB) LoadOrFetchFullIf(dbFile string, expire time.Duration) error {
	return db.LoadOrFetchIf(dbFile, FullURL, expire)
}

func (db *DB) addLF(ps []byte, icann bool) {
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
	db.index.set(h, lo, hi, icann)
	db.buf = append(db.buf, ps...)

	if !checkASCII(ps) {
		if ps1, err := idna.ToASCII(fastconv.B2S(ps)); err == nil {
			db.addLF(fastconv.S2B(ps1), icann)
		}
	}

	return
}
