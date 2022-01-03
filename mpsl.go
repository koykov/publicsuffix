package mpsl

import (
	"sync/atomic"

	"github.com/koykov/bytealg"
	"github.com/koykov/fastconv"
	"github.com/koykov/hash"
	"github.com/koykov/policy"
)

const (
	FullURL = "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat"
)

const (
	statusNil = iota
	statusActive
)

type DB struct {
	policy.RWLock
	status uint32
	hasher hash.BHasher
	index  index
	buf    []byte
}

var (
	bSpace      = []byte(" ")
	bDot        = []byte(".")
	bMaskAll    = []byte("*.")
	bBeginICANN = []byte("// ===BEGIN ICANN DOMAINS===")
	bEndICANN   = []byte("// ===END ICANN DOMAINS===")
)

func New(hasher hash.BHasher) (*DB, error) {
	if hasher == nil {
		return nil, ErrNoHasher
	}
	db := &DB{
		status: statusActive,
		hasher: hasher,
		index:  make(index),
	}
	return db, nil
}

func (db *DB) Parse(hostname []byte) (tld, etld, etld1 []byte, icann bool) {
	if err := db.checkStatus(); err != nil {
		return
	}
	hl := len(hostname)
	if hl < 2 {
		return
	}

	db.RLock()
	defer db.RUnlock()

	var off int
	for i := 0; ; i++ {
		if off = bytealg.IndexAt(hostname, bDot, off); off == -1 {
			if i > 0 {
				etld1 = hostname
			}
			break
		}
		off++
		p := hostname[off:]
		h := db.hasher.Sum64(p)
		if e, ok := db.index[h]; ok {
			lo, hi, f := e.decode()
			eb := db.buf[lo:hi]
			dc, _, lp := dcOf(eb)
			if dc == 0 {
				tld = eb
			} else {
				tld = eb[lp+1:]
				etld = eb
			}
			var x int
			for i := off - 2; i > 0; i-- {
				if hostname[i] == '.' {
					x = i + 1
					break
				}
			}
			etld1 = hostname[x:]
			icann = f == 1
			return
		}
	}

	return
}

func (db *DB) ParseStr(hostname string) (tld, etld, etld1 string, icann bool) {
	var btld, betld, betld1 []byte
	btld, betld, betld1, icann = db.Parse(fastconv.S2B(hostname))
	tld, etld, etld1 = fastconv.B2S(btld), fastconv.B2S(betld), fastconv.B2S(betld1)
	return
}

func (db *DB) Reset() {
	if err := db.checkStatus(); err != nil {
		return
	}
	db.SetPolicy(policy.Locked)
	db.Lock()
	db.index.reset()
	db.buf = db.buf[:0]
	db.Unlock()
	db.SetPolicy(policy.LockFree)
}

func (db *DB) checkStatus() error {
	if atomic.LoadUint32(&db.status) == statusNil {
		return ErrBadDB
	}
	return nil
}

func dcOf(p []byte) (dc, fp, lp int) {
	off := 0
loop:
	if off = bytealg.IndexAt(p, bDot, off); off != -1 {
		if dc == 0 {
			fp = off
		}
		lp = off
		dc++
		off++
		goto loop
	}
	return
}
