package mpsl

import (
	"sync"
	"sync/atomic"

	"github.com/koykov/bytealg"
	"github.com/koykov/fastconv"
	"github.com/koykov/hash"
)

const (
	// FullURL of full known PSL data.
	FullURL = "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat"
)

const (
	// Database status.
	statusNil    = 0
	statusActive = 1

	// Rule types: regular rule (.com), wildcard (*.ck) and exception (!www.ck).
	typeRule      = 0
	typeWildcard  = 1
	typeException = 2
)

// DB is an implementation of Mozilla Public Suffix List database.
type DB struct {
	mux    sync.RWMutex
	status uint32
	// Hash helper to convert strings to uint64 values (to follow pointers reducing policy).
	hasher hash.BHasher
	// Database entry indexes: regular/wildcard and exceptions.
	idx, neg index
	// Monolith entries storage.
	buf []byte
}

var (
	// Byte constants.
	bSpace      = []byte(" ")
	bDot        = []byte(".")
	bMaskAll    = []byte("*.")
	bBeginICANN = []byte("// ===BEGIN ICANN DOMAINS===")
	bEndICANN   = []byte("// ===END ICANN DOMAINS===")
)

// New makes new instance of the DB.
func New(hasher hash.BHasher) (*DB, error) {
	if hasher == nil {
		return nil, ErrNoHasher
	}
	db := &DB{
		status: statusActive,
		hasher: hasher,
		idx:    make(index),
		neg:    make(index),
	}
	return db, nil
}

// Parse parses hostname to separate parts: TLD, eTLD, eTLD1 and ICANN flag.
func (db *DB) Parse(hostname []byte) (tld, etld, etld1 []byte, icann bool) {
	if err := db.checkStatus(); err != nil {
		return
	}
	hl := len(hostname)
	if hl < 2 {
		return
	}

	db.mux.RLock()
	defer db.mux.RUnlock()

	var off, poff int
	for i := 0; ; i++ {
		poff = off
		// Walk over dots in hostname.
		if off = bytealg.IndexAt(hostname, bDot, off); off == -1 {
			if i > 0 {
				etld1 = hostname
			}
			break
		}
		off++
		// Take next possible part. Example: for hostname "a.b.c.org" the steps:
		// * b.c.org
		// * c.org
		// * org
		p := hostname[off:]
		// Calculate hash of part and check it in the index.
		h := db.hasher.Sum64(p)
		if e, ok := db.idx[h]; ok {
			// Entry found for current part - decode it.
			lo, hi, f, typ := e.decode()
			// Use different method to parse wildcard and regular rules.
			if typ == typeWildcard {
				tld, etld, etld1 = db.checkWC(hostname, off, poff)
			} else {
				tld, etld, etld1 = db.checkRule(hostname, off, lo, hi)
			}
			// Finally, check ICANN flag.
			icann = f == 1
			return
		}
	}

	return
}

// Check wildcard rule.
func (db *DB) checkWC(origin []byte, off, poff int) (tld, etld, etld1 []byte) {
	// Assume that wildcard rule doesn't have exception.
	eb := origin[poff:]
	nh := db.hasher.Sum64(eb)
	x := poff
	if _, ok := db.neg[nh]; ok {
		// Current hostname matches with exception rule - use current part as TLD/eTDL.
		eb = origin[off:]
		x = off
	}
	// Calculate offsets of TLD/eTLD/eTLD1.
	dc, _, lp := dcOf(eb)
	if dc == 0 {
		tld = eb
	} else {
		tld = eb[lp+1:]
		etld = eb
	}
	etld1 = origin[prevDot(origin, x):]
	return
}

// Check regular rule.
//
// Similar to checkWC.
func (db *DB) checkRule(origin []byte, off int, lo, hi uint32) (tld, etld, etld1 []byte) {
	eb := db.buf[lo:hi]
	dc, _, lp := dcOf(eb)
	if dc == 0 {
		tld = eb
	} else {
		tld = eb[lp+1:]
		etld = eb
	}
	etld1 = origin[prevDot(origin, off):]
	return
}

// ParseStr parses hostname string to separate parts: TLD, eTLD, eTLD1 and ICANN flag.
func (db *DB) ParseStr(hostname string) (tld, etld, etld1 string, icann bool) {
	var btld, betld, betld1 []byte
	btld, betld, betld1, icann = db.Parse(fastconv.S2B(hostname))
	tld, etld, etld1 = fastconv.B2S(btld), fastconv.B2S(betld), fastconv.B2S(betld1)
	return
}

// Reset flushes all database data.
func (db *DB) Reset() {
	if err := db.checkStatus(); err != nil {
		return
	}
	db.mux.Lock()
	db.idx.reset()
	db.buf = db.buf[:0]
	db.mux.Unlock()
}

func (db *DB) checkStatus() error {
	if atomic.LoadUint32(&db.status) == statusNil {
		return ErrBadDB
	}
	return nil
}

// Check dots count in the p.
//
// Returns count and offsets of first and last dots.
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

// Get offset of previous dot starting from pos.
func prevDot(p []byte, pos int) (x int) {
	for i := pos - 2; i > 0; i-- {
		if p[i] == '.' {
			x = i + 1
			break
		}
	}
	return
}
