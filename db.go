package publicsuffix

import (
	"bufio"
	"bytes"
	"net/http"
	"os"
	"sync"
	"sync/atomic"

	"github.com/koykov/bytealg"
	"github.com/koykov/fastconv"
)

const (
	fullURL = "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat"
)

type DB struct {
	rl, wl uint32

	idx index
	buf []byte

	once sync.Once
}

var (
	bSpace   = []byte(" ")
	bDot     = []byte(".")
	bMaskAll = []byte("*.")
)

func NewDB() *DB {
	db := &DB{}
	db.once.Do(db.init)
	return db
}

func (m *DB) init() {
	m.rl, m.wl = 1, 0
	m.idx.indFn = m.entryBytes
}

func (m *DB) Load(dbFile string) (err error) {
	m.once.Do(m.init)

	atomic.StoreUint32(&m.rl, 1)
	defer m.Commit()

	var file *os.File
	if file, err = os.OpenFile(dbFile, os.O_RDONLY, os.ModePerm); err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	scan := bufio.NewScanner(file)
	for scan.Scan() {
		line := bytealg.TrimLeft(scan.Bytes(), bSpace)
		if psMustSkip(line) {
			continue
		}
		m.add(line)
	}
	err = scan.Err()

	return
}

func (m *DB) Fetch(dbURL string) (err error) {
	m.once.Do(m.init)

	atomic.StoreUint32(&m.rl, 1)
	defer m.Commit()

	var resp *http.Response
	if resp, err = http.Get(dbURL); err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()

	scan := bufio.NewScanner(resp.Body)
	for scan.Scan() {
		line := bytealg.TrimLeft(scan.Bytes(), bSpace)
		if psMustSkip(line) {
			continue
		}
		m.add(line)
	}
	err = scan.Err()

	return
}

func (m *DB) FetchFull() error {
	return m.Fetch(fullURL)
}

func (m *DB) add(ps []byte) {
	if atomic.LoadUint32(&m.wl) == 1 {
		return
	}
	if len(ps) > 1 && bytes.Equal(ps[:2], bMaskAll) {
		ps = ps[2:]
	}
	psl := len(ps)
	if psl == 0 {
		return
	}

	var e entry
	lo := uint32(len(m.buf))
	hi := uint32(len(ps)) + lo
	e.encode(lo, hi)
	m.idx.add(e, dcOf(ps))
	m.buf = append(m.buf, ps...)

	return
}

func (m *DB) AddStr(ps string) {
	m.add(fastconv.S2B(ps))
}

func (m *DB) Commit() {
	atomic.StoreUint32(&m.wl, 1)
	m.idx.sort()
	atomic.StoreUint32(&m.rl, 0)
}

func (m *DB) Get(hostname []byte) (ps []byte) {
	ps, _ = m.GetWP(hostname)
	return
}

func (m *DB) GetWP(hostname []byte) ([]byte, int) {
	if atomic.LoadUint32(&m.rl) == 1 {
		return nil, -1
	}
	hl := len(hostname)
	if hl < 2 {
		return nil, -1
	}

	var off, dc int
	if dc = dcOf(hostname) - 1; dc < 0 {
		return nil, -1
	}
	for {
		if off = bytealg.IndexAt(hostname, bDot, off); off == -1 {
			break
		}
		off++
		p := hostname[off:]
		e, ok := m.idx.search(p, dc)
		if ok {
			return nil, 0
		}
		if dc -= 1; dc == -1 {
			break
		}
		_, _ = e, ok
	}

	return nil, -1
}

func (m *DB) GetStr(hostname string) (ps string) {
	ps, _ = m.GetStrWP(hostname)
	return
}

func (m *DB) GetStrWP(hostname string) (ps string, pos int) {
	x, p := m.GetWP(fastconv.S2B(hostname))
	if p == -1 {
		return
	}
	ps, pos = fastconv.B2S(x), p
	return
}

func (m *DB) entryBytes(e entry) []byte {
	lo, hi := e.decode()
	if hi >= uint32(len(m.buf)) || lo > hi {
		return nil
	}
	return m.buf[lo:hi]
}

func (m *DB) Reset() {
	atomic.StoreUint32(&m.rl, 1)
	m.idx.reset()
	atomic.StoreUint32(&m.wl, 0)
}

func psMustSkip(line []byte) bool {
	if len(line) == 0 || line[0] == '/' || line[0] == '!' {
		return true
	}
	return false
}

func dcOf(p []byte) (dc int) {
	off := 0
loop:
	if off = bytealg.IndexAt(p, bDot, off); off != -1 {
		dc++
		off++
		goto loop
	}
	return
}
