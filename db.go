package publicsuffix

import (
	"bufio"
	"bytes"
	"net/http"
	"os"
	"sort"
	"sync/atomic"

	"github.com/koykov/bytealg"
	"github.com/koykov/fastconv"
)

const (
	fullURL = "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat"
)

type DB struct {
	rl, wl   uint32
	nsr, nsc namespace
}

var (
	bSpace   = []byte(" ")
	bMaskAll = []byte("*.")
)

func (m *DB) Load(dbFile string) (err error) {
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
		m.Add(line)
	}
	err = scan.Err()

	return
}

func (m *DB) Fetch(dbURL string) (err error) {
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
		m.Add(line)
	}
	err = scan.Err()

	return
}

func (m *DB) FetchFull() error {
	return m.Fetch(fullURL)
}

func (m *DB) Add(ps []byte) {
	if atomic.LoadUint32(&m.wl) == 1 {
		return
	}
	if bytes.Equal(ps[:2], bMaskAll) {
		ps = ps[2:]
	}
	if len(ps) == 0 {
		return
	}
	if !bytealg.HasByteLR(ps, '.') {
		m.nsr.add(ps)
		return
	}
	m.nsc.add(ps)
	return
}

func (m *DB) AddStr(ps string) {
	m.Add(fastconv.S2B(ps))
}

func (m *DB) Commit() {
	atomic.StoreUint32(&m.wl, 1)
	sort.Sort(&m.nsr)
	sort.Sort(&m.nsc)
	atomic.StoreUint32(&m.rl, 0)
}

func (m DB) Get(hostname []byte) (ps []byte) {
	ps, _ = m.GetWP(hostname)
	return
}

func (m DB) GetWP(hostname []byte) ([]byte, int) {
	if atomic.LoadUint32(&m.rl) == 1 {
		return nil, -1
	}
	hl := len(hostname)
	if hl < 2 {
		return nil, -1
	}
	i := sort.Search(m.nsc.Len(), func(i int) bool {
		_, _, ok := m.nsc.hostHasEntry(hostname, hl, m.nsc.idx[i])
		return ok
	})
	if i < m.nsc.Len() {
		e := m.nsc.idx[i]
		ps, pos, _ := m.nsc.hostHasEntry(hostname, hl, e)
		return ps, pos
	}

	i = sort.Search(m.nsr.Len(), func(i int) bool {
		_, _, ok := m.nsr.hostHasEntry(hostname, hl, m.nsr.idx[i])
		return ok
	})
	if i < m.nsr.Len() {
		e := m.nsr.idx[i]
		ps, pos, _ := m.nsr.hostHasEntry(hostname, hl, e)
		return ps, pos
	} else {
		return nil, -1
	}
}

func (m DB) GetStr(hostname string) (ps string) {
	ps, _ = m.GetStrWP(hostname)
	return
}

func (m DB) GetStrWP(hostname string) (ps string, pos int) {
	x, p := m.GetWP(fastconv.S2B(hostname))
	if p == -1 {
		return
	}
	ps, pos = fastconv.B2S(x), p
	return
}

func (m *DB) Reset() {
	atomic.StoreUint32(&m.rl, 1)
	m.nsr.reset()
	m.nsc.reset()
	atomic.StoreUint32(&m.wl, 0)
}

func psMustSkip(line []byte) bool {
	if len(line) == 0 || line[0] == '/' || line[0] == '!' {
		return true
	}
	return false
}
