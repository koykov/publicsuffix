package publicsuffix

import (
	"bytes"
	"fmt"

	"github.com/koykov/fastconv"
)

type namespace struct {
	idx []entry
	buf []byte
}

func (n *namespace) add(ps []byte) {
	var c int
	for _, i := range ps {
		if i == '.' {
			c++
		}
	}
	if c > 2 {
		fmt.Println(string(ps))
	}
	var e entry
	lo := uint32(len(n.buf))
	hi := uint32(len(ps)) + lo
	e.encode(lo, hi)
	n.idx = append(n.idx, e)
	n.buf = append(n.buf, ps...)
}

func (n namespace) Len() int {
	return len(n.idx)
}

func (n namespace) Less(i, j int) bool {
	ie, je := n.idx[i], n.idx[j]
	is, js := fastconv.B2S(n.entryBytes(ie)), fastconv.B2S(n.entryBytes(je))
	return is < js
}

func (n *namespace) Swap(i, j int) {
	n.idx[i], n.idx[j] = n.idx[j], n.idx[i]
}

func (n namespace) entryBytes(e entry) []byte {
	lo, hi := e.decode()
	return n.buf[lo:hi]
}

func (n namespace) hostHasEntry(hostname []byte, hl int, e entry) (ps []byte, pos int, ok bool) {
	pos = -1
	a := n.entryBytes(e)
	al := len(a)
	if hl < al+1 {
		return
	}
	b := hostname[hl-al-1:]
	fmt.Println(string(a), " - ", string(b))
	if b[0] == '.' && bytes.Equal(a, b[1:]) {
		ps = b[1:]
		pos = hl - al
		ok = true
	}
	return
}

func (n *namespace) reset() {
	n.idx = n.idx[:0]
	n.buf = n.buf[:0]
}
