package publicsuffix

import (
	"fmt"
	"sort"

	"github.com/koykov/fastconv"
)

type index struct {
	buf   []row
	bufl  int
	indFn func(entry) []byte
}

type row struct {
	buf   []entry
	indFn func(entry) []byte
}

func (i *index) add(e entry, dc int) {
	if i.bufl <= dc {
		for j := i.bufl; j <= dc; j++ {
			i.buf = append(i.buf, row{indFn: i.indFn})
			i.bufl++
		}
	}
	r := &i.buf[dc]
	r.buf = append(r.buf, e)
}

func (i *index) sort() {
	for j := 0; j < len(i.buf); j++ {
		fmt.Println("dc", j)
		for k := 0; k < len(i.buf[j].buf); k++ {
			fmt.Print(string(i.indFn(i.buf[j].buf[k])), " ")
		}
		sort.Sort(&i.buf[j])
		fmt.Println(" ")
		for k := 0; k < len(i.buf[j].buf); k++ {
			fmt.Print(string(i.indFn(i.buf[j].buf[k])), " ")
		}
		fmt.Println(" ")
	}
}

func (i index) search(p []byte, dc int) (entry, bool) {
	if dc >= len(i.buf) {
		return 0, false
	}
	r := i.buf[dc]
	j := sort.Search(r.Len(), func(x int) bool {
		return fastconv.B2S(p) < fastconv.B2S(r.indFn(r.buf[x]))
	})
	if j < r.Len() {
		return r.buf[j], true
	}
	return 0, false
}

func (i index) maxDC() int {
	return i.bufl
}

func (i *index) reset() {
	for j := 0; j < len(i.buf); j++ {
		i.buf[j].buf = i.buf[j].buf[:0]
	}
}

func (r row) Len() int {
	return len(r.buf)
}

func (r row) Less(i, j int) bool {
	ie, je := r.buf[i], r.buf[j]
	is, js := fastconv.B2S(r.indFn(ie)), fastconv.B2S(r.indFn(je))
	return is < js
}

func (r *row) Swap(i, j int) {
	r.buf[i], r.buf[j] = r.buf[j], r.buf[i]
}
