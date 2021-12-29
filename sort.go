package publicsuffix

import (
	"strings"

	"github.com/koykov/fastconv"
)

func (m *DB) Len() int {
	return m.idxl
}

func (m *DB) Less(i, j int) bool {
	ie, je := m.idx[i], m.idx[j]
	is, js := fastconv.B2S(m.entryBytes(ie)), fastconv.B2S(m.entryBytes(je))
	if !strings.Contains(is, ",") && strings.Contains(js, ".") {
		return false
	}
	return is < js
}

func (m *DB) Swap(i, j int) {
	m.idx[i], m.idx[j] = m.idx[j], m.idx[i]
}
