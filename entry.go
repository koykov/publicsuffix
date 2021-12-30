package mpsl

type entry uint64

func (e *entry) encode(lo, hi uint32) {
	*e = entry(lo)<<32 | entry(hi)
}

func (e entry) decode() (lo, hi uint32) {
	lo = uint32(e >> 32)
	hi = uint32(e & 0xffffffff)
	return
}
