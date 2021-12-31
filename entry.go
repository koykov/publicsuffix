package mpsl

type entry uint64

func (e *entry) encode(lo, hi uint32, f uint8) {
	*e = entry(lo)<<32 | entry(hi)<<1 | entry(f)
}

func (e entry) decode() (lo, hi uint32, f uint8) {
	lo = uint32(e >> 32)
	hi = uint32((e << 32) >> 33)
	f = uint8((e << 63) >> 63)
	return
}
