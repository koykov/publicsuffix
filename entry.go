package mpsl

// Entry is a bitmask that stores low/high offsets of the PS in the database buffer, ICANN flag and type.
//
// The structure of the offset:
// * first bit - ICANN flag
// * next 7 bits - entry type
// * next 28 bits - low offset
// * last 28 bits - high offset
// low/high offsets has bitness 28 and may contain maximum 268435456. It's enough to store PSL data (<1 MB).
type entry uint64

// Encode params to entry.
func (e *entry) encode(lo, hi uint32, icann, typ uint8) {
	*e = entry(icann)<<63 | entry(typ)<<56 | entry(lo)<<28 | entry(hi)
}

// Decode params.
func (e entry) decode() (lo, hi uint32, icann, typ uint8) {
	icann = uint8(e >> 63)
	typ = uint8((e >> 56) & 0b01111111)
	lo = uint32((e >> 28) & 0x0fffffff)
	hi = uint32(e & 0x0fffffff)
	return
}
