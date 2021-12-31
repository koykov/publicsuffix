package mpsl

import "github.com/koykov/fastconv"

func (db *DB) SGetTLD(hostname string) (tld string, icann bool) {
	var btld []byte
	_, _, btld, icann = db.Get(fastconv.S2B(hostname))
	tld = fastconv.B2S(btld)
	return
}

func (db *DB) SGetETLD(hostname string) (etld string) {
	_, betld, _, _ := db.Get(fastconv.S2B(hostname))
	etld = fastconv.B2S(betld)
	return
}

func (db *DB) SGetETLD1(hostname string) (etld1 string) {
	betld1, _, _, _ := db.Get(fastconv.S2B(hostname))
	etld1 = fastconv.B2S(betld1)
	return
}

func (db *DB) SGet(hostname string) (tld, etld, etld1 string, icann bool) {
	var btld, betld, betld1 []byte
	btld, betld, betld1, icann = db.Get(fastconv.S2B(hostname))
	tld, etld, etld1 = fastconv.B2S(btld), fastconv.B2S(betld), fastconv.B2S(betld1)
	return
}
