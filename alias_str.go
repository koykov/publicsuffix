package mpsl

import "github.com/koykov/fastconv"

func (db *DB) GetTLDStr(hostname string) (tld string, icann bool) {
	var btld []byte
	_, _, btld, icann = db.Parse(fastconv.S2B(hostname))
	tld = fastconv.B2S(btld)
	return
}

func (db *DB) GetEffectiveTLDStr(hostname string) (etld string) {
	_, betld, _, _ := db.Parse(fastconv.S2B(hostname))
	etld = fastconv.B2S(betld)
	return
}

func (db *DB) GetEffectiveTLDPlusOneStr(hostname string) (etld1 string) {
	_, _, betld1, _ := db.Parse(fastconv.S2B(hostname))
	etld1 = fastconv.B2S(betld1)
	return
}

func (db *DB) GetETLDStr(hostname string) string {
	return db.GetEffectiveTLDStr(hostname)
}

func (db *DB) GetETLD1Str(hostname string) string {
	return db.GetEffectiveTLDPlusOneStr(hostname)
}
