package mpsl

func (db *DB) GetTLD(hostname []byte) (tld []byte, icann bool) {
	_, _, tld, icann = db.Parse(hostname)
	return
}

func (db *DB) GetEffectiveTLD(hostname []byte) (etld []byte) {
	_, etld, _, _ = db.Parse(hostname)
	return
}

func (db *DB) GetEffectiveTLDPlusOne(hostname []byte) (etld1 []byte) {
	etld1, _, _, _ = db.Parse(hostname)
	return
}

func (db *DB) GetETLD(hostname []byte) []byte {
	return db.GetEffectiveTLD(hostname)
}

func (db *DB) GetETLD1(hostname []byte) []byte {
	return db.GetEffectiveTLDPlusOne(hostname)
}
