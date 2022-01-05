package mpsl

// GetTLD returns TLD part of hostname and ICANN flag.
func (db *DB) GetTLD(hostname []byte) (tld []byte, icann bool) {
	_, _, tld, icann = db.Parse(hostname)
	return
}

// GetEffectiveTLD returns only eTLD part of hostname.
func (db *DB) GetEffectiveTLD(hostname []byte) (etld []byte) {
	_, etld, _, _ = db.Parse(hostname)
	return
}

// GetEffectiveTLDPlusOne return only eTLD1 part of hostname.
func (db *DB) GetEffectiveTLDPlusOne(hostname []byte) (etld1 []byte) {
	etld1, _, _, _ = db.Parse(hostname)
	return
}

// GetETLD is a shorthand alias of GetEffectiveTLD.
func (db *DB) GetETLD(hostname []byte) []byte {
	return db.GetEffectiveTLD(hostname)
}

// GetETLD1 is a shorthand alias of GetEffectiveTLDPlusOne.
func (db *DB) GetETLD1(hostname []byte) []byte {
	return db.GetEffectiveTLDPlusOne(hostname)
}
