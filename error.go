package mpsl

import "errors"

var (
	ErrBadDB    = errors.New("cache uninitialized, use New()")
	ErrEmptyDB = errors.New("empty database")
	ErrNoHasher = errors.New("no hasher provided")
)
