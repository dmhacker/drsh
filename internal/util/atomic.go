package util

import (
	"sync/atomic"
)

func numeric(value bool) uint32 {
	if value {
		return 1
	} else {
		return 0
	}
}

type AtomicBoolean struct {
	value uint32
}

func NewAtomicBoolean(value bool) AtomicBoolean {
	return AtomicBoolean{
		value: numeric(value),
	}
}

func (ab *AtomicBoolean) Get() bool {
	return atomic.LoadUint32(&ab.value) != 0
}

func (ab *AtomicBoolean) Set(value bool) {
	atomic.StoreUint32(&ab.value, numeric(value))
}
