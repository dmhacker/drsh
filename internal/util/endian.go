package util

import (
	"encoding/binary"
)

func Ntohs(i uint16) uint16 {
	arr := make([]byte, 2)
	arr[0] = uint8(i >> 8)
	arr[1] = uint8(i & 0xFF)
	return binary.BigEndian.Uint16(arr)
}

func Htons(i uint16) uint16 {
	arr := make([]byte, 2)
	binary.BigEndian.PutUint16(arr, i)
	res := uint16(arr[0])
	res <<= 8
	res |= uint16(arr[1])
	return res
}

func Unpack64(i uint64) []uint16 {
	res := make([]uint16, 4)
	res[0] = Ntohs(uint16(i >> 48))
	res[1] = Ntohs(uint16((i >> 32) & 0xFFFF))
	res[2] = Ntohs(uint16((i >> 16) & 0xFFFF))
	res[3] = Ntohs(uint16(i & 0xFFFF))
	return res
}

func Pack64(a uint16, b uint16, c uint16, d uint16) uint64 {
	return (uint64(Htons(a)) << 48) | (uint64(Htons(b)) << 32) | (uint64(Htons(c)) << 16) | uint64(Htons(d))
}
