package main

import (
	"encoding/binary"
	"testing"
)

func TestEchoReturnsValidIPAndICMP(t *testing.T) {
	p := make([]byte, 32)
	p[0] = 0x45
	p[8] = 64
	p[9] = 1
	binary.BigEndian.PutUint16(p[2:4], 32)
	copy(p[12:16], []byte{10, 66, 67, 254})
	copy(p[16:20], []byte{198, 18, 171, 1})
	p[20] = 8
	copy(p[28:], []byte("test"))
	binary.BigEndian.PutUint16(p[22:24], sum(p[20:]))
	binary.BigEndian.PutUint16(p[10:12], sum(p[:20]))
	r := echo(p)
	if r == nil || r[20] != 0 || sum(r[:20]) != 0 || sum(r[20:]) != 0 || r[12] != 198 || r[16] != 10 {
		t.Fatal("invalid echo reply")
	}
	p[9] = 17
	if echo(p) != nil {
		t.Fatal("fixture must not proxy arbitrary UDP")
	}
}
