// Originally derived from: btcsuite/btcd/wire/bench_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmutil

import (
	"bytes"
	"io/ioutil"
	"testing"
)

// BenchmarkWriteVarInt1 performs a benchmark on how long it takes to write
// a single byte variable length integer.
func BenchmarkWriteVarInt1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		WriteVarInt(ioutil.Discard, 1)
	}
}

// BenchmarkWriteVarInt3 performs a benchmark on how long it takes to write
// a three byte variable length integer.
func BenchmarkWriteVarInt3(b *testing.B) {
	for i := 0; i < b.N; i++ {
		WriteVarInt(ioutil.Discard, 65535)
	}
}

// BenchmarkWriteVarInt5 performs a benchmark on how long it takes to write
// a five byte variable length integer.
func BenchmarkWriteVarInt5(b *testing.B) {
	for i := 0; i < b.N; i++ {
		WriteVarInt(ioutil.Discard, 4294967295)
	}
}

// BenchmarkWriteVarInt9 performs a benchmark on how long it takes to write
// a nine byte variable length integer.
func BenchmarkWriteVarInt9(b *testing.B) {
	for i := 0; i < b.N; i++ {
		WriteVarInt(ioutil.Discard, 18446744073709551615)
	}
}

// BenchmarkReadVarInt1 performs a benchmark on how long it takes to read
// a single byte variable length integer.
func BenchmarkReadVarInt1(b *testing.B) {
	buf := []byte{0x01}
	for i := 0; i < b.N; i++ {
		ReadVarInt(bytes.NewReader(buf))
	}
}

// BenchmarkReadVarInt3 performs a benchmark on how long it takes to read
// a three byte variable length integer.
func BenchmarkReadVarInt3(b *testing.B) {
	buf := []byte{0x0fd, 0xff, 0xff}
	for i := 0; i < b.N; i++ {
		ReadVarInt(bytes.NewReader(buf))
	}
}

// BenchmarkReadVarInt5 performs a benchmark on how long it takes to read
// a five byte variable length integer.
func BenchmarkReadVarInt5(b *testing.B) {
	buf := []byte{0xfe, 0xff, 0xff, 0xff, 0xff}
	for i := 0; i < b.N; i++ {
		ReadVarInt(bytes.NewReader(buf))
	}
}

// BenchmarkReadVarInt9 performs a benchmark on how long it takes to read
// a nine byte variable length integer.
func BenchmarkReadVarInt9(b *testing.B) {
	buf := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for i := 0; i < b.N; i++ {
		ReadVarInt(bytes.NewReader(buf))
	}
}

// BenchmarkReadVarStr4 performs a benchmark on how long it takes to read a
// four byte variable length string.
func BenchmarkReadVarStr4(b *testing.B) {
	buf := []byte{0x04, 't', 'e', 's', 't'}
	for i := 0; i < b.N; i++ {
		ReadVarString(bytes.NewReader(buf), 100)
	}
}

// BenchmarkReadVarStr10 performs a benchmark on how long it takes to read a
// ten byte variable length string.
func BenchmarkReadVarStr10(b *testing.B) {
	buf := []byte{0x0a, 't', 'e', 's', 't', '0', '1', '2', '3', '4', '5'}
	for i := 0; i < b.N; i++ {
		ReadVarString(bytes.NewReader(buf), 100)
	}
}

// BenchmarkWriteVarStr4 performs a benchmark on how long it takes to write a
// four byte variable length string.
func BenchmarkWriteVarStr4(b *testing.B) {
	for i := 0; i < b.N; i++ {
		WriteVarString(ioutil.Discard, "test")
	}
}

// BenchmarkWriteVarStr10 performs a benchmark on how long it takes to write a
// ten byte variable length string.
func BenchmarkWriteVarStr10(b *testing.B) {
	for i := 0; i < b.N; i++ {
		WriteVarString(ioutil.Discard, "test012345")
	}
}
