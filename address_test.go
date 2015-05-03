// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmutil_test

import (
	"reflect"
	"testing"

	"github.com/monetas/bmutil"
)

type addressTestPair struct {
	addrString string
	address    bmutil.Address
}

var addressTests = []addressTestPair{
	{"BM-2cV9RshwouuVKWLBoyH5cghj3kMfw5G7BJ", bmutil.Address{Version: 4,
		Stream: 1, Ripe: [20]byte{0, 118, 97, 129, 167, 56, 98, 210, 144, 213,
			33, 56, 250, 180, 161, 223, 177, 177, 12, 17}}},
	{"BM-2DBXxtaBSV37DsHjN978mRiMbX5rdKNvJ6", bmutil.Address{Version: 3,
		Stream: 1, Ripe: [20]byte{0, 214, 207, 196, 249, 74, 168, 190, 229, 104,
			152, 91, 102, 80, 2, 151, 51, 114, 110, 211}}},
	{"BM-omXeTjutKWmYgQJjmoZjAG3u3NmaLEdZK", bmutil.Address{Version: 2,
		Stream: 1, Ripe: [20]byte{0, 1, 171, 150, 119, 221, 37, 192, 14, 238,
			192, 25, 255, 242, 10, 139, 186, 251, 244, 218}}},
	{"BM-GtovgYdgs7qXPkoYaRgrLFuFKz1SFpsw", bmutil.Address{Version: 3,
		Stream: 1, Ripe: [20]byte{0, 0, 124, 201, 186, 238, 181, 209, 250, 143,
			180, 26, 106, 227, 40, 178, 123, 229, 34, 85}}},
	{"BM-2D7YvqcbRSv2j2zXmamTm4C3XGrTkZqdt3", bmutil.Address{Version: 3,
		Stream: 1, Ripe: [20]byte{0, 21, 243, 247, 60, 104, 72, 169, 139, 195,
			72, 196, 85, 228, 167, 173, 177, 1, 165, 242}}},
}

func TestEncodeAddress(t *testing.T) {
	for _, pair := range addressTests {
		v, err := pair.address.Encode()
		if err != nil {
			t.Error(
				"For", pair.addrString,
				"got error:", err.Error(),
			)
			continue
		}
		if v != pair.addrString {
			t.Error(
				"For", pair.address,
				"expected", pair.addrString,
				"got", v,
			)
		}
	}
}

func TestDecodeAddress(t *testing.T) {
	for _, pair := range addressTests {
		addr, err := bmutil.DecodeAddress(pair.addrString)
		if err != nil {
			t.Error(
				"For", pair.addrString,
				"got error:", err.Error(),
			)
			continue
		}
		if !reflect.DeepEqual(addr, &pair.address) {
			t.Error(
				"For", pair.addrString,
				"expected", pair.address,
				"got", addr,
			)
		}
	}
}
