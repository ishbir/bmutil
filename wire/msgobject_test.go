package wire_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/monetas/bmutil/wire"
)

var pubkey = []wire.PubKey{
	wire.PubKey([wire.PubKeySize]byte{
		23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
		39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
		55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
		71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86}),
	wire.PubKey([wire.PubKeySize]byte{
		87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102,
		103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
		119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
		135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150}),
}

var shahash = wire.ShaHash([wire.HashSize]byte{
	98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
	114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129})

var ripehash = wire.RipeHash([wire.RipeHashSize]byte{
	78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97})

func TestObjectTypeString(t *testing.T) {
	// check if unknowns are handled properly
	str := wire.ObjectType(4).String()
	if str != "Unknown" {
		t.Errorf("expected Unknown got %s", str)
	}
	str = wire.ObjectType(985621).String()
	if str != "Unknown" {
		t.Errorf("expected Unknown got %s", str)
	}

	// check existing object types
	for i := wire.ObjectType(0); i < wire.ObjectType(4); i++ {
		str = i.String()
		if str == "Unknown" {
			t.Errorf("did not expect Unknown for %d", i)
		}
	}
}

// TestEncodeAndDecodeObjectHeader tests EncodeObjectHeader and DecodeObjectHeader
// It is not necessary to test separate cases for different object types.
func TestEncodeAndDecodeObjectHeader(t *testing.T) {
	tests := []struct {
		nonce   uint64
		expires time.Time
		objType wire.ObjectType
		version uint64
		stream  uint64
	}{
		{
			nonce:   uint64(123),
			expires: time.Now(),
			objType: wire.ObjectType(0),
			version: 0,
			stream:  1,
		},
		{
			nonce:   uint64(8390),
			expires: time.Now().Add(-37 * time.Hour),
			objType: wire.ObjectType(66),
			version: 33,
			stream:  17,
		},
		{
			nonce:   uint64(65),
			expires: time.Now().Add(5 * time.Second),
			objType: wire.ObjectType(2),
			version: 2,
			stream:  8,
		},
	}

	for i, test := range tests {
		buf := &bytes.Buffer{}
		err := wire.EncodeMsgObjectHeader(buf, test.nonce, test.expires, test.objType, test.version, test.stream)
		if err != nil {
			t.Errorf("Error encoding header in test case %d.", i)
		}
		nonce, expires, objType, version, stream, err := wire.DecodeMsgObjectHeader(buf)
		if err != nil {
			t.Errorf("Error decoding header in test case %d.", i)
		}
		if nonce != test.nonce {
			t.Errorf("Error on test case %d: nonce should be %x, got %x", i, test.nonce, nonce)
		}
		if expires.Unix() != test.expires.Unix() {
			t.Errorf("Error on test case %d: expire time should be %x, got %x", i, test.expires.Unix(), expires.Unix())
		}
		if objType != test.objType {
			t.Errorf("Error on test case %d: object type should be %d, got %d", i, test.objType, objType)
		}
		if version != test.version {
			t.Errorf("Error on test case %d: version should be %d, got %d", i, test.version, version)
		}
		if stream != test.stream {
			t.Errorf("Error on test case %d: stream should be %d, got %d", i, test.stream, stream)
		}
	}
}

// TestDecodeMsgObject tests DecodeMsgObject and checks if it returns an error if it should.
func TestDecodeMsgObject(t *testing.T) {
	expires := time.Now().Add(300 * time.Minute)

	tests := []struct {
		input       []byte // The input to the function.
		errExpected bool   // Whether an error is expected.
	}{
		{ // Error case: nil input.
			nil,
			true,
		},
		{ // Error case. Incomplete header.
			[]byte{},
			true,
		},
		{ // Error case. Incomplete body.
			[]byte{
				0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 0, 85, 75, 111, 20,
				0, 0, 0, 0, 4, 1, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
				108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
				124, 125, 126},
			true,
		},
		{ // Valid case: GetPubKey object.
			[]byte{
				0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 0, 85, 75, 111, 20,
				0, 0, 0, 0, 4, 1, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
				108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
				124, 125, 126, 127, 128, 129},
			false,
		},
		{ // Valid case: PubKey object.
			wire.EncodeMessage(wire.NewMsgPubKey(543, expires, 4, 1, 2, &pubkey[0], &pubkey[1], 3, 5,
				[]byte{4, 5, 6, 7, 8, 9, 10}, &shahash, []byte{11, 12, 13, 14, 15, 16, 17, 18})),
			false,
		},
		{ // Valid case: Msg object.
			wire.EncodeMessage(wire.NewMsgMsg(765, expires, 1, 1,
				[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23},
				1, 1, 2, &pubkey[0], &pubkey[1], 3, 5, &ripehash, 1,
				[]byte{21, 22, 23, 24, 25, 26, 27, 28},
				[]byte{20, 21, 22, 23, 24, 25, 26, 27},
				[]byte{19, 20, 21, 22, 23, 24, 25, 26})),
			false,
		},
		{ // Valid case: Broadcast object.
			wire.EncodeMessage(wire.NewMsgBroadcast(876, expires, 1, 1, &shahash,
				[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23},
				1, 1, 2, &pubkey[0], &pubkey[1], 3, 5, &ripehash, 1,
				[]byte{27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41},
				[]byte{42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56})),
			false,
		},
		{ // Valid case: unknown object.
			wire.EncodeMessage(wire.NewMsgUnknownObject(345, expires, wire.ObjectType(4), 1, 1, []byte{77, 82, 53, 48, 96, 1})),
			false,
		},
	}

	for i, test := range tests {
		if _, err := wire.DecodeMsgObject(test.input); (err != nil) != test.errExpected {
			t.Errorf("failed test case %d.", i)
		}
	}
}
