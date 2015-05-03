// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/monetas/bmutil/wire"
)

// TestPubKey tests the PubKey API.
func TestPubKeyH(t *testing.T) {

	pubKeyStr := "3f554c24e91da07b257b73c87338653c6009943b62e43161e326de7b73f19ebf87201ea1a68e87edb95961d603b80eb13de1d8c4865a99fcee8fb6b92fe65699"
	pubKey, err := wire.NewPubKeyFromStr(pubKeyStr)
	if err != nil {
		t.Errorf("NewPubKeyFromStr: %v", err)
	}

	buf := []byte{
		0x79, 0xa6, 0x1a, 0xdb, 0xc6, 0xe5, 0xa2, 0xe1,
		0x39, 0xd2, 0x71, 0x3a, 0x54, 0x6e, 0xc7, 0xc8,
		0x79, 0xa6, 0x1a, 0xdb, 0xc6, 0xe5, 0xa2, 0xe1,
		0x39, 0xd2, 0x71, 0x3a, 0x54, 0x6e, 0xc7, 0xc8,
		0x79, 0xa6, 0x1a, 0xdb, 0xc6, 0xe5, 0xa2, 0xe1,
		0x39, 0xd2, 0x71, 0x3a, 0x54, 0x6e, 0xc7, 0xc8,
		0x79, 0xa6, 0x1a, 0xdb, 0xc6, 0xe5, 0xa2, 0xe1,
		0x39, 0xd2, 0x71, 0x3a, 0x54, 0x6e, 0xc7, 0xc8,
	}

	pubkey, err := wire.NewPubKey(buf)
	if err != nil {
		t.Errorf("NewPubKey: unexpected error %v", err)
	}

	// Ensure proper size.
	if len(pubkey) != wire.PubKeySize {
		t.Errorf("NewPubKey: pubkey length mismatch - got: %v, want: %v",
			len(pubkey), wire.PubKeySize)
	}

	// Ensure contents match.
	if !bytes.Equal(pubkey[:], buf) {
		t.Errorf("NewPubKey: pubkey contents mismatch - got: %v, want: %v",
			pubkey[:], buf)
	}

	// Set hash from byte slice and ensure contents match.
	err = pubkey.SetBytes(pubKey.Bytes())
	if err != nil {
		t.Errorf("SetBytes: %v", err)
	}
	if !pubkey.IsEqual(pubKey) {
		t.Errorf("IsEqual: pubkey contents mismatch - got: %v, want: %v",
			pubkey, pubKey)
	}

	// Invalid size for SetBytes.
	err = pubkey.SetBytes([]byte{0x00})
	if err == nil {
		t.Errorf("SetBytes: failed to received expected err - got: nil")
	}

	// Invalid size for NewPubKey.
	invalidHash := make([]byte, wire.PubKeySize+1)
	_, err = wire.NewPubKey(invalidHash)
	if err == nil {
		t.Errorf("NewPubKey: failed to received expected err - got: nil")
	}
}

// TestPubKeyString  tests the stringized output for sha hashes.
func TestPubKeyString(t *testing.T) {
	wantStr := "06e533fd1ada86391f3f6c343204b0d206e533fd1ada86391f3f6c343204b0d206e533fd1ada86391f3f6c343204b0d206e533fd1ada86391f3f6c343204b0d2"
	pubkey := wire.PubKey([wire.PubKeySize]byte{ // Make go vet happy.
		0x06, 0xe5, 0x33, 0xfd, 0x1a, 0xda, 0x86, 0x39,
		0x1f, 0x3f, 0x6c, 0x34, 0x32, 0x04, 0xb0, 0xd2,
		0x06, 0xe5, 0x33, 0xfd, 0x1a, 0xda, 0x86, 0x39,
		0x1f, 0x3f, 0x6c, 0x34, 0x32, 0x04, 0xb0, 0xd2,
		0x06, 0xe5, 0x33, 0xfd, 0x1a, 0xda, 0x86, 0x39,
		0x1f, 0x3f, 0x6c, 0x34, 0x32, 0x04, 0xb0, 0xd2,
		0x06, 0xe5, 0x33, 0xfd, 0x1a, 0xda, 0x86, 0x39,
		0x1f, 0x3f, 0x6c, 0x34, 0x32, 0x04, 0xb0, 0xd2,
	})

	pubkeyStr := pubkey.String()
	if pubkeyStr != wantStr {
		t.Errorf("String: wrong pubkey string - got %v, want %v",
			pubkeyStr, wantStr)
	}
}

// TestNewPubKeyFromStr executes tests against the NewPubKeyFromStr function.
func TestNewPubKeyFromStr(t *testing.T) {
	tests := []struct {
		in   string
		want wire.PubKey
		err  error
	}{
		// Empty string.
		{
			"",
			wire.PubKey{},
			wire.ErrPubKeyStrSize,
		},

		// Single digit pubkey.
		{
			"1",
			wire.PubKey([wire.PubKeySize]byte{ // Make go vet happy.
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			}),
			wire.ErrPubKeyStrSize,
		},

		{
			"3cb827da3ad158bc13143349f6cac62d0c74c035f88bb63f1f7fd5dd352e1c626c3c809ab2ae71da6622a16749188295151cb91667d77bf72be88848291fdd0a",
			wire.PubKey([wire.PubKeySize]byte{ // Make go vet happy.
				0x3C, 0xB8, 0x27, 0xDA, 0x3A, 0xD1, 0x58, 0xBC,
				0x13, 0x14, 0x33, 0x49, 0xF6, 0xCA, 0xC6, 0x2D,
				0x0C, 0x74, 0xC0, 0x35, 0xF8, 0x8B, 0xB6, 0x3F,
				0x1F, 0x7F, 0xD5, 0xDD, 0x35, 0x2E, 0x1C, 0x62,
				0x6C, 0x3C, 0x80, 0x9A, 0xB2, 0xAE, 0x71, 0xDA,
				0x66, 0x22, 0xA1, 0x67, 0x49, 0x18, 0x82, 0x95,
				0x15, 0x1C, 0xB9, 0x16, 0x67, 0xD7, 0x7B, 0xF7,
				0x2B, 0xE8, 0x88, 0x48, 0x29, 0x1F, 0xDD, 0x0A,
			}),
			nil,
		},

		// Pub Key that is too long.
		{
			"012345678901234567890123456789012345678901234567890123456789123450123456789012345678901234567890123456789012345678901234567891234501234567890123456789012345678901234567890123456789012345678912345",
			wire.PubKey{},
			wire.ErrPubKeyStrSize,
		},

		// Pub Key that is contains non-hex chars.
		{
			"3gb827da3ad158bc13143349f6cac62d0c74c035f88bb63f1f7fd5dd352e1c626c3c809ab2ae71da6622a16749188295151cb91667d77bf72be88848291fdd0a",
			wire.PubKey{},
			hex.InvalidByteError('g'),
		},
	}

	unexpectedErrStr := "NewPubKeyFromStr #%d failed to detect expected error - got: %v want: %v"
	unexpectedResultStr := "NewPubKeyFromStr #%d got: %v want: %v"
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result, err := wire.NewPubKeyFromStr(test.in)
		if err != test.err {
			t.Errorf(unexpectedErrStr, i, err, test.err)
			continue
		} else if err != nil {
			// Got expected error. Move on to the next test.
			continue
		}
		if !test.want.IsEqual(result) {
			t.Errorf(unexpectedResultStr, i, result, &test.want)
			continue
		}
	}
}

func TestToBtcec(t *testing.T) {
	tests := []struct {
		pubKeyBytes []byte
	}{
		{ // Valid public key.
			[]byte{0x04,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3,
				0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
				0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f,
				0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
			},
		},
		{ // Valid public key.
			[]byte{0x04,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
				0x66, 0xfb, 0xe7, 0x27, 0xb2, 0xba, 0x09, 0xe0,
				0x9f, 0x5a, 0x98, 0xd7, 0x0a, 0x5e, 0xfc, 0xe8,
				0x42, 0x4c, 0x5f, 0xa4, 0x25, 0xbb, 0xda, 0x1c,
				0x51, 0x1f, 0x86, 0x06, 0x57, 0xb8, 0x53, 0x5e,
			},
		},
		{ // Error case. Invalid pubic key.
			[]byte{0x04,
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{ // Error case. Invalid pubic key.
			[]byte{0x04,
				0x3C, 0xB8, 0x27, 0xDA, 0x3A, 0xD1, 0x58, 0xBC,
				0x13, 0x14, 0x33, 0x49, 0xF6, 0xCA, 0xC6, 0x2D,
				0x0C, 0x74, 0xC0, 0x35, 0xF8, 0x8B, 0xB6, 0x3F,
				0x1F, 0x7F, 0xD5, 0xDD, 0x35, 0x2E, 0x1C, 0x62,
				0x6C, 0x3C, 0x80, 0x9A, 0xB2, 0xAE, 0x71, 0xDA,
				0x66, 0x22, 0xA1, 0x67, 0x49, 0x18, 0x82, 0x95,
				0x15, 0x1C, 0xB9, 0x16, 0x67, 0xD7, 0x7B, 0xF7,
				0x2B, 0xE8, 0x88, 0x48, 0x29, 0x1F, 0xDD, 0x0A,
			},
		},
	}

	for test_case, test := range tests {
		bmPubKey, _ := wire.NewPubKey(test.pubKeyBytes[1:])
		btcPubKeyExp, btcErrExp := btcec.ParsePubKey(test.pubKeyBytes, btcec.S256())
		btcPubKeyTest, btcErrTest := bmPubKey.ToBtcec()
		
		if btcErrExp != nil {
			if btcErrTest == nil {
				t.Errorf("Error case %d: expecting error %s, but no error was returned. ", test_case, btcErrExp)
			} else if btcErrTest.Error() != btcErrExp.Error() {
				t.Errorf("Error case %d: expecting error %s, but got error %s. ", test_case, btcErrExp, btcErrTest)
			}
		} else if !bytes.Equal(btcPubKeyExp.SerializeUncompressed(), btcPubKeyTest.SerializeUncompressed()) {
			t.Errorf("Error case %d: different public key bytes returned. ", test_case)
		}
	}
}
