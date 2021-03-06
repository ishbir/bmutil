// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity_test

import (
	"fmt"
	"testing"

	"github.com/monetas/bmutil"
	"github.com/monetas/bmutil/identity"
	"github.com/monetas/bmutil/pow"
)

type addressImportExportTest struct {
	address       string
	signingkey    string
	encryptionkey string
}

// Taken from https://bitmessage.ch/nuked/
var addressImportExportTests = []addressImportExportTest{
	{"BM-2cVLR8vzEu6QUjGkYAPHQQTUenPVC62f9B",
		"5JvnKKDF1vWDBnnjCPGMVVzsX2EinsXbiiJj7JUwZ9La4xJ9FWt",
		"5JTYsHKSzDx6636UatMppek1QzKYL8b5RLeZdayHoi1Qa5yJjJS"},
	{"BM-2cUuzjWQjDWyDfYHL9C93jcJYKW1B8JyS5",
		"5KWFoFRXVHraujrFWuXfNn1fnP4euVUq79QnMWE2QPv3kWhbjs1",
		"5JYcPUZuMjzgSHmsmcsQcpzFGqM7DdEVtxwNjRZg7KfUTqmepFh"},
}

// Need to figure out a way to improve testing for this.
func TestImportExport(t *testing.T) {
	for _, pair := range addressImportExportTests {
		v, err := identity.ImportWIF(pair.address, pair.signingkey,
			pair.encryptionkey, pow.DefaultNonceTrialsPerByte,
			pow.DefaultExtraBytes)
		if err != nil {
			t.Error(
				"for", pair.address,
				"got error:", err.Error(),
			)
		}

		address, signingkey, encryptionkey, err := v.ExportWIF()
		if err != nil {
			t.Error(
				"for", pair.address,
				"got error:", err,
			)
		}

		if address != pair.address || signingkey != pair.signingkey ||
			encryptionkey != pair.encryptionkey {
			t.Error(
				"for", pair.address,
				"got address:", address,
				"signingkey:", signingkey,
				"encryptionkey:", encryptionkey,
				"expected", pair.address, pair.signingkey, pair.encryptionkey,
			)
		}
	}
}

// Just check if generation of random address was successful
func TestNewRandom(t *testing.T) {
	// At least one zero in the beginning
	_, err := identity.NewRandom(0)
	if err == nil {
		t.Error("for requiredZeros=0 expected error got none")
	}
	v, err := identity.NewRandom(1)
	if err != nil {
		t.Error(err)
		return
	}
	v.Address.Version = 4
	v.Address.Stream = 1
	address, signingkey, encryptionkey, err := v.ExportWIF()
	if err != nil {
		t.Error("export failed, error:", err)
		return
	}
	fmt.Println("Address:", address)
	fmt.Println("Signing Key:", signingkey)
	fmt.Println("Encryption Key:", encryptionkey)
}

type deterministicAddressTest struct {
	password string
	address  string
}

var deterministicAddressTests = []deterministicAddressTest{
	{"hello", "BM-2DB6AzjZvzM8NkS3HMYWMP9R1Rt778mhN8"},
	{"general", "BM-2DAV89w336ovy6BUJnfVRD5B9qipFbRgmr"},
	{"privacy", "BM-2D8hw9EzzMMJUYV44txMFqbtq3T7MCvyz7"},
	{"news", "BM-2D8ZrxtSU1jf7nnfvqVwRfCVh1Q8NW4td5"},
	{"PHP", "BM-2cUvgm9ScCJxig3cAkwNzD5iEw3rKJ7NeG"},
}

func TestNewDeterministic(t *testing.T) {
	for _, pair := range deterministicAddressTests {
		id, err := identity.NewDeterministic(pair.password, 1)
		if err != nil {
			t.Error(
				"for", pair.password,
				"got error:", err.Error(),
			)
			continue
		}
		// Make sure to generate address of same version and stream
		addr, _ := bmutil.DecodeAddress(pair.address)
		id.Address.Version = addr.Version
		id.Address.Stream = addr.Stream
		address, _, _, _ := id.ExportWIF()
		if address != pair.address {
			t.Error(
				"for", pair.password,
				"got", address,
				"expected", pair.address,
			)
		}
	}
}

func TestErrors(t *testing.T) {
	// NewDeterministic
	_, err := identity.NewDeterministic("abcabc", 0) // 0 initial zeros
	if err == nil {
		t.Error("NewDeterministic: 0 initial zeros, got no error")
	}

	// ImportWIF

	// invalid address
	_, err = identity.ImportWIF("BM-9tSxgK6q4X6bNdEbyMRgGBcfnFC3MoW3Bp5", "",
		"", 1000, 1000)
	if err == nil {
		t.Error("ImportWIF: invalid address, got no error")
	}

	// invalid signing key
	_, err = identity.ImportWIF("BM-2cWgt4u3shyzQ8vP56uzMSe2iajy8r4Hxe",
		"sd5f48erdfoiopadsfa5d6sf405", "", 1000, 1000)
	if err == nil {
		t.Error("ImportWIF: invalid signing key, got no error")
	}

	// invalid encryption key
	_, err = identity.ImportWIF("BM-2cV9RshwouuVKWLBoyH5cghj3kMfw5G7BJ",
		"5KHBtHsy9eWz6fFZzJCNMVVJ3r4m7AbuzYRE3hwkKZ2H7BEZrGU",
		"sd5f48erdfoiopadsfa5d6sf405", 1000, 1000)
	if err == nil {
		t.Error("ImportWIF: invalid encryption key, got no error")
	}

	// address does not match
	_, err = identity.ImportWIF("BM-2DB6AzjZvzM8NkS3HMYWMP9R1Rt778mhN8",
		"5JXVjG9CNFh17kCawPxCtekJBei9gv6hzmawBGFkuciTCMaxeJD",
		"5KQC3fHBCUNyBoXeEpgphrqa314Cvy4beS21Zg1rvrj1FY3Tgqb", 1000, 1000)
	if err == nil {
		t.Error("ImportWIF: address mismatch, got no error")
	}

	// ExportWIF
	id, err := identity.ImportWIF("BM-2cU2a336vzu7SEuPPa1UTWgrVg8mWiqzpm",
		"5Ke7eXNJmQYpdeVckePnRWEu5TwPrE9BsZfZZQGGb1jzor9fXit",
		"5HwY8h5skGnaFaQZZv9UzMJdJbdtuZBjXhsSyDK9msGernqPRDt", 1000, 1000)

	id.Address.Version = 5 // set invalid version
	_, _, _, err = id.ExportWIF()
	if err == nil {
		t.Error("ExportWIF: invalid address, got no error")
	}
}
