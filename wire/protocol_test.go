// Originally derived from: btcsuite/btcd/wire/protocol_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire_test

import (
	"testing"

	"github.com/monetas/bmutil/wire"
)

// TestServiceFlagStringer tests the stringized output for service flag types.
func TestServiceFlagStringer(t *testing.T) {
	tests := []struct {
		in   wire.ServiceFlag
		want string
	}{
		{0, "0x0"},
		{wire.SFNodeNetwork, "SFNodeNetwork"},
		{0xffffffff, "SFNodeNetwork|0xfffffffe"},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.String()
		if result != test.want {
			t.Errorf("String #%d\n got: %s want: %s", i, result,
				test.want)
			continue
		}
	}
}

// TestBitmessageNetStringer tests the stringized output for bitmessage net types.
func TestBitmessageNetStringer(t *testing.T) {
	tests := []struct {
		in   wire.BitmessageNet
		want string
	}{
		{wire.MainNet, "MainNet"},
		{0xffffffff, "Unknown BitmessageNet (4294967295)"},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.String()
		if result != test.want {
			t.Errorf("String #%d\n got: %s want: %s", i, result,
				test.want)
			continue
		}
	}
}
