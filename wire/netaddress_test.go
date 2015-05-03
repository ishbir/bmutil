// Originally derived from: btcsuite/btcd/wire/netaddress_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire_test

import (
	"bytes"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/monetas/bmutil/wire"
)

// TestNetAddress tests the NetAddress API.
func TestNetAddress(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	port := 8333

	// Test NewNetAddress.
	tcpAddr := &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
	na, err := wire.NewNetAddress(tcpAddr, 0, 0)
	if err != nil {
		t.Errorf("NewNetAddress: %v", err)
	}

	// Ensure we get the same ip, port, services and stream back out.
	if !na.IP.Equal(ip) {
		t.Errorf("NetNetAddress: wrong ip - got %v, want %v", na.IP, ip)
	}
	if na.Port != uint16(port) {
		t.Errorf("NetNetAddress: wrong port - got %v, want %v", na.Port,
			port)
	}
	if na.Services != 0 {
		t.Errorf("NetNetAddress: wrong services - got %v, want %v",
			na.Services, 0)
	}
	if na.HasService(wire.SFNodeNetwork) {
		t.Errorf("HasService: SFNodeNetwork service is set")
	}
	if na.Stream != 0 {
		t.Errorf("Stream: wrong stream - got %v, want %v", na.Stream, 0)
	}

	// Ensure adding the full service node flag works.
	na.AddService(wire.SFNodeNetwork)
	if na.Services != wire.SFNodeNetwork {
		t.Errorf("AddService: wrong services - got %v, want %v",
			na.Services, wire.SFNodeNetwork)
	}
	if !na.HasService(wire.SFNodeNetwork) {
		t.Errorf("HasService: SFNodeNetwork service not set")
	}

	// Ensure max payload is expected value for latest protocol version.
	wantPayload := 38
	maxPayload := wire.TstMaxNetAddressPayload()
	if maxPayload != wantPayload {
		t.Errorf("maxNetAddressPayload: wrong max payload length for "+
			"- got %v, want %v", maxPayload, wantPayload)
	}

	// Check for expected failure on wrong address type.
	udpAddr := &net.UDPAddr{}
	_, err = wire.NewNetAddress(udpAddr, 0, 0)
	if err != wire.ErrInvalidNetAddr {
		t.Errorf("NewNetAddress: expected error not received - "+
			"got %v, want %v", err, wire.ErrInvalidNetAddr)
	}
}

// TestNetAddressWire tests the NetAddress wire.encode and decode for various
// protocol versions and timestamp flag combinations.
func TestNetAddressWire(t *testing.T) {
	// baseNetAddr is used in the various tests as a baseline NetAddress.
	baseNetAddr := wire.NetAddress{
		Timestamp: time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
		Stream:    1,
		Services:  wire.SFNodeNetwork,
		IP:        net.ParseIP("127.0.0.1"),
		Port:      8333,
	}

	// baseNetAddrNoTS is baseNetAddr with a zero value for the timestamp.
	baseNetAddrNoTS := baseNetAddr
	baseNetAddrNoTS.Timestamp = time.Time{}
	baseNetAddrNoTS.Stream = 0

	// baseNetAddrEncoded is the wire.encoded bytes of baseNetAddr.
	baseNetAddrEncoded := []byte{
		0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // Timestamp
		0x00, 0x00, 0x00, 0x01, // Stream number
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SFNodeNetwork
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01, // IP 127.0.0.1
		0x20, 0x8d, // Port 8333 in big-endian
	}

	// baseNetAddrNoTSEncoded is the wire.encoded bytes of baseNetAddrNoTS.
	baseNetAddrNoTSEncoded := []byte{
		// No timestamp
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SFNodeNetwork
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01, // IP 127.0.0.1
		0x20, 0x8d, // Port 8333 in big-endian
	}

	tests := []struct {
		in  wire.NetAddress // NetAddress to encode
		out wire.NetAddress // Expected decoded NetAddress
		ts  bool            // Include timestamp?
		buf []byte          // Wire encoding
	}{
		// Latest protocol version without ts flag.
		{
			baseNetAddr,
			baseNetAddrNoTS,
			false,
			baseNetAddrNoTSEncoded,
		},

		// Latest protocol version with ts flag.
		{
			baseNetAddr,
			baseNetAddr,
			true,
			baseNetAddrEncoded,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire.format.
		var buf bytes.Buffer
		err := wire.TstWriteNetAddress(&buf, &test.in, test.ts)
		if err != nil {
			t.Errorf("writeNetAddress #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("writeNetAddress #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire.format.
		var na wire.NetAddress
		rbuf := bytes.NewReader(test.buf)
		err = wire.TstReadNetAddress(rbuf, &na, test.ts)
		if err != nil {
			t.Errorf("readNetAddress #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(na, test.out) {
			t.Errorf("readNetAddress #%d\n got: %s want: %s", i,
				spew.Sdump(na), spew.Sdump(test.out))
			continue
		}
	}
}

// TestNetAddressWireErrors performs negative tests against wire.encode and
// decode NetAddress to confirm error paths work correctly.
func TestNetAddressWireErrors(t *testing.T) {

	// baseNetAddr is used in the various tests as a baseline NetAddress.
	baseNetAddr := wire.NetAddress{
		Timestamp: time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST
		Services:  wire.SFNodeNetwork,
		IP:        net.ParseIP("127.0.0.1"),
		Port:      8333,
	}

	tests := []struct {
		in       *wire.NetAddress // Value to encode
		buf      []byte           // Wire encoding
		ts       bool             // Include timestamp flag
		max      int              // Max size of fixed buffer to induce errors
		writeErr error            // Expected write error
		readErr  []error          // Expected read error (more than one may be possible)
	}{
		// Latest protocol version with timestamp and intentional
		// read/write errors.
		// Force errors on timestamp.
		{&baseNetAddr, []byte{}, true, 0, io.ErrShortWrite, []error{io.EOF, io.ErrUnexpectedEOF}},
		// Force errors on services.
		{&baseNetAddr, []byte{}, true, 4, io.ErrShortWrite, []error{io.EOF, io.ErrUnexpectedEOF}},
		// Force errors on ip.
		{&baseNetAddr, []byte{}, true, 12, io.ErrShortWrite, []error{io.EOF, io.ErrUnexpectedEOF}},
		// Force errors on port.
		{&baseNetAddr, []byte{}, true, 28, io.ErrShortWrite, []error{io.EOF, io.ErrUnexpectedEOF}},

		// Latest protocol version with no timestamp and intentional
		// read/write errors.
		// Force errors on services.
		{&baseNetAddr, []byte{}, false, 0, io.ErrShortWrite, []error{io.EOF, io.ErrUnexpectedEOF}},
		// Force errors on ip.
		{&baseNetAddr, []byte{}, false, 8, io.ErrShortWrite, []error{io.EOF, io.ErrUnexpectedEOF}},
		// Force errors on port.
		{&baseNetAddr, []byte{}, false, 24, io.ErrShortWrite, []error{io.EOF, io.ErrUnexpectedEOF}},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire.format.
		w := newFixedWriter(test.max)
		err := wire.TstWriteNetAddress(w, test.in, test.ts)
		if err != test.writeErr {
			t.Errorf("writeNetAddress #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// Decode from wire.format.
		var na wire.NetAddress
		r := newFixedReader(test.max, test.buf)
		err = wire.TstReadNetAddress(r, &na, test.ts)

		for _, readErr := range test.readErr {
			if err == readErr {
				goto pass
			}
		}
		t.Errorf("readNetAddress #%d wrong error got: %v, want: %v",
			i, err, test.readErr)
		continue
	pass:
	}
}
