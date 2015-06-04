// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/monetas/bmutil/identity"
	"github.com/monetas/bmutil/pow"
	"github.com/monetas/bmutil/wire"
)

func TestIdentityFromPubKeyMsg(t *testing.T) {
	id, err := identity.NewRandom(1)
	if err != nil {
		t.Fatal("identity generation failed")
	}
	enc := id.ToPublic().EncryptionKey.SerializeUncompressed()[1:]
	sig := id.ToPublic().SigningKey.SerializeUncompressed()[1:]
	var encryptKey wire.PubKey
	var signingKey wire.PubKey
	copy(encryptKey[:], enc)
	copy(signingKey[:], sig)

	// test version 2 message
	id.CreateAddress(2, 1)
	addr, err := id.Address.Encode()
	if err != nil {
		t.Fatalf("for error got %v", err)
	}

	validIdMsg := wire.NewMsgPubKey(123123, time.Now().Add(time.Hour), 2, 1, 1,
		&signingKey, &encryptKey, 0, 0, nil, nil, nil)
	testId, err := identity.FromPubKeyMsg(validIdMsg)
	if err != nil {
		t.Errorf("for error got %v", err)
	}

	if testAddr, _ := testId.Address.Encode(); testAddr != addr {
		t.Errorf("generated address doesn't match, got %s expected %s",
			testAddr, addr)
	}
	if testEnc := testId.EncryptionKey.SerializeUncompressed()[1:]; !bytes.Equal(
		testEnc, enc) {
		t.Errorf("public encryption key doesn't match, got %v expected %v",
			testEnc, enc)
	}
	if testSig := testId.SigningKey.SerializeUncompressed()[1:]; !bytes.Equal(
		testSig, sig) {
		t.Errorf("public signing key doesn't match, got %v expected %v",
			testSig, enc)
	}
	if testId.NonceTrialsPerByte != pow.DefaultNonceTrialsPerByte {
		t.Errorf("nonce trials per byte doesn't match, got %d expected %d",
			testId.NonceTrialsPerByte, pow.DefaultNonceTrialsPerByte)
	}
	if testId.ExtraBytes != pow.DefaultExtraBytes {
		t.Errorf("extra bytes doesn't match, got %d expected %d",
			testId.ExtraBytes, pow.DefaultExtraBytes)
	}

	// test version 3 message
	id.CreateAddress(3, 1)
	addr, err = id.Address.Encode()
	if err != nil {
		t.Fatalf("for error got %v", err)
	}

	validIdMsg = wire.NewMsgPubKey(123123, time.Now().Add(time.Hour), 3, 1, 1,
		&signingKey, &encryptKey, 2000, 1500, nil, nil, nil)
	testId, err = identity.FromPubKeyMsg(validIdMsg)
	if err != nil {
		t.Errorf("for error got %v", err)
	}

	if testAddr, _ := testId.Address.Encode(); testAddr != addr {
		t.Errorf("generated address doesn't match, got %s expected %s",
			testAddr, addr)
	}
	if testEnc := testId.EncryptionKey.SerializeUncompressed()[1:]; !bytes.Equal(
		testEnc, enc) {
		t.Errorf("public encryption key doesn't match, got %v expected %v",
			testEnc, enc)
	}
	if testSig := testId.SigningKey.SerializeUncompressed()[1:]; !bytes.Equal(
		testSig, sig) {
		t.Errorf("public signing key doesn't match, got %v expected %v",
			testSig, enc)
	}
	if testId.NonceTrialsPerByte != validIdMsg.NonceTrials {
		t.Errorf("nonce trials per byte doesn't match, got %d expected %d",
			testId.NonceTrialsPerByte, pow.DefaultNonceTrialsPerByte)
	}
	if testId.ExtraBytes != validIdMsg.ExtraBytes {
		t.Errorf("extra bytes doesn't match, got %d expected %d",
			testId.ExtraBytes, pow.DefaultExtraBytes)
	}

	// version 4 message should fail since it's encrypted
	invMsg := wire.NewMsgPubKey(123123, time.Now().Add(time.Hour), 4, 1, 1,
		&signingKey, &encryptKey, 2000, 1500, nil, nil, nil)
	testId, err = identity.FromPubKeyMsg(invMsg)
	if err == nil {
		t.Error("got none expected error")
	}

	// invalid signing key
	invKey := bytes.Repeat([]byte{0x00}, wire.PubKeySize)
	var invSigningKey wire.PubKey
	copy(invSigningKey[:], invKey)

	invMsg = wire.NewMsgPubKey(123123, time.Now().Add(time.Hour), 3, 1, 1,
		&invSigningKey, &encryptKey, 2000, 1500, nil, nil, nil)
	testId, err = identity.FromPubKeyMsg(invMsg)
	if err == nil {
		t.Error("got no error")
	}

	// invalid encryption key
	var invEncryptKey wire.PubKey
	copy(invEncryptKey[:], invKey)

	invMsg = wire.NewMsgPubKey(123123, time.Now().Add(time.Hour), 3, 1, 1,
		&signingKey, &invEncryptKey, 2000, 1500, nil, nil, nil)
	testId, err = identity.FromPubKeyMsg(invMsg)
	if err == nil {
		t.Error("got no error")
	}
}
