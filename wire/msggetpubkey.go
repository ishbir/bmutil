// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
	"time"
)

const (
	// TagGetPubKeyVersion specifies the version of MsgGetPubKey from which
	// tags started being encoded in messages and not ripe. This was done to
	// thwart any public key/address harvesting attempts.
	TagGetPubKeyVersion = 4
)

// MsgGetPubKey implements the Message interface and represents a request for a
// public key. If Version <= TagGetPubKeyVersion, tag is encoded in message and
// not ripe.
type MsgGetPubKey struct {
	Nonce        uint64
	ExpiresTime  time.Time
	ObjectType   ObjectType
	Version      uint64
	StreamNumber uint64
	Ripe         *RipeHash
	Tag          *ShaHash
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgGetPubKey) Decode(r io.Reader) error {
	var err error
	msg.Nonce, msg.ExpiresTime, msg.ObjectType, msg.Version,
		msg.StreamNumber, err = DecodeMsgObjectHeader(r)
	if err != nil {
		return err
	}

	if msg.ObjectType != ObjectTypeGetPubKey {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			ObjectTypeGetPubKey, msg.ObjectType)
		return messageError("Decode", str)
	}

	switch msg.Version {
	case TagGetPubKeyVersion:
		msg.Tag, _ = NewShaHash(make([]byte, HashSize))
		if err = readElement(r, msg.Tag); err != nil {
			return err
		}
	case SimplePubKeyVersion, ExtendedPubKeyVersion:
		msg.Ripe, _ = NewRipeHash(make([]byte, 20))
		if err = readElement(r, msg.Ripe); err != nil {
			return err
		}
	default:
		return messageError("MsgGetPubKey.Decode", "unsupported pubkey version")
	}

	return err
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgGetPubKey) Encode(w io.Writer) error {
	err := EncodeMsgObjectHeader(w, msg.Nonce, msg.ExpiresTime, msg.ObjectType,
		msg.Version, msg.StreamNumber)
	if err != nil {
		return err
	}

	switch msg.Version {
	case TagGetPubKeyVersion:
		if err = writeElement(w, msg.Tag); err != nil {
			return err
		}
	case SimplePubKeyVersion, ExtendedPubKeyVersion:
		if err = writeElement(w, msg.Ripe); err != nil {
			return err
		}
	default:
		return messageError("MsgGetPubKey.Decode", "unsupported pubkey version")
	}

	return err
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *MsgGetPubKey) Command() string {
	return CmdObject
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgGetPubKey) MaxPayloadLength() int {
	return 70
}

func (msg *MsgGetPubKey) String() string {
	return fmt.Sprintf("getpubkey: v%d %d %s %d %x %x", msg.Version, msg.Nonce, msg.ExpiresTime, msg.StreamNumber, msg.Ripe, msg.Tag)
}

// NewMsgGetPubKey returns a new object message that conforms to the
// Message interface using the passed parameters and defaults for the remaining
// fields.
func NewMsgGetPubKey(nonce uint64, expires time.Time, version, streamNumber uint64, ripe *RipeHash, tag *ShaHash) *MsgGetPubKey {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	return &MsgGetPubKey{
		Nonce:        nonce,
		ExpiresTime:  expires,
		ObjectType:   ObjectTypeGetPubKey,
		Version:      version,
		StreamNumber: streamNumber,
		Ripe:         ripe,
		Tag:          tag,
	}
}
