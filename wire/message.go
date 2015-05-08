// Originally derived from: btcsuite/btcd/wire/message.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/monetas/bmutil"
)

// MessageHeaderSize is the number of bytes in a bitmessage message header.
// Bitmessage network (magic) 4 bytes + command 12 bytes +
// payload length 4 bytes + checksum 4 bytes.
const MessageHeaderSize = 24

// CommandSize is the fixed size of all commands in the common bitmessage message
// header. Shorter commands must be zero padded.
const CommandSize = 12

// MaxMessagePayload is the maximum bytes a message can be regardless of other
// individual limits imposed by messages themselves. ~1.6 MB, which is which is
// the maximum possible size of an inv message.
const MaxMessagePayload = 1600100

// Commands used in bitmessage message headers which describe the type of message.
const (
	CmdVersion = "version"
	CmdVerAck  = "verack"
	CmdAddr    = "addr"
	CmdInv     = "inv"
	CmdGetData = "getdata"
	CmdObject  = "object"
)

// Message is an interface that describes a bitmessage message.  A type that
// implements Message has complete control over the representation of its data
// and may therefore contain additional or fewer fields than those which
// are used directly in the protocol encoded message.
type Message interface {
	Decode(io.Reader) error
	Encode(io.Writer) error
	Command() string
	MaxPayloadLength() int
}

// makeEmptyMessage creates a message of the appropriate concrete type based
// on the command.
func makeEmptyMessage(command string) (Message, error) {
	var msg Message
	switch command {
	case CmdVersion:
		msg = &MsgVersion{}

	case CmdVerAck:
		msg = &MsgVerAck{}

	case CmdAddr:
		msg = &MsgAddr{}

	case CmdInv:
		msg = &MsgInv{}

	case CmdGetData:
		msg = &MsgGetData{}

	default:
		return nil, fmt.Errorf("unhandled command [%s]", command)
	}
	return msg, nil
}

// messageHeader defines the header structure for all bitmessage protocol messages.
type messageHeader struct {
	magic    BitmessageNet // 4 bytes
	command  string        // 12 bytes
	length   uint32        // 4 bytes
	checksum [4]byte       // 4 bytes
}

// readMessageHeader reads a bitmessage message header from r.
func readMessageHeader(r io.Reader) (int, *messageHeader, error) {
	// Since readElements doesn't return the amount of bytes read, attempt
	// to read the entire header into a buffer first in case there is a
	// short read so the proper amount of read bytes are known.  This works
	// since the header is a fixed size.
	var headerBytes [MessageHeaderSize]byte
	n, err := io.ReadFull(r, headerBytes[:])
	if err != nil {
		return n, nil, err
	}
	hr := bytes.NewReader(headerBytes[:])

	// Create and populate a messageHeader struct from the raw header bytes.
	hdr := messageHeader{}
	var command [CommandSize]byte
	readElements(hr, &hdr.magic, &command, &hdr.length, &hdr.checksum)

	// Strip trailing zeros from command string.
	hdr.command = string(bytes.TrimRight(command[:], string(0)))

	return n, &hdr, nil
}

// discardInput reads n bytes from reader r in chunks and discards the read
// bytes.  This is used to skip payloads when various errors occur and helps
// prevent rogue nodes from causing massive memory allocation through forging
// header length.
func discardInput(r io.Reader, n uint32) {
	maxSize := uint32(10 * 1024) // 10k at a time
	numReads := n / maxSize
	bytesRemaining := n % maxSize
	if n > 0 {
		buf := make([]byte, maxSize)
		for i := uint32(0); i < numReads; i++ {
			io.ReadFull(r, buf)
		}
	}
	if bytesRemaining > 0 {
		buf := make([]byte, bytesRemaining)
		io.ReadFull(r, buf)
	}
}

// WriteMessageN writes a bitmessage Message to w including the necessary header
// information and returns the number of bytes written.    This function is the
// same as WriteMessage except it also returns the number of bytes written.
func WriteMessageN(w io.Writer, msg Message, bmnet BitmessageNet) (int, error) {
	totalBytes := 0

	// Enforce max command size.
	var command [CommandSize]byte
	cmd := msg.Command()
	if len(cmd) > CommandSize {
		str := fmt.Sprintf("command [%s] is too long [max %v]",
			cmd, CommandSize)
		return totalBytes, messageError("WriteMessage", str)
	}
	copy(command[:], []byte(cmd))

	// Encode the message payload.
	var bw bytes.Buffer
	err := msg.Encode(&bw)
	if err != nil {
		return totalBytes, err
	}
	payload := bw.Bytes()
	lenp := len(payload)

	// Enforce maximum overall message payload.
	if lenp > MaxMessagePayload {
		str := fmt.Sprintf("message payload is too large - encoded "+
			"%d bytes, but maximum message payload is %d bytes",
			lenp, MaxMessagePayload)
		return totalBytes, messageError("WriteMessage", str)
	}

	// Enforce maximum message payload based on the message type.
	mpl := msg.MaxPayloadLength()
	if lenp > mpl {
		str := fmt.Sprintf("message payload is too large - encoded "+
			"%d bytes, but maximum message payload size for "+
			"messages of type [%s] is %d.", lenp, cmd, mpl)
		return totalBytes, messageError("WriteMessage", str)
	}

	// Create header for the message.
	hdr := messageHeader{}
	hdr.magic = bmnet
	hdr.command = cmd
	hdr.length = uint32(lenp)
	copy(hdr.checksum[:], bmutil.Sha512(payload)[0:4])

	// Encode the header for the message.  This is done to a buffer
	// rather than directly to the writer since writeElements doesn't
	// return the number of bytes written.
	hw := bytes.NewBuffer(make([]byte, 0, MessageHeaderSize))

	writeElements(hw, hdr.magic, command, hdr.length, hdr.checksum)

	// Write header.
	n, err := w.Write(hw.Bytes())
	if err != nil {
		totalBytes += n
		return totalBytes, err
	}
	totalBytes += n

	// Write payload.
	n, err = w.Write(payload)
	if err != nil {
		totalBytes += n
		return totalBytes, err
	}
	totalBytes += n

	return totalBytes, nil
}

// WriteMessage writes a bitmessage Message to w including the necessary header
// information.  This function is the same as WriteMessageN except it doesn't
// doesn't return the number of bytes written.  This function is mainly provided
// for backwards compatibility with the original API, but it's also useful for
// callers that don't care about byte counts.
func WriteMessage(w io.Writer, msg Message, bmnet BitmessageNet) error {
	_, err := WriteMessageN(w, msg, bmnet)
	return err
}

// ReadMessageN reads, validates, and parses the next bitmessage Message from r for
// the provided protocol version and bitmessage network.  It returns the number of
// bytes read in addition to the parsed Message and raw bytes which comprise the
// message.  This function is the same as ReadMessage except it also returns the
// number of bytes read.
func ReadMessageN(r io.Reader, bmnet BitmessageNet) (int, Message, []byte, error) {
	totalBytes := 0
	n, hdr, err := readMessageHeader(r)
	if err != nil {
		totalBytes += n
		return totalBytes, nil, nil, err
	}

	totalBytes += n

	// Enforce maximum message payload as a malicious client could
	// otherwise create a well-formed header and set the length to max numbers
	// in order to exhaust the machine's memory.
	if hdr.length > MaxMessagePayload {
		str := fmt.Sprintf("message payload is too large - header "+
			"indicates %d bytes, but max message payload is %d "+
			"bytes.", hdr.length, MaxMessagePayload)
		return totalBytes, nil, nil, messageError("ReadMessage", str)
	}

	// Check for messages from the wrong bitmessage network.
	if hdr.magic != bmnet {
		discardInput(r, hdr.length)
		str := fmt.Sprintf("message from other network [%v]", hdr.magic)
		return totalBytes, nil, nil, messageError("ReadMessage", str)
	}

	// Check for malformed commands.
	command := hdr.command
	if !utf8.ValidString(command) {
		discardInput(r, hdr.length)
		str := fmt.Sprintf("invalid command %v", []byte(command))
		return totalBytes, nil, nil, messageError("ReadMessage", str)
	}

	payload := make([]byte, hdr.length)

	// read payload
	n, err = io.ReadFull(r, payload)
	totalBytes += n
	if err != nil {
		return totalBytes, nil, nil, err
	}

	// Create struct of appropriate message type based on the command.
	var msg Message

	if command == CmdObject {
		// Handle objects differently because we need to read some data to
		// know what message type it is
		var nonce uint64
		var sec int64
		var objType ObjectType
		err := readElements(bytes.NewReader(payload), &nonce, &sec, &objType)
		if err != nil {
			return totalBytes, nil, nil, messageError("ReadMessage",
				err.Error())
		}

		switch objType {
		case ObjectTypeGetPubKey:
			msg = &MsgGetPubKey{}
		case ObjectTypePubKey:
			msg = &MsgPubKey{}
		case ObjectTypeMsg:
			msg = &MsgMsg{}
		case ObjectTypeBroadcast:
			msg = &MsgBroadcast{}
		default:
			msg = &MsgUnknownObject{}
		}
	} else {
		msg, err = makeEmptyMessage(command)
		if err != nil {
			return totalBytes, nil, nil, messageError("ReadMessage",
				err.Error())
		}
	}

	// Check for maximum length based on the message type as a protection
	// against malicious users and malformed messages.
	mpl := msg.MaxPayloadLength()
	if int(hdr.length) > mpl {
		str := fmt.Sprintf("payload exceeds max length - header "+
			"indicates %v bytes, but max payload size for "+
			"messages of type [%v] is %v.", hdr.length, command, mpl)
		return totalBytes, nil, nil, messageError("ReadMessage", str)
	}

	// Test checksum.
	checksum := bmutil.Sha512(payload)[0:4]
	if !bytes.Equal(checksum[:], hdr.checksum[:]) {
		str := fmt.Sprintf("payload checksum failed - header "+
			"indicates %v, but actual checksum is %v.",
			hdr.checksum, checksum)
		return totalBytes, nil, nil, messageError("ReadMessage", str)
	}

	// Unmarshal message.
	err = msg.Decode(bytes.NewReader(payload))
	if err != nil {
		return totalBytes, nil, nil, err
	}

	return totalBytes, msg, payload, nil
}

// ReadMessage reads, validates, and parses the next bitmessage Message from r
// for bitmessage network.  It returns the parsed Message and raw bytes which
// comprise the message.  This function only differs from ReadMessageN in that
// it doesn't return the number of bytes read.  This function is useful for
// callers that don't care about byte counts.
func ReadMessage(r io.Reader, bmnet BitmessageNet) (Message, []byte, error) {
	_, msg, buf, err := ReadMessageN(r, bmnet)
	return msg, buf, err
}
