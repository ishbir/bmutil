package cipher

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/monetas/bmutil"
	"github.com/monetas/bmutil/identity"
	"github.com/monetas/bmutil/wire"
)

var (
	ErrUnsupportedOp    = errors.New("operation unsupported")
	ErrInvalidSignature = errors.New("invalid signature/verification failed")
	ErrInvalidIdentity  = errors.New("invalid supplied identity/decryption failed")
)

// SignAndEncryptPubkey signs and encrypts a MsgPubKey message, populating the
// Signature and Encrypted fields using the provided private identity.
//
// The private identity supplied should be of the sender. There are no checks
// against supplying invalid private identity.
func SignAndEncryptPubKey(msg *wire.MsgPubKey, privId *identity.Private) error {
	if msg.Version < wire.ExtendedPubKeyVersion ||
		msg.Version > wire.EncryptedPubKeyVersion {
		return ErrUnsupportedOp
	}
	// Start signing
	var b bytes.Buffer
	err := msg.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	b.Reset()

	// Sign
	sig, err := privId.SigningKey.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}
	msg.Signature = sig.Serialize()

	// Start encryption
	if msg.Version != wire.EncryptedPubKeyVersion {
		return nil // Current version doesn't support encryption. We're done!
	}

	err = msg.EncodeForEncryption(&b)
	if err != nil {
		return err
	}

	// Encrypt
	msg.Encrypted, err = btcec.Encrypt(privId.Address.PrivateKey().PubKey(),
		b.Bytes())
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	return nil
}

// SignAndEncryptBroadcast signs and encrypts a MsgBroadcast message, populating
// the Signature and Encrypted fields using the provided private identity.
//
// The private identity supplied should be of the sender. There are no checks
// against supplying invalid private identity.
func SignAndEncryptBroadcast(msg *wire.MsgBroadcast, privId *identity.Private) error {
	switch msg.Version {
	case wire.TaglessBroadcastVersion:
		if msg.FromAddressVersion != 2 && msg.FromAddressVersion != 3 {
			// only v2/v3 addresses allowed for tagless broadcast
			return ErrUnsupportedOp
		}
	case wire.TagBroadcastVersion:
		if msg.FromAddressVersion != 4 {
			// only v4 addresses support tags
			return ErrUnsupportedOp
		}
	default:
		return ErrUnsupportedOp
	}

	// Start signing
	var b bytes.Buffer
	err := msg.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	b.Reset()

	// Sign
	sig, err := privId.SigningKey.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}
	msg.Signature = sig.Serialize()

	// Start encryption
	err = msg.EncodeForEncryption(&b)
	if err != nil {
		return err
	}

	// Encrypt
	switch msg.Version {
	case wire.TaglessBroadcastVersion:
		msg.Encrypted, err = btcec.Encrypt(privId.Address.PrivateKeySingleHash().PubKey(),
			b.Bytes())

	case wire.TagBroadcastVersion:
		msg.Encrypted, err = btcec.Encrypt(privId.Address.PrivateKey().PubKey(),
			b.Bytes())
	}

	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	return nil
}

// SignAndEncryptMsg signs and encrypts a MsgMsg message, populating the
// Signature and Encrypted fields using the provided private identity.
//
// The private identity supplied should be of the sender. The public identity
// should be that of the recipient. There are no checks against supplying
// invalid private or public identities.
func SignAndEncryptMsg(msg *wire.MsgMsg, privId *identity.Private,
	pubId *identity.Public) error {
	if msg.Version != 1 {
		return ErrUnsupportedOp
	}

	// Start signing
	var b bytes.Buffer
	err := msg.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	b.Reset()

	// Sign
	sig, err := privId.SigningKey.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}
	msg.Signature = sig.Serialize()

	// Start encryption
	err = msg.EncodeForEncryption(&b)
	if err != nil {
		return err
	}

	// Encrypt
	msg.Encrypted, err = btcec.Encrypt(pubId.EncryptionKey, b.Bytes())
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	return nil
}

// TryDecryptAndVerifyPubKey tries to decrypt a wire.MsgPubKey of the address.
// If it fails, it returns ErrInvalidIdentity. If decryption succeeds, it
// verifies the embedded signature. If signature verification fails, it returns
// ErrInvalidSignature. Else, it returns nil.
//
// All necessary fields of the provided wire.MsgPubKey are populated.
func TryDecryptAndVerifyPubKey(msg *wire.MsgPubKey, address *bmutil.Address) error {
	if msg.Version < wire.ExtendedPubKeyVersion ||
		msg.Version > wire.EncryptedPubKeyVersion {
		return ErrUnsupportedOp
	}

	// Try decryption if msg.Version == wire.EncryptedPubKeyVersion
	if msg.Version == wire.EncryptedPubKeyVersion {
		// Check tag, save decryption cost.
		if subtle.ConstantTimeCompare(msg.Tag[:], address.Tag()) != 1 {
			return ErrInvalidIdentity
		}

		dec, err := btcec.Decrypt(address.PrivateKey(), msg.Encrypted)
		if err == btcec.ErrInvalidMAC { // decryption failed due to invalid key
			return ErrInvalidIdentity
		} else if err != nil { // other reasons
			return err
		}

		err = msg.DecodeFromDecrypted(bytes.NewReader(dec))
		if err != nil {
			return err
		}
	}

	// Verify validity of secp256k1 public keys.
	signKey, err := msg.SigningKey.ToBtcec()
	if err != nil {
		return err
	}
	encKey, err := msg.EncryptionKey.ToBtcec()
	if err != nil {
		return err
	}

	// Check if embedded keys correspond to the address used for decryption.
	if msg.Version == wire.EncryptedPubKeyVersion {
		id := identity.NewPublic(signKey, encKey, msg.NonceTrials,
			msg.ExtraBytes, msg.Version, msg.StreamNumber)

		genAddr, _ := id.Address.Encode()
		dencAddr, _ := address.Encode()
		if dencAddr != genAddr {
			return fmt.Errorf("Address used for decryption (%s) doesn't match "+
				"that generated from public key (%s). Possible surreptitious "+
				"forwarding attack.", dencAddr, genAddr)
		}
	}

	// Start signature verification
	var b bytes.Buffer
	err = msg.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	sha1hash := sha1.Sum(b.Bytes()) // backwards compatibility

	// Verify
	sig, err := btcec.ParseSignature(msg.Signature, btcec.S256())
	if err != nil {
		return ErrInvalidSignature
	}

	if !sig.Verify(hash[:], signKey) { // Try SHA256 first
		if !sig.Verify(sha1hash[:], signKey) { // then SHA1
			return ErrInvalidSignature
		}
	}

	return nil
}

// TryDecryptAndVerifyBroadcast tries to decrypt a wire.MsgBroadcast of the
// public identity. If it fails, it returns ErrInvalidIdentity. If decryption
// succeeds, it verifies the embedded signature. If signature verification
// fails, it returns ErrInvalidSignature. Else, it returns nil.
//
// All necessary fields of the provided wire.MsgBroadcast are populated.
func TryDecryptAndVerifyBroadcast(msg *wire.MsgBroadcast, address *bmutil.Address) error {
	var dec []byte
	var err error

	switch msg.Version {
	case wire.TaglessBroadcastVersion:
		dec, err = btcec.Decrypt(address.PrivateKeySingleHash(), msg.Encrypted)
	case wire.TagBroadcastVersion:
		if subtle.ConstantTimeCompare(msg.Tag[:], address.Tag()) != 1 {
			return ErrInvalidIdentity
		}
		dec, err = btcec.Decrypt(address.PrivateKey(), msg.Encrypted)
	default:
		return ErrUnsupportedOp
	}

	if err == btcec.ErrInvalidMAC { // decryption failed due to invalid key
		return ErrInvalidIdentity
	} else if err != nil { // other reasons
		return err
	}

	err = msg.DecodeFromDecrypted(bytes.NewReader(dec))
	if err != nil {
		return err
	}

	// Check if embedded keys correspond to the address used to decrypt.
	signKey, err := msg.SigningKey.ToBtcec()
	if err != nil {
		return err
	}
	encKey, err := msg.EncryptionKey.ToBtcec()
	if err != nil {
		return err
	}
	id := identity.NewPublic(signKey, encKey, msg.NonceTrials,
		msg.ExtraBytes, msg.FromAddressVersion, msg.FromStreamNumber)

	genAddr, _ := id.Address.Encode()
	dencAddr, _ := address.Encode()
	if dencAddr != genAddr {
		return fmt.Errorf("Address used for decryption (%s) doesn't match "+
			"that generated from public key (%s). Possible surreptitious "+
			"forwarding attack.", dencAddr, genAddr)
	}

	// Start signature verification
	var b bytes.Buffer
	err = msg.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	sha1hash := sha1.Sum(b.Bytes()) // backwards compatibility

	// Verify
	sig, err := btcec.ParseSignature(msg.Signature, btcec.S256())
	if err != nil {
		return ErrInvalidSignature
	}

	if !sig.Verify(hash[:], signKey) { // Try SHA256 first
		if !sig.Verify(sha1hash[:], signKey) { // then SHA1
			return ErrInvalidSignature
		}
	}
	return nil
}

// TryDecryptAndVerifyMsg tries to decrypt a wire.MsgMsg using the private
// identity. If it fails, it returns ErrInvalidIdentity. If decryption succeeds,
// it verifies the embedded signature. If signature verification fails, it
// returns ErrInvalidSignature. Else, it returns nil.
//
// All necessary fields of the provided wire.MsgMsg are populated.
func TryDecryptAndVerifyMsg(msg *wire.MsgMsg, privId *identity.Private) error {
	if msg.Version != 1 {
		return ErrUnsupportedOp
	}

	dec, err := btcec.Decrypt(privId.EncryptionKey, msg.Encrypted)

	if err == btcec.ErrInvalidMAC { // decryption failed due to invalid key
		return ErrInvalidIdentity
	} else if err != nil { // other reasons
		return err
	}

	err = msg.DecodeFromDecrypted(bytes.NewReader(dec))
	if err != nil {
		return err
	}

	// Check if embedded destination ripe corresponds to private identity.
	if subtle.ConstantTimeCompare(privId.Address.Ripe[:],
		msg.Destination.Bytes()) != 1 {
		return fmt.Errorf("Decryption succeeded but ripes don't match. Got %s"+
			" expected %s", msg.Destination,
			hex.EncodeToString(privId.Address.Ripe[:]))
	}

	// Start signature verification
	var b bytes.Buffer
	err = msg.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	sha1hash := sha1.Sum(b.Bytes())

	// Verify
	pubSigningKey, err := msg.SigningKey.ToBtcec()
	if err != nil {
		return err
	}

	sig, err := btcec.ParseSignature(msg.Signature, btcec.S256())
	if err != nil {
		return ErrInvalidSignature
	}

	if !sig.Verify(hash[:], pubSigningKey) { // Try SHA256 first
		if !sig.Verify(sha1hash[:], pubSigningKey) { // then SHA1
			return ErrInvalidSignature
		}
	}

	return nil
}
