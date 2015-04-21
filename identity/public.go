package identity

import (
	"github.com/btcsuite/btcd/btcec"

	"github.com/monetas/bmutil"
	"github.com/monetas/bmutil/pow"
)

// Public contains the identity of the remote  user, which includes public
// encryption and signing keys, POW parameters and the address that contains
// information about stream number and address version.
type Public struct {
	bmutil.Address
	NonceTrialsPerByte uint64
	ExtraBytes         uint64
	SigningKey         *btcec.PublicKey
	EncryptionKey      *btcec.PublicKey
}

// CreateAddress populates the Address object within the identity based on the
// provided version and stream values and also generates the ripe.
func (id *Public) CreateAddress(version, stream uint64) {
	id.Address.Version = version
	id.Address.Stream = stream
	copy(id.Address.Ripe[:], id.hash())
}

func (id *Public) setDefaultPOWParams() {
	id.NonceTrialsPerByte = pow.DefaultNonceTrialsPerByte
	id.ExtraBytes = pow.DefaultExtraBytes
}

// hash returns the ripemd160 hash used in the address
func (id *Public) hash() []byte {
	return hash_helper(id.SigningKey.SerializeUncompressed(),
		id.EncryptionKey.SerializeUncompressed())
}
