package sec

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"

	drshproto "github.com/dmhacker/drsh/internal/drsh/proto"
	"github.com/monnand/dhkx"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Attached to a host and provides the host
// with key exchange & symmetric encryption capabilities
type EncryptionModule struct {
	cipher        cipher.AEAD
	group         *dhkx.DHGroup
	PrivateKey    *dhkx.DHKey
	completedFlag bool
	completedMtx  sync.Mutex
	completedCnd  *sync.Cond
}

func NewEncryptionModule() *EncryptionModule {
	em := EncryptionModule{
		completedFlag: false,
	}
	em.completedCnd = sync.NewCond(&em.completedMtx)
	return &em
}

// Creates the host's keypair needed for key exchange.
func (em *EncryptionModule) PrepareKeyExchange() error {
	grp, err := dhkx.GetGroup(0)
	if err != nil {
		return err
	}
	priv, err := grp.GeneratePrivateKey(nil)
	if err != nil {
		return err
	}
	em.group = grp
	em.PrivateKey = priv
	return nil
}

// Marks the completion of the key exchange protocol.
// When the key exchange handshake is performed, the other host's public
// key is mixed with the keypair generated via PrepareKeyExchange. This
// creates a shared secret, passed through a KDF and given to a cipher.
func (em *EncryptionModule) CompleteKeyExchange(key []byte) error {
	pub := dhkx.NewPublicKey(key)
	secret, err := em.group.ComputeKey(pub, em.PrivateKey)
	if err != nil {
		return err
	}
	deriv := hkdf.New(sha256.New, secret.Bytes(), nil, nil)
	skey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(deriv, skey); err != nil {
		return err
	}
	em.cipher, err = chacha20poly1305.New(skey)
	if err != nil {
		return err
	}
	em.completedMtx.Lock()
	defer em.completedMtx.Unlock()
	em.completedFlag = true
	return nil
}

// Blocks until a key exchange has been completed, resulting in a valid cipher
func (em *EncryptionModule) WaitForKeyExchange() {
	em.completedMtx.Lock()
	defer em.completedMtx.Unlock()
	for !em.completedFlag {
		em.completedCnd.Wait()
	}
}

// Removes references to the keypair, allowing for it to
// be garbage collected.
func (em *EncryptionModule) FreePrivateKeys() {
	em.group = nil
	em.PrivateKey = nil
}

// Encrypt a message with the key formed during the key exchange process.
// If encryption is not enabled, then the data is returned without modification.
func (em *EncryptionModule) Encrypt(data []byte) (*drshproto.EncryptedSessionMessage, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := em.cipher.Seal(nil, nonce, data, nil)
	return &drshproto.EncryptedSessionMessage{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

// Decrypts a ciphertext with the key formed during the key exchange process.
// If encryption is not enabled, then the data is returned without modification.
func (em *EncryptionModule) Decrypt(emsg *drshproto.EncryptedSessionMessage) ([]byte, error) {
	plaintext, err := em.cipher.Open(nil, emsg.Nonce, emsg.Ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
