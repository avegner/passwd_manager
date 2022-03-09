package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
)

var ErrNotFound = errors.New("not found")

const KeySize = 32

type Storage struct {
	db passwdDB
}

type passwdDB map[string]string

func New(blob, nonce, key []byte) (*Storage, error) {
	var db passwdDB

	if len(blob) > 0 && len(nonce) > 0 && len(key) > 0 {
		var err error
		if db, err = decrypt(blob, nonce, key); err != nil {
			return nil, err
		}
	} else {
		db = make(passwdDB)
	}

	return &Storage{db: db}, nil
}

// decrypt func decrypts a blob with passwords.
func decrypt(blob, nonce, key []byte) (passwdDB, error) {
	c, err := aes.NewCipher(normalizeKey(key))
	if err != nil {
		return nil, err
	}

	mode, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	m, err := mode.Open(nil, nonce, blob, nil)
	if err != nil {
		return nil, err
	}

	db := make(passwdDB)
	if err = json.Unmarshal(m, &db); err != nil {
		return nil, err
	}

	return db, nil
}

// Encrypt encrypts passwords into a blob.
func (st *Storage) Encrypt(key []byte) (blob []byte, nonce []byte, err error) {
	m, err := json.Marshal(st.db)
	if err != nil {
		return nil, nil, err
	}

	c, err := aes.NewCipher(normalizeKey(key))
	if err != nil {
		return nil, nil, err
	}

	mode, err := cipher.NewGCM(c)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, mode.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	return mode.Seal(nil, nonce, m, nil), nonce, nil
}

// Put adds a new password with the given label.
func (st *Storage) Put(label, passwd string) {
	st.db[label] = passwd
}

// Get returns a password for the given label.
func (st *Storage) Get(label string) (string, error) {
	passwd, ok := st.db[label]
	if !ok {
		return "", ErrNotFound
	}
	return passwd, nil
}

// Remove returns a label with corresponding password.
func (st *Storage) Remove(label string) error {
	if _, ok := st.db[label]; !ok {
		return ErrNotFound
	}
	delete(st.db, label)
	return nil
}

// List returns all labels.
func (st *Storage) List() []string {
	labels := make([]string, 0, len(st.db))
	for k := range st.db {
		labels = append(labels, k)
	}
	return labels
}

func normalizeKey(v []byte) []byte {
	if len(v) > KeySize {
		return v[:KeySize]
	} else if len(v) < KeySize {
		return append(v, make([]byte, KeySize-len(v))...)
	}
	return v
}
