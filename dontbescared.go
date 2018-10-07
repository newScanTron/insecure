package insecure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func GetUniqueToken() string {
	crutime := time.Now().Unix()
	h := md5.New()
	io.WriteString(h, strconv.FormatInt(crutime, 10))
	token := fmt.Sprintf("%x", h.Sum(nil))
	return token
}

//SetPasswordHash returns a string version of a bcrypt hashed password.
func SetPasswordHash(pw string) []byte {
	userPassword1 := pw

	// Generate "hash" to store from user password
	hash, err := bcrypt.GenerateFromPassword([]byte(userPassword1), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
		return []byte(err.Error())
	}
	// fmt.Println("Hash to store:", string(hash))
	return hash
}

func CheckPasswordhash(pw string, hs []byte) bool {
	if string(SetPasswordHash(pw)) != string(hs) {
		return false
	}
	return true
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
