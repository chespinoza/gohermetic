//
// Example:
// "Key" must to have 16 or 32 chars
//
//package main
//
//import (
//		"github.com/chespinoza/gohermetic"
//		"fmt"
//)
//
//func main() {
//	key := []byte("example key 1234") // 16 chars
//	plaintext := []byte("example text to encrypt")
//
//	h := gohermetic.NewHermetic(key)
//	ciphertext := h.Encode(plaintext)
//	text, _ := h.Decode(ciphertext)
//	fmt.Printf("%s\n", ciphertext)
//	fmt.Printf("%s\n", text)
//}
//

package gohermetic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

type Hermetic struct {
	key []byte
}

func NewHermetic(key []byte) *Hermetic {
	l := len(key)
	switch l {
	case 16, 32:
		h := new(Hermetic)
		h.key = key
		return h
	default:
		panic("Key must to have 16 or 32 chars")
	}
}

func (h *Hermetic) AddKey(key []byte) bool {
	h.key = key
	return true
}

func (h *Hermetic) Decode(ciphertext []byte) (text []byte, err error) {
	block, err := aes.NewCipher(h.key)
	if err != nil {
		panic(err)
	}
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCFBDecrypter(block, iv)
	mode.XORKeyStream(ciphertext, ciphertext)
	text, err = base64.StdEncoding.DecodeString(string(ciphertext))
	return
}

func (h *Hermetic) Encode(plaintext []byte) []byte {

	block, err := aes.NewCipher(h.key)
	if err != nil {
		panic(err)
	}
	b64 := []byte(base64.StdEncoding.EncodeToString(plaintext))
	ciphertext := make([]byte, aes.BlockSize+len(b64))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	mode := cipher.NewCFBEncrypter(block, iv)
	mode.XORKeyStream(ciphertext[aes.BlockSize:], b64)
	return ciphertext
}
