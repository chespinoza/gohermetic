//
// Example:
//func main() {
//	key := []byte("example key 1234")
//	plaintext := []byte("example text to encrypt")
//
//	h := NewHermetic(key)
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
	"fmt"
	"io"
)

type Hermetic struct {
	key []byte
}

func NewHermetic(key []byte) *Hermetic {
	h := new(Hermetic)
	h.key = key
	return h
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