// Package encryptedkey provides elliptic curve cryptography for DTLS
package encryptedkey

import (
	"testing"
)

func TestCBCEncryptAndDecrypt(t *testing.T) {
	key := "example key 1234"
	plaintext := "exampleplaintextexampleplaintext"

	ciphertext := AESCBCEncryptFromString(key, plaintext)
	decryptPlaintext := AESCBCDecryptFromString(key, ciphertext)

	if decryptPlaintext != plaintext {
		t.Errorf("Decrypt error! The plaintext is: %s. The decrypted text is: %s\n", plaintext, decryptPlaintext)
	}

	cipherbyte := AESCBCEncryptFromBytes([]byte(key), []byte(plaintext))
	decryptBytes := AESCBCDecryptFromBytes([]byte(key), cipherbyte)

	if string(decryptBytes) != plaintext {
		t.Errorf("Decrypt error! The plaintext is: %s. The decrypted text is: %s\n", []byte(plaintext), decryptBytes)
	}
}

func TestGCMEncryptAndDecrypt(t *testing.T) {
	key := "example key 1234"
	plaintext := "exampleplaintext"

	ciphertext, noncetext := AESGCMEncrypt(key, plaintext)
	decryptPlaintext := AESGCMDecrypt(key, ciphertext, noncetext)

	if decryptPlaintext != plaintext {
		t.Errorf("Decrypt error! The plaintext is: %s. The decrypted text is: %s\n", plaintext, decryptPlaintext)
	}
}
