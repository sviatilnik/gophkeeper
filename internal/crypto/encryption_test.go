package crypto

import "testing"

func TestEncryptDecryptData(t *testing.T) {
	key := make([]byte, 32) // AES-256 requires 32-byte key
	for i := range key {
		key[i] = byte(i)
	}

	originalData := []byte("test secret data")

	ciphertext, err := EncryptData(originalData, key)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Error("EncryptData returned empty ciphertext")
	}

	plaintext, err := DecryptData(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptData failed: %v", err)
	}

	if string(plaintext) != string(originalData) {
		t.Errorf("DecryptData returned wrong data: got %s, want %s", string(plaintext), string(originalData))
	}
}

func TestDecryptDataWithWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1 // Different key

	originalData := []byte("test secret data")

	ciphertext, err := EncryptData(originalData, key1)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	_, err = DecryptData(ciphertext, key2)
	if err == nil {
		t.Error("DecryptData should fail with wrong key")
	}
}

func TestDecryptDataWithShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	shortCiphertext := []byte("short")

	_, err := DecryptData(shortCiphertext, key)
	if err == nil {
		t.Error("DecryptData should fail with short ciphertext")
	}
}

func TestDecryptDataWithWrongKeyLength(t *testing.T) {
	key := make([]byte, 15) // Invalid key length (AES requires 16, 24, or 32 bytes)

	originalData := []byte("test data")
	_, err := EncryptData(originalData, key)
	if err == nil {
		t.Error("EncryptData should fail with invalid key length")
	}
}

func TestDeriveKeyFromPassword(t *testing.T) {
	password := "testpassword"
	salt := []byte("testsalt")

	key1 := DeriveKeyFromPassword(password, salt)
	key2 := DeriveKeyFromPassword(password, salt)

	if len(key1) != 32 {
		t.Errorf("DeriveKeyFromPassword returned key of wrong length: %d", len(key1))
	}

	// Same password and salt should produce same key
	if string(key1) != string(key2) {
		t.Error("DeriveKeyFromPassword returned different keys for same input")
	}

	// Different salt should produce different key
	salt2 := []byte("differentsalt")
	key3 := DeriveKeyFromPassword(password, salt2)
	if string(key1) == string(key3) {
		t.Error("DeriveKeyFromPassword returned same key for different salt")
	}

	// Different password should produce different key
	key4 := DeriveKeyFromPassword("differentpassword", salt)
	if string(key1) == string(key4) {
		t.Error("DeriveKeyFromPassword returned same key for different password")
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := []byte("test1")
	b := []byte("test1")
	c := []byte("test2")

	if !ConstantTimeCompare(a, b) {
		t.Error("ConstantTimeCompare should return true for equal slices")
	}

	if ConstantTimeCompare(a, c) {
		t.Error("ConstantTimeCompare should return false for different slices")
	}

	// Empty slices should be equal
	if !ConstantTimeCompare([]byte(""), []byte("")) {
		t.Error("ConstantTimeCompare should return true for empty slices")
	}

	// Different length slices should be different
	if ConstantTimeCompare([]byte("a"), []byte("ab")) {
		t.Error("ConstantTimeCompare should return false for different length slices")
	}
}
