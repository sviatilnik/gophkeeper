package crypto

import "testing"

func TestHashPassword(t *testing.T) {
	password := "testpassword123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if hash == "" {
		t.Error("HashPassword returned empty string")
	}

	if hash == password {
		t.Error("HashPassword returned the same value as input")
	}
}

func TestHashPasswordEmpty(t *testing.T) {
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword failed with empty password: %v", err)
	}

	if hash == "" {
		t.Error("HashPassword returned empty string for empty password")
	}
}

func TestCheckPassword(t *testing.T) {
	password := "testpassword123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !CheckPassword(password, hash) {
		t.Error("CheckPassword failed for correct password")
	}

	if CheckPassword("wrongpassword", hash) {
		t.Error("CheckPassword succeeded for wrong password")
	}
}

func TestCheckPasswordEmpty(t *testing.T) {
	hash, err := HashPassword("test")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if CheckPassword("", hash) {
		t.Error("CheckPassword should fail for empty password")
	}
}

func TestHashSHA256(t *testing.T) {
	data := []byte("test data")
	hash1 := HashSHA256(data)
	hash2 := HashSHA256(data)

	if hash1 != hash2 {
		t.Error("HashSHA256 returned different hashes for same input")
	}

	if len(hash1) != 64 { // SHA256 produces 64 hex characters
		t.Errorf("HashSHA256 returned hash of wrong length: %d", len(hash1))
	}
}

func TestHashSHA256Empty(t *testing.T) {
	data := []byte("")
	hash := HashSHA256(data)

	if len(hash) != 64 {
		t.Errorf("HashSHA256 returned hash of wrong length for empty data: %d", len(hash))
	}
}

func TestHashSHA256DifferentData(t *testing.T) {
	data1 := []byte("test1")
	data2 := []byte("test2")

	hash1 := HashSHA256(data1)
	hash2 := HashSHA256(data2)

	if hash1 == hash2 {
		t.Error("HashSHA256 returned same hash for different data")
	}
}
