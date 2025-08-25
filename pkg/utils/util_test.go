package utils

import (
	"testing"
)

func TestRandomBits(t *testing.T) {
	out, err := RandomBits(24)
	if err != nil {
		t.Fatalf("Error generating random bits: %v", err)
	}
	if len(out) != 3 {
		t.Errorf("Expected 3 random byte; got %d", len(out))
	}

	out, err = RandomBits(14)
	if err != nil {
		t.Fatalf("Error generating random bits: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("Expected 2 random byte; got %d", len(out))
	}
	leadingTwoBits := out[0] & 0xC0
	if leadingTwoBits != 0 {
		t.Errorf("Expected top 2 bits to be zero, got %d", leadingTwoBits)
	}

	// Error when bits <= 2
	_, err = RandomBits(2)
	if err == nil {
		t.Errorf("Expected error when bits <= 2; got none")
	}
}
