package utils

import (
	"encoding/hex"
	"testing"
)

func TestConvertSidToSddl(t *testing.T) {
	// Example SID: S-1-5-21-3627276066-3195855974-1188546171-500
	// Hex: 01050000000000051500000022d733d866e47cbe7bc6d746f4010000
	// Little Endian Verification:
	// 22d733d8 -> 3627276066
	// 66e47cbe -> 3195855974
	// 7bc6d746 -> 1188546171
	// f4010000 -> 500
	sidHex := "01050000000000051500000022d733d866e47cbe7bc6d746f4010000"
	sidBytes, _ := hex.DecodeString(sidHex)

	expected := "S-1-5-21-3627276066-3195855974-1188546171-500"
	result := ConvertSidToSddl(sidBytes)

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}
