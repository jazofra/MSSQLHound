package utils

import (
	"testing"
)

func TestSplitObjectIdentifier(t *testing.T) {
	name, context := SplitObjectIdentifier("user@domain")
	if name != "user" || context != "domain" {
		t.Errorf("Expected user, domain; got %s, %s", name, context)
	}

	name, context = SplitObjectIdentifier("simple")
	if name != "simple" || context != "" {
		t.Errorf("Expected simple, ''; got %s, %s", name, context)
	}
}

func TestConvertToBool(t *testing.T) {
	if !ConvertToBool(1) {
		t.Error("Expected true for 1")
	}
	if !ConvertToBool("1") {
		t.Error("Expected true for '1'")
	}
	if !ConvertToBool(true) {
		t.Error("Expected true for true")
	}
	if ConvertToBool(0) {
		t.Error("Expected false for 0")
	}
}
