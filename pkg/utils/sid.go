package utils

import (
	"fmt"
)

// ConvertSidToSddl converts a binary SID to its SDDL string representation (S-1-5-...)
func ConvertSidToSddl(sid []byte) string {
	if len(sid) < 8 {
		return ""
	}

	revision := sid[0]
	// subAuthorityCount := sid[1]

	// Identifier Authority (6 bytes, big endian)
	// Usually 0-5, e.g., 5 for NT Authority
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(sid[i])
	}

	sddl := fmt.Sprintf("S-%d-%d", revision, authority)

	// SubAuthorities (4 bytes each, little endian)
	// We iterate from byte 8 onwards
	for i := 8; i < len(sid); i += 4 {
		if i+4 > len(sid) {
			break
		}
		var subAuth uint32
		// Little endian conversion
		subAuth = uint32(sid[i]) | (uint32(sid[i+1]) << 8) | (uint32(sid[i+2]) << 16) | (uint32(sid[i+3]) << 24)
		sddl += fmt.Sprintf("-%d", subAuth)
	}

	return sddl
}
