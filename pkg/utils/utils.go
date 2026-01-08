package utils

import "strings"

// SplitObjectIdentifier splits an object identifier into name and context (e.g., "name@context")
func SplitObjectIdentifier(objID string) (string, string) {
	parts := strings.Split(objID, "@")
	if len(parts) > 1 {
		return parts[0], parts[1]
	}
	return parts[0], ""
}

// ConvertToBool converts various SQL types (0/1, string "true"/"false") to bool
func ConvertToBool(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case int:
		return val == 1
	case int64:
		return val == 1
	case string:
		return val == "1" || strings.ToLower(val) == "true"
	default:
		return false
	}
}
