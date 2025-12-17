//go:build !windows

package discovery

import (
	"fmt"
	"runtime"

	"github.com/go-ldap/ldap/v3"
)

// BindCurrentWindowsUser is a stub for non-Windows platforms
func BindCurrentWindowsUser(conn *ldap.Conn) error {
	return fmt.Errorf("automatic Windows authentication is not supported on %s", runtime.GOOS)
}
