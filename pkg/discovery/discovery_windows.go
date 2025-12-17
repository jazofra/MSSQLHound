//go:build windows

package discovery

import (
	"fmt"
    "strings"
	"syscall"
	"unsafe"
)

var (
	wldap32        = syscall.NewLazyDLL("wldap32.dll")
	ldap_init      = wldap32.NewProc("ldap_initW")
	ldap_connect   = wldap32.NewProc("ldap_connect")
	ldap_bind_s    = wldap32.NewProc("ldap_bind_sW")
	ldap_search_s  = wldap32.NewProc("ldap_search_sW")
	ldap_msgfree   = wldap32.NewProc("ldap_msgfree")
	ldap_unbind    = wldap32.NewProc("ldap_unbind")
    ldap_first_entry = wldap32.NewProc("ldap_first_entry")
    ldap_next_entry  = wldap32.NewProc("ldap_next_entry")
    ldap_get_values  = wldap32.NewProc("ldap_get_valuesW")
    ldap_value_free  = wldap32.NewProc("ldap_value_freeW")
)

const (
	LDAP_AUTH_NEGOTIATE = 0x486
	LDAP_SCOPE_SUBTREE  = 2
	LDAP_SUCCESS        = 0
    LDAP_PORT           = 389
)

type WindowsDiscoverer struct {
	ld     uintptr
	domain string
}

func NewWindowsDiscoverer(domainController string, domain string) (*WindowsDiscoverer, error) {
	dcPtr, _ := syscall.UTF16PtrFromString(domainController)
	ld, _, _ := ldap_init.Call(uintptr(unsafe.Pointer(dcPtr)), uintptr(LDAP_PORT))
	if ld == 0 {
		return nil, fmt.Errorf("ldap_init failed")
	}

	ret, _, _ := ldap_connect.Call(ld, 0)
	if ret != LDAP_SUCCESS {
        ldap_unbind.Call(ld)
		return nil, fmt.Errorf("ldap_connect failed: %d", ret)
	}

	ret, _, _ = ldap_bind_s.Call(ld, 0, 0, uintptr(LDAP_AUTH_NEGOTIATE))
	if ret != LDAP_SUCCESS {
        ldap_unbind.Call(ld)
		return nil, fmt.Errorf("ldap_bind_s (Negotiate) failed: %d. Ensure you are in a domain context.", ret)
	}

	return &WindowsDiscoverer{ld: ld, domain: domain}, nil
}

func (w *WindowsDiscoverer) Close() {
	if w.ld != 0 {
		ldap_unbind.Call(w.ld)
		w.ld = 0
	}
}

func (w *WindowsDiscoverer) FindMSSQLSPNs() ([]string, error) {
	filter := "(servicePrincipalName=MSSQLSvc/*)"
	attr := "servicePrincipalName"
    return w.search(filter, attr)
}

func (w *WindowsDiscoverer) FindComputers() ([]string, error) {
    filter := "(objectClass=computer)"
    attr := "dNSHostName"
    return w.search(filter, attr)
}

func (w *WindowsDiscoverer) search(filter string, attr string) ([]string, error) {
    // Convert domain to DN
    parts := strings.Split(w.domain, ".")
    var dnParts []string
    for _, part := range parts {
        dnParts = append(dnParts, "DC="+part)
    }
    baseDN := strings.Join(dnParts, ",")

    basePtr, _ := syscall.UTF16PtrFromString(baseDN)
    filterPtr, _ := syscall.UTF16PtrFromString(filter)
    attrPtr, _ := syscall.UTF16PtrFromString(attr)

    // Attributes array (null-terminated)
    var attrs []*uint16
    attrs = append(attrs, attrPtr)
    attrs = append(attrs, nil)
    attrsPtr := uintptr(unsafe.Pointer(&attrs[0]))

    var res uintptr

    // ldap_search_sW
    ret, _, _ := ldap_search_s.Call(
        w.ld,
        uintptr(unsafe.Pointer(basePtr)),
        uintptr(LDAP_SCOPE_SUBTREE),
        uintptr(unsafe.Pointer(filterPtr)),
        attrsPtr,
        0,
        uintptr(unsafe.Pointer(&res)),
    )

    if ret != LDAP_SUCCESS {
        return nil, fmt.Errorf("ldap_search_s failed: %d", ret)
    }
    defer ldap_msgfree.Call(res)

    var results []string

    // Iterate results
    for entry, _, _ := ldap_first_entry.Call(w.ld, res); entry != 0; entry, _, _ = ldap_next_entry.Call(w.ld, entry) {
        // Get values
        valsPtr, _, _ := ldap_get_values.Call(w.ld, entry, uintptr(unsafe.Pointer(attrPtr)))
        if valsPtr != 0 {
            // valsPtr is *PWCHAR[], null terminated
            // We need to iterate the array
            // Go doesn't let us iterate uintptr array easily without casting

            // Pointer arithmetic simulation
            p := valsPtr
            for {
                // Read the pointer at p
                valPtr := *(*uintptr)(unsafe.Pointer(p))
                if valPtr == 0 {
                    break
                }

                // Convert PWCHAR to string
                str := syscall.UTF16ToString((*[1 << 30]uint16)(unsafe.Pointer(valPtr))[:])

                // For SPNs, we might get multiple values per object?
                // Yes, check prefix for FindMSSQLSPNs
                if attr == "servicePrincipalName" {
                    if strings.HasPrefix(str, "MSSQLSvc/") {
                        results = append(results, str)
                    }
                } else {
                    results = append(results, str)
                }

                // Increment p by size of pointer (8 bytes on 64-bit)
                p += unsafe.Sizeof(uintptr(0))
            }

            ldap_value_free.Call(valsPtr)
        }
    }

    return results, nil
}
