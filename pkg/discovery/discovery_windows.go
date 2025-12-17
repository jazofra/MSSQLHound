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
    ldap_search_ext_s = wldap32.NewProc("ldap_search_ext_sW")
    ldap_search_init_page = wldap32.NewProc("ldap_search_init_pageW")
    ldap_get_next_page_s = wldap32.NewProc("ldap_get_next_page_s")
    ldap_search_abandon_page = wldap32.NewProc("ldap_search_abandon_page")
	ldap_msgfree   = wldap32.NewProc("ldap_msgfree")
	ldap_unbind    = wldap32.NewProc("ldap_unbind")
    ldap_first_entry = wldap32.NewProc("ldap_first_entry")
    ldap_next_entry  = wldap32.NewProc("ldap_next_entry")
    ldap_get_values  = wldap32.NewProc("ldap_get_valuesW")
    ldap_value_free  = wldap32.NewProc("ldap_value_freeW")
    ldap_set_option    = wldap32.NewProc("ldap_set_optionW")
)

const (
	LDAP_AUTH_NEGOTIATE = 0x486
	LDAP_SCOPE_SUBTREE  = 2
	LDAP_SUCCESS        = 0
    LDAP_NO_RESULTS_RETURNED = 0x5E // 94
    LDAP_PORT           = 389
    PAGE_SIZE = 1000

    LDAP_OPT_PROTOCOL_VERSION = 0x11
    LDAP_VERSION3             = 3
    LDAP_OPT_REFERRALS        = 0x02
    LDAP_OPT_OFF              = 0
)

type WindowsDiscoverer struct {
	ld     uintptr
	domain string
    debug  bool
}

func NewWindowsDiscoverer(domainController string, domain string, debug bool) (*WindowsDiscoverer, error) {
    if debug {
        fmt.Printf("[DEBUG] Initializing Windows LDAP client for %s\n", domainController)
    }
	dcPtr, _ := syscall.UTF16PtrFromString(domainController)
	ld, _, _ := ldap_init.Call(uintptr(unsafe.Pointer(dcPtr)), uintptr(LDAP_PORT))
	if ld == 0 {
		return nil, fmt.Errorf("ldap_init failed")
	}

    // Set LDAP v3
    version := uintptr(LDAP_VERSION3)
    ret, _, _ := ldap_set_option.Call(ld, uintptr(LDAP_OPT_PROTOCOL_VERSION), uintptr(unsafe.Pointer(&version)))
    if debug {
        fmt.Printf("[DEBUG] Set LDAPv3: ret=%d\n", ret)
    }

    // Disable Referrals
    referrals := uintptr(LDAP_OPT_OFF)
    ret, _, _ = ldap_set_option.Call(ld, uintptr(LDAP_OPT_REFERRALS), uintptr(unsafe.Pointer(&referrals)))
    if debug {
        fmt.Printf("[DEBUG] Disable Referrals: ret=%d\n", ret)
    }

	ret, _, _ = ldap_connect.Call(ld, 0)
	if ret != LDAP_SUCCESS {
        ldap_unbind.Call(ld)
		return nil, fmt.Errorf("ldap_connect failed: %d", ret)
	}

	ret, _, _ = ldap_bind_s.Call(ld, 0, 0, uintptr(LDAP_AUTH_NEGOTIATE))
	if ret != LDAP_SUCCESS {
        ldap_unbind.Call(ld)
		return nil, fmt.Errorf("ldap_bind_s (Negotiate) failed: %d. Ensure you are in a domain context.", ret)
	}
    if debug {
        fmt.Printf("[DEBUG] Bind Successful\n")
    }

	return &WindowsDiscoverer{ld: ld, domain: domain, debug: debug}, nil
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
    if w.debug {
        fmt.Printf("[DEBUG] Searching %s for %s\n", filter, attr)
    }
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

    // Initialize Page Search
    var searchHandle uintptr
    // ldap_search_init_pageW
    // Args: ld, dn, scope, filter, attrs, attrsonly, serverctrls, clientctrls, pagetimelimit, totalsizelimit, sortkeys
    ret, _, _ := ldap_search_init_page.Call(
        w.ld,
        uintptr(unsafe.Pointer(basePtr)),
        uintptr(LDAP_SCOPE_SUBTREE),
        uintptr(unsafe.Pointer(filterPtr)),
        attrsPtr,
        0, // attrsonly
        0, // serverctrls
        0, // clientctrls
        0, // pagetimelimit
        0, // totalsizelimit
        0, // sortkeys
    )

    searchHandle = ret
    if searchHandle == 0 {
        return nil, fmt.Errorf("ldap_search_init_page failed")
    }
    defer ldap_search_abandon_page.Call(w.ld, searchHandle)

    var results []string
    var totalCount uint32

    for {
        var res uintptr
        // ldap_get_next_page_s
        // Args: ld, searchHandle, timeout(NULL), pageSize, totalCount(OUT), results(OUT)
        ret, _, _ := ldap_get_next_page_s.Call(
            w.ld,
            searchHandle,
            0, // timeout
            uintptr(PAGE_SIZE),
            uintptr(unsafe.Pointer(&totalCount)),
            uintptr(unsafe.Pointer(&res)),
        )

        if ret == LDAP_NO_RESULTS_RETURNED {
            break
        }
        if ret != LDAP_SUCCESS {
            return nil, fmt.Errorf("ldap_get_next_page_s failed: %d", ret)
        }

        // Iterate results in this page
        entriesInPage := 0
        for entry, _, _ := ldap_first_entry.Call(w.ld, res); entry != 0; entry, _, _ = ldap_next_entry.Call(w.ld, entry) {
            // Get values
            valsPtr, _, _ := ldap_get_values.Call(w.ld, entry, uintptr(unsafe.Pointer(attrPtr)))
            if valsPtr != 0 {
                p := valsPtr
                for {
                    valPtr := *(*uintptr)(unsafe.Pointer(p))
                    if valPtr == 0 {
                        break
                    }
                    str := syscall.UTF16ToString((*[1 << 30]uint16)(unsafe.Pointer(valPtr))[:])

                    if attr == "servicePrincipalName" {
                        if strings.HasPrefix(str, "MSSQLSvc/") {
                            results = append(results, str)
                        }
                    } else {
                        results = append(results, str)
                    }
                    p += unsafe.Sizeof(uintptr(0))
                }
                ldap_value_free.Call(valsPtr)
            }
            entriesInPage++
        }
        ldap_msgfree.Call(res)

        if w.debug {
            fmt.Printf("[DEBUG] Page entries: %d. Total accumulated: %d\n", entriesInPage, len(results))
        }
    }

    return results, nil
}
