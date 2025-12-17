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
	ldap_msgfree   = wldap32.NewProc("ldap_msgfree")
	ldap_unbind    = wldap32.NewProc("ldap_unbind")
    ldap_first_entry = wldap32.NewProc("ldap_first_entry")
    ldap_next_entry  = wldap32.NewProc("ldap_next_entry")
    ldap_get_values  = wldap32.NewProc("ldap_get_valuesW")
    ldap_value_free  = wldap32.NewProc("ldap_value_freeW")
    ldap_create_page_control = wldap32.NewProc("ldap_create_page_controlW")
    ldap_parse_result = wldap32.NewProc("ldap_parse_resultW")
    ldap_parse_page_control = wldap32.NewProc("ldap_parse_page_controlW")
    ldap_control_free = wldap32.NewProc("ldap_control_freeW")
    ldap_controls_free = wldap32.NewProc("ldap_controls_freeW")
    ldap_set_option    = wldap32.NewProc("ldap_set_optionW")
    ber_bvfree = wldap32.NewProc("ber_bvfree")
)

const (
	LDAP_AUTH_NEGOTIATE = 0x486
	LDAP_SCOPE_SUBTREE  = 2
	LDAP_SUCCESS        = 0
    LDAP_PORT           = 389
    LDAP_CONTROL_PAGED_RESULTS = "1.2.840.113556.1.4.319"
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

    // Paging loop
    var results []string
    var cookie uintptr = 0 // Initially NULL

    for {
        if w.debug {
            fmt.Printf("[DEBUG] Starting Loop. Cookie: %x\n", cookie)
        }

        var pageControl uintptr
        // ldap_create_page_controlW
        // args: ld, pageSize, cookie, isCritical, outputControl
        ret, _, _ := ldap_create_page_control.Call(
            w.ld,
            uintptr(PAGE_SIZE),
            cookie,
            1, // IsCritical=1 (Force server to fail if paging not supported)
            uintptr(unsafe.Pointer(&pageControl)),
        )
        if ret != LDAP_SUCCESS {
            return nil, fmt.Errorf("ldap_create_page_control failed: %d", ret)
        }

        if w.debug {
            fmt.Printf("[DEBUG] Page control created. Ptr: %x\n", pageControl)
        }

        // Setup Server Controls Array
        // wldap32 expects a NULL-terminated array of PLDAPControl (which are pointers to LDAPControl structs)
        // pageControl IS the PLDAPControl (uintptr)
        var serverControls []uintptr
        serverControls = append(serverControls, pageControl)
        serverControls = append(serverControls, 0)
        serverControlsPtr := uintptr(unsafe.Pointer(&serverControls[0]))

        var res uintptr

        // ldap_search_ext_sW
        // args: ld, base, scope, filter, attrs, attrsonly, serverctrls, clientctrls, timeout, sizeLimit, res
        ret, _, _ = ldap_search_ext_s.Call(
            w.ld,
            uintptr(unsafe.Pointer(basePtr)),
            uintptr(LDAP_SCOPE_SUBTREE),
            uintptr(unsafe.Pointer(filterPtr)),
            attrsPtr,
            0,
            serverControlsPtr,
            0, // client controls
            0, // timeout
            0, // sizelimit
            uintptr(unsafe.Pointer(&res)),
        )

        if ret != LDAP_SUCCESS {
            ldap_control_free.Call(pageControl)
            return nil, fmt.Errorf("ldap_search_ext_s failed: %d. Check if server supports Paged Results.", ret)
        }

        // Process results
        entriesInPage := 0
        // Iterate results
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

        if w.debug {
            fmt.Printf("[DEBUG] Page entries: %d. Total accumulated: %d\n", entriesInPage, len(results))
        }

        // Get paging cookie from response
        // ldap_parse_resultW
        // args: ld, res, errCode, matchedDN, errMsg, referrals, serverControls, freeIt
        var responseControlsPtr uintptr
        ret, _, _ = ldap_parse_result.Call(
            w.ld,
            res,
            0, // errCode
            0, // matchedDN
            0, // errMsg
            0, // referrals
            uintptr(unsafe.Pointer(&responseControlsPtr)),
            0, // freeIt (we free res later)
        )

        if ret != LDAP_SUCCESS {
             ldap_msgfree.Call(res)
             ldap_control_free.Call(pageControl)
             break
        }

        // ldap_parse_page_controlW
        // args: ld, serverControls, totalCount, cookie
        var totalCount uint32
        var nextCookie uintptr // BERVAL*

        ret, _, _ = ldap_parse_page_control.Call(
            w.ld,
            responseControlsPtr,
            uintptr(unsafe.Pointer(&totalCount)),
            uintptr(unsafe.Pointer(&nextCookie)),
        )

        // Clean up
        ldap_control_free.Call(pageControl)
        if responseControlsPtr != 0 {
             ldap_controls_free.Call(responseControlsPtr)
        }
        ldap_msgfree.Call(res)

        if ret != LDAP_SUCCESS {
            break // Error or end
        }

        // Check if cookie is empty
        // BERVAL struct: len (ULONG), val (char*)
        // If val is NULL or len is 0
        if nextCookie == 0 {
            break
        }

        // Check content of cookie (berval)
        // struct berval { ULONG bv_len; PCHAR bv_val; }
        // ULONG is 32-bit. PCHAR is 64-bit on x64.
        // Alignment of PCHAR is 8 bytes.
        // Struct size: 4 (len) + 4 (padding) + 8 (ptr) = 16 bytes.

        bvLen := *(*uint32)(unsafe.Pointer(nextCookie))

        if w.debug {
            fmt.Printf("[DEBUG] Next Cookie Len: %d. Ptr: %x\n", bvLen, nextCookie)
        }

        if bvLen == 0 {
             ber_bvfree.Call(nextCookie)
             break
        }

        // Update cookie for next iteration
        if cookie != 0 {
             ber_bvfree.Call(cookie)
        }
        cookie = nextCookie
    }

    if cookie != 0 {
        ber_bvfree.Call(cookie)
    }

    return results, nil
}
