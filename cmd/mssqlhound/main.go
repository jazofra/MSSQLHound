package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/SpecterOps/MSSQLHound/pkg/collector"
	"github.com/SpecterOps/MSSQLHound/pkg/converter"
	"github.com/SpecterOps/MSSQLHound/pkg/discovery"
	"github.com/SpecterOps/MSSQLHound/pkg/models"
)

func main() {
	// Flags
	serverInstance := flag.String("server", "", "Target MSSQL Server (host:port or host\\instance)")
    username := flag.String("username", "", "SQL Username")
    password := flag.String("password", "", "SQL Password")
    authType := flag.String("auth", "", "Authentication type: 'SQL' or 'Windows'. Defaults to Windows if no username provided.")
	checkAllComputers := flag.Bool("check-all", false, "Scan all computers in AD for MSSQL")
    threads := flag.Int("threads", 10, "Number of concurrent threads for processing")
    portThreads := flag.Int("port-scan-threads", 100, "Threads for port scanning")
    domain := flag.String("domain", "", "Domain name")
    dc := flag.String("dc", "", "Domain Controller")
	flag.Parse()

    // Determine Auth Type
    finalAuthType := "Windows"
    if *username != "" {
        finalAuthType = "SQL"
    }
    if *authType != "" {
        finalAuthType = *authType
    }

	log.Printf("Starting MSSQLHound (Go Port)... Auth Mode: %s", finalAuthType)

	var targets []string

    // 1. Target Discovery
	if *serverInstance != "" {
		targets = append(targets, *serverInstance)
	} else {
        // LDAP Discovery
        targetDomain := *domain
        targetDC := *dc

        // Auto-discover domain
        if targetDomain == "" {
            targetDomain = os.Getenv("USERDNSDOMAIN")
            if targetDomain == "" {
                 // Try parsing from USERDOMAIN or hostname?
                 // USERDNSDOMAIN is standard on Windows AD joined machines.
            }
        }

        // Auto-discover DC
        if targetDC == "" && targetDomain != "" {
            _, addrs, err := net.LookupSRV("ldap", "tcp", targetDomain)
            if err == nil && len(addrs) > 0 {
                targetDC = addrs[0].Target
                // Strip trailing dot
                targetDC = strings.TrimSuffix(targetDC, ".")
            }
        }

        if targetDomain != "" && targetDC != "" {
            log.Printf("Auto-discovered environment: Domain=%s, DC=%s", targetDomain, targetDC)

            // Pass explicit credentials if provided, otherwise empty strings trigger auto-auth attempt (SSPI/Anonymous)
            session, err := discovery.NewLDAPSession(targetDC, targetDomain, *username, *password, false)
            if err != nil {
                 log.Printf("LDAP connection failed (skipping AD enum): %v", err)
            } else {
            defer session.Close()
            spns, err := session.FindMSSQLSPNs()
            if err == nil {
                log.Printf("Found %d MSSQL SPNs", len(spns))
                 // Parse SPNs to targets (MSSQLSvc/host:port)
                 for _, spn := range spns {
                     // SPN format: MSSQLSvc/host:port or MSSQLSvc/host
                     trimmed := strings.TrimPrefix(spn, "MSSQLSvc/")
                     // Append as is, parseTarget handles both formats
                     targets = append(targets, trimmed)
                 }
            }

            if *checkAllComputers {
                computers, err := session.FindComputers()
                if err == nil {
                    log.Printf("Found %d computers. Scanning ports...", len(computers))
                    scanResults := discovery.ScanPorts(computers, []int{1433}, 500, *portThreads)
                     for _, res := range scanResults {
                         if res.IsOpen {
                             targets = append(targets, fmt.Sprintf("%s:%d", res.HostName, res.Port))
                         }
                     }
                }
            }
        } // end if targetDomain...
        }
	}

    // De-dupe targets
    uniqueTargets := make(map[string]bool)
    var jobQueue []string
    for _, t := range targets {
        if !uniqueTargets[t] {
            uniqueTargets[t] = true
            jobQueue = append(jobQueue, t)
        }
    }

    log.Printf("Processing %d unique targets...", len(jobQueue))

	// 2. Collection & Processing (Worker Pool)
    resultsChan := make(chan *models.MSSQLServerInfo, len(jobQueue))

    // Create a jobs channel
    jobs := make(chan string, len(jobQueue))
    for _, j := range jobQueue {
        jobs <- j
    }
    close(jobs)

    // Start workers
    for w := 0; w < *threads; w++ {
        go func() {
            for tgt := range jobs {
                host, port, instance := parseTarget(tgt)
                // Use default domain if none provided, or discovered one
                dom := *domain
                if dom == "" {
                     dom = os.Getenv("USERDOMAIN")
                }

                col := collector.NewMSSQLCollector(host, port, instance, *username, *password, dom, finalAuthType)
                info, err := col.Collect(context.Background())
                if err != nil {
                    log.Printf("Failed to collect from %s: %v", tgt, err)
                    resultsChan <- nil
                } else {
                    resultsChan <- info
                    log.Printf("Successfully collected from %s", tgt)
                }
            }
        }()
    }

	// 3. Conversion & Output
    // We collect all results then convert, or stream convert?
    // Streaming is better for memory.

    // Create Zip File
    outFile, err := os.Create(fmt.Sprintf("mssqlhound_%d.zip", time.Now().Unix()))
    if err != nil {
        log.Fatal(err)
    }
    defer outFile.Close()

    zipWriter := zip.NewWriter(outFile)
    defer zipWriter.Close()

    // Process results as they come in
    conv := converter.NewConverter()

    processed := 0
    for i := 0; i < len(jobQueue); i++ {
        info := <-resultsChan
        if info != nil {
            conv.Convert(info)
            processed++
        }
    }

    // Write JSON to Zip
    f, err := zipWriter.Create("mssql_bloodhound.json")
    if err != nil {
        log.Fatal(err)
    }

    enc := json.NewEncoder(f)
    enc.SetIndent("", "  ")
    if err := enc.Encode(conv.Output); err != nil {
        log.Fatal(err)
    }

    log.Printf("Finished. Processed %d servers.", processed)
}

func parseTarget(target string) (string, int, string) {
    // Basic parser: host:port or host\instance
    if strings.Contains(target, "\\") {
        parts := strings.Split(target, "\\")
        return parts[0], 0, parts[1]
    }
    if strings.Contains(target, ":") {
         parts := strings.Split(target, ":")
         // convert port
         var p int
         fmt.Sscanf(parts[1], "%d", &p)
         return parts[0], p, ""
    }
    return target, 1433, ""
}
