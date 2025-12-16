package discovery

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type ScanResult struct {
	HostName string
	Port     int
	IsOpen   bool
}

// ScanPorts scans a list of hosts on specified ports concurrently
func ScanPorts(hosts []string, ports []int, timeoutMs int, threads int) []ScanResult {
	var results []ScanResult
	resultChan := make(chan ScanResult)
	sem := make(chan struct{}, threads) // Semaphore to limit concurrency
	var wg sync.WaitGroup

	// Start result collector
	go func() {
		for res := range resultChan {
			results = append(results, res)
		}
	}()

	for _, host := range hosts {
		for _, port := range ports {
			wg.Add(1)
			go func(h string, p int) {
				defer wg.Done()
				sem <- struct{}{} // Acquire token
				defer func() { <-sem }() // Release token

				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, p), time.Duration(timeoutMs)*time.Millisecond)
				isOpen := false
				if err == nil {
					conn.Close()
					isOpen = true
				}

				if isOpen {
					resultChan <- ScanResult{HostName: h, Port: p, IsOpen: true}
				}
			}(host, port)
		}
	}

	wg.Wait()
	close(resultChan)
	return results
}
