package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
)

//go:embed fastly.txt
var fastlyData string

//go:embed cloudflare.txt
var cloudflareData string

//go:embed gcore.txt
var gcoreData string

func loadIPRangesFromData(data string) ([]*net.IPNet, error) {
	var ranges []*net.IPNet
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			ip := net.ParseIP(line)
			if ip != nil {
				mask := net.CIDRMask(32, 32)
				if ip.To4() == nil {
					mask = net.CIDRMask(128, 128)
				}
				ranges = append(ranges, &net.IPNet{IP: ip, Mask: mask})
			}
			continue
		}
		ranges = append(ranges, ipNet)
	}
	return ranges, scanner.Err()
}

func isInRanges(ip net.IP, ipRanges []*net.IPNet) bool {
	for _, r := range ipRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

func extractAddressAndParams(line string) (string, url.Values) {
	atIdx := strings.LastIndex(line, "@")
	if atIdx == -1 {
		return "", nil
	}
	remainder := line[atIdx+1:]

	var addrPart string
	var queryPart string

	// Split by ? or #
	firstQuery := strings.Index(remainder, "?")
	firstFragment := strings.Index(remainder, "#")
	
	splitIdx := -1
	if firstQuery != -1 && (firstFragment == -1 || firstQuery < firstFragment) {
		splitIdx = firstQuery
	} else if firstFragment != -1 {
		splitIdx = firstFragment
	}

	if splitIdx != -1 {
		addrPart = remainder[:splitIdx]
		if firstQuery != -1 && (firstFragment == -1 || firstQuery < firstFragment) {
			if firstFragment != -1 {
				queryPart = remainder[firstQuery+1 : firstFragment]
			} else {
				queryPart = remainder[firstQuery+1:]
			}
		}
	} else {
		addrPart = remainder
	}

	// Extract address from host:port or [ipv6]:port
	var addr string
	if strings.HasPrefix(addrPart, "[") {
		endBracket := strings.Index(addrPart, "]")
		if endBracket != -1 {
			addr = addrPart[1:endBracket]
		}
	} else {
		colonIdx := strings.Index(addrPart, ":")
		if colonIdx != -1 {
			addr = addrPart[:colonIdx]
		} else {
			addr = addrPart
		}
	}

	params, _ := url.ParseQuery(queryPart)
	return strings.TrimSpace(addr), params
}

type Job struct {
	ID   int
	Line string
}

type Result struct {
	ID    int
	Line  string
	Clean bool
}

func main() {
	fastlyFlag := flag.Bool("fastly", false, "Filter out Fastly IPs")
	cfFlag := flag.Bool("cf", false, "Filter out Cloudflare IPs")
	gcoreFlag := flag.Bool("gcore", false, "Filter out Gcore IPs")

	// Security flags
	tlsFlag := flag.Bool("tls", false, "Only keep configs with security=tls")
	realityFlag := flag.Bool("reality", false, "Only keep configs with security=reality")

	// Transmission flags
	tcpFlag := flag.Bool("tcp", false, "Only keep configs with type=tcp")
	wsFlag := flag.Bool("ws", false, "Only keep configs with type=ws")
	huFlag := flag.Bool("httpupgrade", false, "Only keep configs with type=httpupgrade")
	xhFlag := flag.Bool("xhttp", false, "Only keep configs with type=xhttp")
	grpcFlag := flag.Bool("grpc", false, "Only keep configs with type=grpc")
	kcpFlag := flag.Bool("kcp", false, "Only keep configs with type=kcp")

	flag.Parse()

	var targetRanges []*net.IPNet
	if *fastlyFlag {
		ranges, _ := loadIPRangesFromData(fastlyData)
		targetRanges = append(targetRanges, ranges...)
	}
	if *cfFlag {
		ranges, _ := loadIPRangesFromData(cloudflareData)
		targetRanges = append(targetRanges, ranges...)
	}
	if *gcoreFlag {
		ranges, _ := loadIPRangesFromData(gcoreData)
		targetRanges = append(targetRanges, ranges...)
	}

	// Determine if we need to filter by security/transmission
	filterSecurity := *tlsFlag || *realityFlag
	filterTransmission := *tcpFlag || *wsFlag || *huFlag || *xhFlag || *grpcFlag || *kcpFlag

	numWorkers := 100
	jobsChan := make(chan Job, 1000)
	resultsChan := make(chan Result, 1000)
	var wg sync.WaitGroup
	var cache sync.Map

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobsChan {
				line := job.Line
				addr, params := extractAddressAndParams(line)
				if addr == "" {
					resultsChan <- Result{ID: job.ID, Clean: false}
					continue
				}

				// Check security type
				if filterSecurity {
					sec := params.Get("security")
					match := false
					if *tlsFlag && sec == "tls" {
						match = true
					}
					if *realityFlag && sec == "reality" {
						match = true
					}
					if !match {
						resultsChan <- Result{ID: job.ID, Clean: false}
						continue
					}
				}

				// Check transmission type
				if filterTransmission {
					t := params.Get("type")
					// Default to tcp if missing
					if t == "" {
						t = "tcp"
					}
					match := false
					if *tcpFlag && t == "tcp" {
						match = true
					}
					if *wsFlag && t == "ws" {
						match = true
					}
					if *huFlag && t == "httpupgrade" {
						match = true
					}
					if *xhFlag && t == "xhttp" {
						match = true
					}
					if *grpcFlag && t == "grpc" {
						match = true
					}
					if *kcpFlag && t == "kcp" {
						match = true
					}
					if !match {
						resultsChan <- Result{ID: job.ID, Clean: false}
						continue
					}
				}

				var ips []net.IP
				if val, ok := cache.Load(addr); ok {
					ips = val.([]net.IP)
				} else {
					if ip := net.ParseIP(addr); ip != nil {
						ips = []net.IP{ip}
					} else {
						resolved, err := net.LookupIP(addr)
						if err == nil {
							ips = resolved
						}
					}
					cache.Store(addr, ips)
				}

				var firstCleanIP string
				if len(targetRanges) == 0 {
					if len(ips) > 0 {
						firstCleanIP = ips[0].String()
					}
				} else {
					for _, ip := range ips {
						if !isInRanges(ip, targetRanges) {
							firstCleanIP = ip.String()
							break
						}
					}
				}

				if firstCleanIP != "" {
					atIdx := strings.LastIndex(line, "@")
					prefix := line[:atIdx+1]
					remainder := line[atIdx+1:]
					
					addrEndIdx := 0
					if strings.HasPrefix(remainder, "[") {
						addrEndIdx = strings.Index(remainder, "]") + 1
					} else {
						colonIdx := strings.Index(remainder, ":")
						if colonIdx != -1 {
							addrEndIdx = colonIdx
						} else {
							qIdx := strings.IndexAny(remainder, "?#")
							if qIdx != -1 {
								addrEndIdx = qIdx
							} else {
								addrEndIdx = len(remainder)
							}
						}
					}
					
					newLine := prefix + firstCleanIP + remainder[addrEndIdx:]
					resultsChan <- Result{ID: job.ID, Line: newLine, Clean: true}
				} else {
					resultsChan <- Result{ID: job.ID, Clean: false}
				}
			}
		}()
	}

	done := make(chan bool)
	go func() {
		pending := make(map[int]Result)
		nextID := 0
		for res := range resultsChan {
			pending[res.ID] = res
			for {
				if r, ok := pending[nextID]; ok {
					if r.Clean {
						fmt.Println(r.Line)
					}
					delete(pending, nextID)
					nextID++
				} else {
					break
				}
			}
		}
		done <- true
	}()

	scanner := bufio.NewScanner(os.Stdin)
	const maxCapacity = 2 * 1024 * 1024 // 2MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	id := 0
	for scanner.Scan() {
		jobsChan <- Job{ID: id, Line: scanner.Text()}
		id++
	}
	close(jobsChan)

	wg.Wait()
	close(resultsChan)
	<-done
}
