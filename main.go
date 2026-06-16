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

// VLESSInfo holds the parsed components of a VLESS line
type VLESSInfo struct {
	Prefix     string // Everything before host (e.g., "vless://uuid@")
	HostRaw    string // The host part as it appeared (e.g., "example.com" or "[2001:db8::1]")
	HostParsed string // The host part without brackets (e.g., "2001:db8::1")
	Suffix     string // Everything after host (e.g., ":443?security=tls#fragment")
	Params     url.Values
}

func parseVLESS(line string) *VLESSInfo {
	// Find vless://
	vIdx := strings.Index(line, "vless://")
	if vIdx == -1 {
		return nil
	}

	// Find the first @ after vless://
	atIdx := strings.Index(line[vIdx:], "@")
	if atIdx == -1 {
		return nil
	}
	atIdx += vIdx // Absolute index

	prefix := line[:atIdx+1]
	remainder := line[atIdx+1:]

	var hostRaw string
	var suffix string

	if strings.HasPrefix(remainder, "[") {
		// IPv6
		endBracketIdx := strings.Index(remainder, "]")
		if endBracketIdx == -1 {
			return nil // Malformed IPv6
		}
		hostRaw = remainder[:endBracketIdx+1]
		suffix = remainder[endBracketIdx+1:]
	} else {
		// Domain or IPv4
		endIdx := strings.IndexAny(remainder, ":?#")
		if endIdx == -1 {
			hostRaw = remainder
			suffix = ""
		} else {
			hostRaw = remainder[:endIdx]
			suffix = remainder[endIdx:]
		}
	}

	// Parse host for IPv6 brackets
	hostParsed := hostRaw
	if strings.HasPrefix(hostRaw, "[") && strings.HasSuffix(hostRaw, "]") {
		hostParsed = hostRaw[1 : len(hostRaw)-1]
	}

	// Parse query params for filtering
	var queryPart string
	qIdx := strings.Index(suffix, "?")
	fIdx := strings.Index(suffix, "#")
	if qIdx != -1 {
		if fIdx != -1 && fIdx > qIdx {
			queryPart = suffix[qIdx+1 : fIdx]
		} else {
			queryPart = suffix[qIdx+1:]
		}
	}
	params, _ := url.ParseQuery(queryPart)

	return &VLESSInfo{
		Prefix:     prefix,
		HostRaw:    hostRaw,
		HostParsed: strings.TrimSpace(hostParsed),
		Suffix:     suffix,
		Params:     params,
	}
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
	fastlyFlag := flag.Bool("fastly", false, "Only keep configs with Fastly IPs")
	cfFlag := flag.Bool("cf", false, "Only keep configs with Cloudflare IPs")
	gcoreFlag := flag.Bool("gcore", false, "Only keep configs with Gcore IPs")

	tlsFlag := flag.Bool("tls", false, "Only keep configs with security=tls")
	realityFlag := flag.Bool("reality", false, "Only keep configs with security=reality")

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
				info := parseVLESS(job.Line)
				if info == nil {
					resultsChan <- Result{ID: job.ID, Line: job.Line, Clean: true}
					continue
				}

				// Check security type
				if filterSecurity {
					sec := info.Params.Get("security")
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
					t := info.Params.Get("type")
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
				if val, ok := cache.Load(info.HostParsed); ok {
					ips = val.([]net.IP)
				} else {
					if ip := net.ParseIP(info.HostParsed); ip != nil {
						ips = []net.IP{ip}
					} else {
						resolved, err := net.LookupIP(info.HostParsed)
						if err == nil {
							ips = resolved
						}
					}
					cache.Store(info.HostParsed, ips)
				}

				var chosenIP string
				if len(targetRanges) == 0 {
					// No provider filtering requested, just resolve to an IP
					if len(ips) > 0 {
						chosenIP = ips[0].String()
					}
				} else {
					// INCLUSIVE FILTER: Find the first IP that IS in the target ranges
					for _, ip := range ips {
						if isInRanges(ip, targetRanges) {
							chosenIP = ip.String()
							break
						}
					}
				}

				if chosenIP != "" {
					// Reconstruct the line
					newHost := chosenIP
					if ip := net.ParseIP(chosenIP); ip != nil && ip.To4() == nil {
						newHost = "[" + chosenIP + "]"
					}

					if chosenIP == info.HostParsed {
						resultsChan <- Result{ID: job.ID, Line: job.Line, Clean: true}
					} else {
						newLine := info.Prefix + newHost + info.Suffix
						resultsChan <- Result{ID: job.ID, Line: newLine, Clean: true}
					}
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
	const maxCapacity = 2 * 1024 * 1024
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
