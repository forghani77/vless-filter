package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
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

//go:embed ir_ipv4.txt
var irIPv4Data string

//go:embed ru_ipv4.txt
var ruIPv4Data string

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

// ProxyInfo holds unified components for both VLESS and VMess
type ProxyInfo struct {
	Protocol string // "vless" or "vmess"
	Host     string // Parsed host (no brackets)
	RawLine  string // Original line
	Params   url.Values
	VMess    *VMessConfig // Only for vmess
	VLESS    *VLESSInfo   // Only for vless
	URL      *url.URL     // Parsed URL for ss/trojan
	SSEncoded bool        // True when ss:// line was base64-encoded
}

type VLESSInfo struct {
	Prefix string
	Suffix string
}

type VMessConfig struct {
	V    string      `json:"v"`
	Ps   string      `json:"ps"`
	Add  string      `json:"add"`
	Port interface{} `json:"port"` // Can be string or int
	Id   string      `json:"id"`
	Aid  interface{} `json:"aid"`
	Scy  string      `json:"scy"`
	Net  string      `json:"net"`
	Type string      `json:"type"`
	Host string      `json:"host"`
	Path string      `json:"path"`
	Tls  string      `json:"tls"`
	Sni  string      `json:"sni"`
}

func parseLine(line string) *ProxyInfo {
	trimmed := strings.TrimSpace(strings.ReplaceAll(line, "&amp;", "&"))
	if strings.HasPrefix(trimmed, "vless://") {
		return parseVLESS(trimmed)
	}
	if strings.HasPrefix(trimmed, "vmess://") {
		return parseVMess(trimmed)
	}
	if strings.HasPrefix(trimmed, "ss://") {
		return parseSS(trimmed)
	}
	if strings.HasPrefix(trimmed, "trojan://") {
		return parseTrojan(trimmed)
	}
	return nil
}

func parseVLESS(line string) *ProxyInfo {
	vIdx := strings.Index(line, "vless://")
	atIdx := strings.Index(line[vIdx:], "@")
	if atIdx == -1 {
		return nil
	}
	atIdx += vIdx

	prefix := line[:atIdx+1]
	remainder := line[atIdx+1:]

	var hostRaw, hostParsed, suffix string
	if strings.HasPrefix(remainder, "[") {
		endBracketIdx := strings.Index(remainder, "]")
		if endBracketIdx == -1 {
			return nil
		}
		hostRaw = remainder[:endBracketIdx+1]
		suffix = remainder[endBracketIdx+1:]
	} else {
		endIdx := strings.IndexAny(remainder, ":?#")
		if endIdx == -1 {
			hostRaw = remainder
			suffix = ""
		} else {
			hostRaw = remainder[:endIdx]
			suffix = remainder[endIdx:]
		}
	}

	hostParsed = hostRaw
	if strings.HasPrefix(hostRaw, "[") && strings.HasSuffix(hostRaw, "]") {
		hostParsed = hostRaw[1 : len(hostRaw)-1]
	}

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

	return &ProxyInfo{
		Protocol: "vless",
		Host:     strings.TrimSpace(hostParsed),
		RawLine:  line,
		Params:   params,
		VLESS: &VLESSInfo{
			Prefix: prefix,
			Suffix: suffix,
		},
	}
}

func parseVMess(line string) *ProxyInfo {
	data := strings.TrimPrefix(line, "vmess://")
	// Fix padding if needed
	if i := len(data) % 4; i != 0 {
		data += strings.Repeat("=", 4-i)
	}
	
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}

	var cfg VMessConfig
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return nil
	}

	params := url.Values{}
	params.Set("security", cfg.Tls)
	if cfg.Tls == "" && cfg.Scy != "" {
		params.Set("security", cfg.Scy)
	}
	params.Set("type", cfg.Net)

	return &ProxyInfo{
		Protocol: "vmess",
		Host:     strings.TrimSpace(cfg.Add),
		RawLine:  line,
		Params:   params,
		VMess:    &cfg,
	}
}

func parseSS(line string) *ProxyInfo {
	body := strings.TrimPrefix(line, "ss://")
	mainPart := body
	suffix := ""
	if cut := strings.IndexAny(body, "?#"); cut != -1 {
		mainPart = body[:cut]
		suffix = body[cut:]
	}

	encoded := false
	decoded := mainPart
	if !strings.Contains(mainPart, "@") {
		decodedBytes, err := base64.StdEncoding.DecodeString(padBase64(mainPart))
		if err != nil {
			decodedBytes, err = base64.RawStdEncoding.DecodeString(mainPart)
			if err != nil {
				decodedBytes, err = base64.RawURLEncoding.DecodeString(mainPart)
				if err != nil {
					return nil
				}
			}
		}
		decoded = string(decodedBytes)
		encoded = true
	}

	u, err := url.Parse("ss://" + decoded)
	if err != nil {
		return nil
	}
	if suffix != "" {
		if qIdx := strings.Index(suffix, "?"); qIdx != -1 {
			rawQuery := suffix[qIdx+1:]
			fragment := ""
			if hashIdx := strings.Index(rawQuery, "#"); hashIdx != -1 {
				fragment = rawQuery[hashIdx+1:]
				rawQuery = rawQuery[:hashIdx]
			}
			u.RawQuery = rawQuery
			u.Fragment = fragment
		} else if strings.HasPrefix(suffix, "#") {
			u.Fragment = suffix[1:]
		}
	}

	return &ProxyInfo{
		Protocol:  "ss",
		Host:      strings.TrimSpace(u.Hostname()),
		RawLine:   line,
		Params:    u.Query(),
		URL:       u,
		SSEncoded: encoded,
	}
}

func parseTrojan(line string) *ProxyInfo {
	u, err := url.Parse(line)
	if err != nil {
		return nil
	}

	return &ProxyInfo{
		Protocol: "trojan",
		Host:     strings.TrimSpace(u.Hostname()),
		RawLine:  line,
		Params:   u.Query(),
		URL:      u,
	}
}

func padBase64(s string) string {
	if i := len(s) % 4; i != 0 {
		s += strings.Repeat("=", 4-i)
	}
	return s
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

func loadAllowedRanges(data string) ([]*net.IPNet, error) {
	var ranges []*net.IPNet
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
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

func isAllowedIP(ip net.IP, includeRanges, excludeRanges []*net.IPNet) bool {
	if len(includeRanges) > 0 && !isInRanges(ip, includeRanges) {
		return false
	}
	if len(excludeRanges) > 0 && isInRanges(ip, excludeRanges) {
		return false
	}
	return true
}

func main() {
	fastlyFlag := flag.Bool("fastly", false, "Only keep configs with Fastly IPs")
	cfFlag := flag.Bool("cf", false, "Only keep configs with Cloudflare IPs")
	gcoreFlag := flag.Bool("gcore", false, "Only keep configs with Gcore IPs")
	nonFastlyFlag := flag.Bool("non-fastly", false, "Exclude configs with Fastly IPs")
	nonCFFlag := flag.Bool("non-cf", false, "Exclude configs with Cloudflare IPs")
	nonGcoreFlag := flag.Bool("non-gcore", false, "Exclude configs with Gcore IPs")
	nonIRFlag := flag.Bool("non-ir", false, "Exclude configs with Iranian IPs")
	nonRUFlag := flag.Bool("non-ru", false, "Exclude configs with Russian IPs")

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

	var excludeRanges []*net.IPNet
	if *nonFastlyFlag {
		ranges, _ := loadIPRangesFromData(fastlyData)
		excludeRanges = append(excludeRanges, ranges...)
	}
	if *nonCFFlag {
		ranges, _ := loadIPRangesFromData(cloudflareData)
		excludeRanges = append(excludeRanges, ranges...)
	}
	if *nonGcoreFlag {
		ranges, _ := loadIPRangesFromData(gcoreData)
		excludeRanges = append(excludeRanges, ranges...)
	}
	if *nonIRFlag {
		ranges, _ := loadAllowedRanges(irIPv4Data)
		excludeRanges = append(excludeRanges, ranges...)
	}
	if *nonRUFlag {
		ranges, _ := loadAllowedRanges(ruIPv4Data)
		excludeRanges = append(excludeRanges, ranges...)
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
				info := parseLine(job.Line)
				if info == nil {
					resultsChan <- Result{ID: job.ID, Line: job.Line, Clean: true}
					continue
				}

				// Check security type
				if filterSecurity {
					sec := info.Params.Get("security")
					match := false
					if *tlsFlag && (sec == "tls" || (info.Protocol == "vmess" && info.VMess.Tls == "tls")) {
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
					if *tcpFlag && t == "tcp" { match = true }
					if *wsFlag && t == "ws" { match = true }
					if *huFlag && t == "httpupgrade" { match = true }
					if *xhFlag && t == "xhttp" { match = true }
					if *grpcFlag && t == "grpc" { match = true }
					if *kcpFlag && t == "kcp" { match = true }
					if !match {
						resultsChan <- Result{ID: job.ID, Clean: false}
						continue
					}
				}

				var ips []net.IP
				if val, ok := cache.Load(info.Host); ok {
					ips = val.([]net.IP)
				} else {
					if ip := net.ParseIP(info.Host); ip != nil {
						ips = []net.IP{ip}
					} else {
						resolved, err := net.LookupIP(info.Host)
						if err == nil {
							ips = resolved
						}
					}
					cache.Store(info.Host, ips)
				}

				var chosenIP string
				if len(ips) > 0 {
					if len(targetRanges) == 0 && len(excludeRanges) == 0 {
						chosenIP = ips[0].String()
					} else {
						for _, ip := range ips {
							if isAllowedIP(ip, targetRanges, excludeRanges) {
								chosenIP = ip.String()
								break
							}
						}
					}
				}

				if chosenIP != "" {
					if chosenIP == info.Host {
						resultsChan <- Result{ID: job.ID, Line: job.Line, Clean: true}
					} else {
						// Reconstruct
						if info.Protocol == "vless" {
							newHost := chosenIP
							if ip := net.ParseIP(chosenIP); ip != nil && ip.To4() == nil {
								newHost = "[" + chosenIP + "]"
							}
							newLine := info.VLESS.Prefix + newHost + info.VLESS.Suffix
							resultsChan <- Result{ID: job.ID, Line: newLine, Clean: true}
						} else if info.Protocol == "vmess" {
							info.VMess.Add = chosenIP
							newJson, _ := json.Marshal(info.VMess)
							newLine := "vmess://" + base64.StdEncoding.EncodeToString(newJson)
							resultsChan <- Result{ID: job.ID, Line: newLine, Clean: true}
						} else if info.Protocol == "ss" || info.Protocol == "trojan" {
							u := *info.URL
							if port := u.Port(); port != "" {
								u.Host = net.JoinHostPort(chosenIP, port)
							} else {
								u.Host = chosenIP
							}
							if info.Protocol == "ss" && info.SSEncoded {
								decoded := strings.TrimPrefix(u.String(), "ss://")
								newLine := "ss://" + base64.StdEncoding.EncodeToString([]byte(decoded))
								resultsChan <- Result{ID: job.ID, Line: newLine, Clean: true}
							} else {
								resultsChan <- Result{ID: job.ID, Line: u.String(), Clean: true}
							}
						}
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
	normalizer := strings.NewReplacer("<br/>", "\n", "<br />", "\n", "<br>", "\n")
	for scanner.Scan() {
		for _, line := range strings.Split(normalizer.Replace(scanner.Text()), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			jobsChan <- Job{ID: id, Line: line}
			id++
		}
	}
	close(jobsChan)

	wg.Wait()
	close(resultsChan)
	<-done
}
