# vf (VLESS Filter)

`vf` is a high-performance, standalone CLI tool designed to filter and process VLESS configurations. It extracts addresses, resolves them to IPs, and filters against known provider ranges (Fastly, Cloudflare, Gcore) and protocol/security types.

## Key Features
- **Standalone Binary:** Provider IP ranges (Fastly, Cloudflare, Gcore) are baked directly into the binary.
- **Concurrent Processing:** Uses a high-speed worker pool for DNS resolution.
- **Auto-Substitution:** Automatically replaces domain names with resolved, non-filtered IPs.
- **Order Preservation:** Maintains the original sequence of configurations from input to output.
- **Protocol Filtering:** Filter by security (`tls`, `reality`) or transmission type (`tcp`, `ws`, `grpc`, etc.).

## Installation
Requires Go 1.16+ for embedding support.
```bash
go build -o vf main.go
```

## Usage
`vf` reads from `stdin` and writes to `stdout`.

### Provider Filtering
Exclude IPs belonging to specific providers:
```bash
cat vless.txt | ./vf -fastly -cf -gcore > filtered.txt
```

### Protocol & Security Filtering
Only keep specific configuration types:
```bash
# Only keep TLS configs using WebSocket
cat vless.txt | ./vf -tls -ws

# Only keep Reality configs using GRPC or xHTTP
cat vless.txt | ./vf -reality -grpc -xhttp
```

### Combined Example
```bash
cat vless.txt | ./vf -fastly -cf -tls -ws -reality > final_configs.txt
```

## Flags
| Flag | Description |
|------|-------------|
| `-fastly` | Filter out Fastly IPs |
| `-cf` | Filter out Cloudflare IPs |
| `-gcore` | Filter out Gcore IPs |
| `-tls` | Keep only `security=tls` |
| `-reality` | Keep only `security=reality` |
| `-tcp` | Keep only `type=tcp` |
| `-ws` | Keep only `type=ws` |
| `-httpupgrade` | Keep only `type=httpupgrade` |
| `-xhttp` | Keep only `type=xhttp` |
| `-grpc` | Keep only `type=grpc` |
| `-kcp` | Keep only `type=kcp` |
