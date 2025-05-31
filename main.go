package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/pires/go-proxyproto"
	"gopkg.in/yaml.v2"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var udpTargetMap = make(map[string]ProxyOptions)
var tcpTargetMap = make(map[string]ProxyOptions)
var tcpRoutingMap = make(map[string]ProxyOptions)
var tcpRoutingHost int64

type Config struct {
	UDPEntries        []ProxyTarget   `yaml:"udpEntries"`
	TCPEntries        []ProxyTarget   `yaml:"tcpEntries"`
	TCPRoutingEntries []RoutingTarget `yaml:"tcpRoutingEntries"`
	TCPRoutingHost    int64           `yaml:"tcpRoutingHost"`
}

type ProxyTarget struct {
	BindAddress string       `yaml:"bindAddress"`
	Options     ProxyOptions `yaml:"options"`
}

type RoutingTarget struct {
	BindAddress string       `yaml:"hostname"`
	Options     ProxyOptions `yaml:"options"`
}

type ProxyOptions struct {
	Target             string `yaml:"target"`
	SkipProxyHeader    bool   `yaml:"skip_proxy_header"`
	TLS                bool   `yaml:"tls"`
	MinecraftHandshake bool   `yaml:"minecraft_handshake"`
	HTTPHost           bool   `yaml:"http_host"`
	LogConnections     bool   `yaml:"log_connections"`
}

func main() {

	// Command-line flags for adding entries and skipping Proxy Protocol v2 header
	udpEntries := flag.String("udp", "", "Comma-separated list of UDP local=target mappings with optional flags. Format: ':9000=127.0.0.1:8080|no-proxy-header,http,log-con'")
	tcpEntries := flag.String("tcp", "", "Comma-separated list of TCP local=target mappings with optional flags. Format: ':9001=127.0.0.1:25565|no-proxy-header,mc,log-con'")
	tcpRoutingEntries := flag.String("tcpRouteTarget", "", "Comma-separated list of TCP hostname=target mappings with optional flags. Format: 'mc.example.com=127.0.0.1:25565|mc,log-con'")
	flag.Int64Var(&tcpRoutingHost, "tcpRouteHost", 0, "TCP port to use for routing requests")
	flag.Parse()

	// Parse the UDP and TCP entries
	if *udpEntries != "" {
		udpTargetMap = parseEntries(*udpEntries)
	}
	if *tcpEntries != "" {
		tcpTargetMap = parseEntries(*tcpEntries)
	}

	if *tcpRoutingEntries != "" {
		tcpRoutingMap = parseEntries(*tcpRoutingEntries)
	}

	cfg, err := loadConfig("config.yml")
	if err != nil {
		log.Println(err)
	}

	if cfg != nil {
		if len(cfg.UDPEntries) > 0 {
			for index := range cfg.UDPEntries {
				var udpConfigEntry = cfg.UDPEntries[index]
				udpTargetMap[udpConfigEntry.BindAddress] = udpConfigEntry.Options
			}
		}

		if len(cfg.TCPEntries) > 0 {
			for index := range cfg.TCPEntries {
				var tcpConfigEntry = cfg.TCPEntries[index]
				tcpTargetMap[tcpConfigEntry.BindAddress] = tcpConfigEntry.Options
			}
		}

		if len(cfg.TCPRoutingEntries) > 0 {
			for index := range cfg.TCPRoutingEntries {
				var tcpRoutingConfigEntry = cfg.TCPRoutingEntries[index]
				tcpRoutingMap[tcpRoutingConfigEntry.BindAddress] = tcpRoutingConfigEntry.Options
			}
		}
	}

	// Check if no entries were provided and print a message
	if len(udpTargetMap) == 0 && len(tcpTargetMap) == 0 && len(tcpRoutingMap) == 0 {
		fmt.Println("No entries provided for proxying. Please provide UDP and/or TCP address mappings.")
		os.Exit(1) // Exit with an error code
	}
	// Start proxies
	for localAddr := range udpTargetMap {
		go startUDPProxy(localAddr)
	}
	for localAddr := range tcpTargetMap {
		go startTCPProxy(localAddr, false)
	}

	var routingPort int64

	if tcpRoutingHost > 0 {
		routingPort = tcpRoutingHost
	} else if cfg != nil && cfg.TCPRoutingHost > 0 {
		routingPort = cfg.TCPRoutingHost
	} else {
		routingPort = 0
	}

	if routingPort > 0 {
		go startTCPProxy(fmt.Sprintf(":%d", routingPort), true)
	}

	select {} // Keep main alive
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &cfg, nil
}

// Parse command-line entry string (e.g., ":9000=127.0.0.1:8080|no-proxy-header,mc,log-con,:9001=127.0.0.1:8081|no-proxy-header,log-con")
func parseEntries(entryString string) map[string]ProxyOptions {
	entryMap := make(map[string]ProxyOptions)
	entries := strings.Split(entryString, ",")
	for _, entry := range entries {
		parts := strings.Split(entry, "=")
		if len(parts) != 2 {
			fmt.Println("Invalid entry:", entry)
			continue
		}

		addr := parts[0]
		targetOptions := strings.Split(parts[1], "|")
		target := targetOptions[0]

		options := ProxyOptions{
			Target: target,
		}

		if len(targetOptions) > 1 {
			flags := strings.Split(targetOptions[1], ",")
			for _, flag := range flags {
				switch flag {
				case "no-proxy-header":
					options.SkipProxyHeader = true
				case "tls":
					options.TLS = true
				case "mc":
					options.MinecraftHandshake = true
				case "http":
					options.HTTPHost = true
				case "log-con":
					options.LogConnections = true
				}
			}
		}

		entryMap[addr] = options
	}
	return entryMap
}

func startUDPProxy(localAddr string) {
	proxyAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		fmt.Println("Error resolving local UDP address:", err)
		os.Exit(1)
	}

	conn, err := net.ListenUDP("udp", proxyAddr)
	if err != nil {
		fmt.Println("Error starting UDP proxy:", err)
		os.Exit(1)
	}
	defer conn.Close()

	ops := udpTargetMap[localAddr]

	fmt.Println("UDP Proxy started on", localAddr, "forwarding to", ops.Target)
	if ops.SkipProxyHeader {
		fmt.Println("Skipping proxy header")
	}

	if ops.TLS {
		fmt.Println("Using TLS SNI extraction")
	}

	if ops.MinecraftHandshake {
		fmt.Println("Using Minecraft Handshake hostname extraction")
	}

	if ops.HTTPHost {
		fmt.Println("Using HTTP Hostname extraction")
	}

	if ops.LogConnections {
		fmt.Println("Log connections")
	}

	buffer := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from client:", err)
			continue
		}

		go handleUDPPacket(conn, buffer[:n], clientAddr, ops)
	}
}

func handleUDPPacket(conn *net.UDPConn, data []byte, clientAddr *net.UDPAddr, options ProxyOptions) {
	if options.LogConnections {
		fmt.Println("Received UDP packet from (C=>S):", clientAddr.IP.String())
	}

	targetAddr, err := net.ResolveUDPAddr("udp", options.Target)
	if err != nil {
		fmt.Println("Error resolving UDP target address:", err)
		return
	}

	srvConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		fmt.Println("Error connecting to UDP server:", err)
		return
	}
	defer srvConn.Close()

	// Add Proxy Protocol header if the flag is not set
	var packet []byte
	if !options.SkipProxyHeader {
		proxyHeader := proxyproto.HeaderProxyFromAddrs(2, clientAddr, targetAddr)
		proxyHeaderContent, err := proxyHeader.Format()
		if err != nil {
			fmt.Println("Proxy Protocol V2 UDP Format error:", err)
			return
		}
		packet = append(proxyHeaderContent, data...)
	} else {
		packet = data
	}

	_, err = srvConn.Write(packet)
	if err != nil {
		fmt.Println("Error forwarding UDP packet:", err)
		return
	}

	respBuffer := make([]byte, 4096)
	for {
		srvConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := srvConn.ReadFromUDP(respBuffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			}
			//fmt.Println("Error reading UDP response:", err)
			return
		}

		_, err = conn.WriteToUDP(respBuffer[:n], clientAddr)
		if err != nil {
			fmt.Println("Error sending UDP response to client:", err)
			return
		} else {
			if options.LogConnections {
				fmt.Println("Received UDP response from (S=>C):", targetAddr.IP.String())
			}
		}
	}
}

func startTCPProxy(localAddr string, isRouting bool) {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		fmt.Println("Error starting TCP proxy:", err)
		os.Exit(1)
	}
	defer func(listener net.Listener) {
		err := listener.Close()
		if err != nil {
			fmt.Println("Error closing listener:", err)
		}
	}(listener)

	var ops *ProxyOptions

	if isRouting {
		fmt.Println("TCP Proxy started on", localAddr, "set to routing")
	} else {
		tempOps := tcpTargetMap[localAddr]
		ops = &tempOps

		fmt.Println("TCP Proxy started on", localAddr, "forwarding to", ops.Target)

		if ops.SkipProxyHeader {
			fmt.Println("Skipping proxy header")
		}

		if ops.TLS {
			fmt.Println("Using TLS SNI extraction")
		}

		if ops.MinecraftHandshake {
			fmt.Println("Using Minecraft Handshake hostname extraction")
		}

		if ops.HTTPHost {
			fmt.Println("Using HTTP Hostname extraction")
		}

		if ops.LogConnections {
			fmt.Println("Log connections")
		}
	}

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting TCP connection:", err)
			continue
		}

		if isRouting {
			go handleTCPConnection(clientConn, ops, true)
		} else {
			go handleTCPConnection(clientConn, ops, false)
		}
	}
}

func handleTCPConnection(clientConn net.Conn, options *ProxyOptions, isRouting bool) {
	sourceAddr := clientConn.RemoteAddr().(*net.TCPAddr)

	if options != nil && options.LogConnections {
		fmt.Println("Opened TCP connection from:", sourceAddr.IP.String())
	}

	// Read the first few bytes to determine if it's HTTP or Minecraft
	buffer := make([]byte, 1024)
	n, err := clientConn.Read(buffer)
	if err != nil && err != io.EOF {
		fmt.Println("Error reading from client:", err)
		err := clientConn.Close()
		if err != nil {
			return
		}

		return
	}

	var hostname string
	isHTTP := false
	isMinecraftHandshake := false
	isTLS := false
	if n > 0 {
		// Minecraft handshake packet starts with VarInt protocol version
		// followed by VarInt server address length, then the server address string
		// Also before actually parsing the handshake packet, check if routing is even active.
		if isRouting && options != nil && options.MinecraftHandshake && buffer[0] <= 0x7F { // Simple VarInt check
			// Attempt to parse Minecraft handshake
			protocolVersion, bytesRead := readVarInt(buffer)
			if bytesRead > 0 && bytesRead <= n {
				serverAddressLength, bytesRead2 := readVarInt(buffer[bytesRead:])
				if bytesRead2 > 0 && bytesRead+bytesRead2 <= n {
					serverAddressStart := bytesRead + bytesRead2
					serverAddressEnd := serverAddressStart + int(serverAddressLength)
					if serverAddressEnd <= n {
						hostname = string(buffer[serverAddressStart:serverAddressEnd])
						isMinecraftHandshake = true
						fmt.Println("Detected protocol version:", protocolVersion)
					}
				}
			}
		} else if bytes.HasPrefix(buffer, []byte("GET")) || bytes.HasPrefix(buffer, []byte("POST")) {
			isHTTP = true

			if isRouting && options != nil && options.HTTPHost {
				// Extract hostname from HTTP headers
				headers := string(buffer[:n])
				lines := strings.Split(headers, "\r\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "Host:") {
						hostname = strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
						break
					}
				}
			}
		} else if isRouting && options != nil && options.TLS && buffer[0] == 0x16 && buffer[1] == 0x03 && buffer[2] <= 0x03 {
			// Possible TLS handshake (SNI extraction)
			isTLS = true
			hostname = extractSNI(buffer[:n])
		}
	}

	if isHTTP {
		fmt.Println("HTTP connection from", sourceAddr.String())
	}

	if isMinecraftHandshake {
		fmt.Println("Minecraft handshake from", sourceAddr.String())
	}

	if isTLS {
		fmt.Println("TLS connection from", sourceAddr.String())
	}

	if isRouting && len(hostname) != 0 {
		if newTarget, ok := tcpRoutingMap[hostname]; ok {
			options = &newTarget
		}
	}

	if options == nil {
		fmt.Println("No routing options found")
		return
	}

	srvConn, err := net.Dial("tcp", options.Target)
	if err != nil {
		fmt.Println("Error connecting to TCP server:", err)
		err := clientConn.Close()
		if err != nil {
			fmt.Println("Failed to close client TCP connection:", err)
			return
		}
		return
	}

	targetAddr := srvConn.RemoteAddr().(*net.TCPAddr)

	var hasModifiedBytes = false

	// Is it even smart to only send the Real-IP header once on connection?
	// Probably not now that I think about it but meh I aim on making this more for games rather than HTTP.
	// Given FiveM uses HTTP for a lot of stuff, so I should fix this in the future?

	// Handle Proxy Protocol or X-Real-IP header
	if !options.SkipProxyHeader {
		if isHTTP {
			// Inject X-Real-IP header into the HTTP request
			clientIP := sourceAddr.IP.String()
			headers := fmt.Sprintf("X-Real-IP: %s\r\n", clientIP)

			// Find the end of the HTTP request headers
			headersEnd := bytes.Index(buffer[:n], []byte("\r\n\r\n"))
			if headersEnd != -1 {
				modifiedBuffer := append(buffer[:headersEnd], []byte("\r\n"+headers)...)
				modifiedBuffer = append(modifiedBuffer, []byte("\r\n")...)
				hasModifiedBytes = true
				_, err := srvConn.Write(modifiedBuffer)
				if err != nil {
					fmt.Println("Error sending modified Header to server:", err)
					return
				}
			}
		} else {
			// Create and send the Proxy Protocol header
			proxyHeader := proxyproto.HeaderProxyFromAddrs(2, sourceAddr, targetAddr)
			_, err = proxyHeader.WriteTo(srvConn)
			if err != nil {
				fmt.Println("Error writing proxy header:", err)
			}
		}
	}

	if !hasModifiedBytes {
		_, err = srvConn.Write(buffer[:n])
		if err != nil {
			fmt.Println("Error forwarding TCP packet to server:", err)
			return
		}
	}

	// Forward the rest of the traffic
	go func() {
		_, err := io.Copy(srvConn, clientConn)
		if err != nil {
			fmt.Println("Error forwarding TCP request to server:", err)
		}
	}()
	go func() {
		_, err := io.Copy(clientConn, srvConn)
		if err != nil {
			fmt.Println("Error forwarding TCP response to client:", err)
		}
	}()
}

// Helper function to read VarInt from Minecraft protocol
func readVarInt(data []byte) (int, int) {
	var value int
	bytesRead := 0
	for bytesRead < len(data) {
		byteValue := int(data[bytesRead])
		value |= (byteValue & 0x7F) << (7 * bytesRead)
		bytesRead++
		if (byteValue & 0x80) == 0 {
			break
		}
	}
	return value, bytesRead
}

func extractSNI(data []byte) string {
	if len(data) < 43 {
		return ""
	}

	sessionIDLength := int(data[43])
	if len(data) < 44+sessionIDLength+2 {
		return ""
	}
	offset := 44 + sessionIDLength
	extensionLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	endOffset := offset + extensionLength
	if len(data) < endOffset {
		return ""
	}

	for offset < endOffset {
		typeField := binary.BigEndian.Uint16(data[offset:])
		offset += 2
		lengthField := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2

		if typeField == 0x0000 && len(data) >= offset+lengthField {
			sniLength := int(data[offset])
			if len(data) >= offset+1+sniLength {
				return string(data[offset+1 : offset+1+sniLength])
			}
		}
		offset += lengthField
	}
	return ""
}
