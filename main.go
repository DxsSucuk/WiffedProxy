package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	proxyproto "github.com/pires/go-proxyproto"
	"io"
	"net"
	"os"
	"strings"
)

var udpTargetMap = make(map[string]string)
var tcpTargetMap = make(map[string]string)
var tcpRoutingMap = make(map[string]string)
var skipProxyHeader bool
var dontTLS bool
var dontMinecraftHandshake bool
var dontHTTPHost bool
var tcpRoutingHost int64

func main() {

	// Command-line flags for adding entries and skipping Proxy Protocol v2 header
	udpEntries := flag.String("udp", "", "Comma-separated list of UDP local:target address pairs (e.g., ':9000=127.0.0.1:8080,:9001=127.0.0.1:8081')")
	tcpEntries := flag.String("tcp", "", "Comma-separated list of TCP local:target address pairs (e.g., ':9002=127.0.0.1:8082,:9003=127.0.0.1:8083')")
	tcpRoutingEntries := flag.String("tcpRouteTarget", "", "Comma-separated list of TCP hostname:target address pairs (e.g., 'fivem.presti.me=127.0.0.1:8082,:mc.presti.me=127.0.0.1:8083')")
	flag.Int64Var(&tcpRoutingHost, "tcpRouteHost", 0, "TCP port to use for routing requests")
	flag.BoolVar(&skipProxyHeader, "no-proxy-header", false, "Skip Proxy Protocol v2 header in packet forwarding")
	flag.BoolVar(&dontTLS, "dont-tls", false, "Don't try to pass SNI from TLS request")
	flag.BoolVar(&dontMinecraftHandshake, "dont-mc", false, "Don't try to pass Hostname from Minecraft Handshake")
	flag.BoolVar(&dontHTTPHost, "dont-http", false, "Don't try to pass Hostname from HTTP request")
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

	// Check if no entries were provided and print a message
	if len(udpTargetMap) == 0 && len(tcpTargetMap) == 0 && len(tcpRoutingMap) == 0 {
		fmt.Println("No entries provided for proxying. Please provide UDP and/or TCP address mappings.")
		os.Exit(1) // Exit with an error code
	}

	if skipProxyHeader {
		fmt.Println("Skipping proxy header")
	}

	if dontTLS {
		fmt.Println("Skipping TLS SNI extraction")
	}

	if dontMinecraftHandshake {
		fmt.Println("Skipping Minecraft Handshake hostname extraction")
	}

	if dontHTTPHost {
		fmt.Println("Skipping HTTP Hostname extraction")
	}

	// Start proxies
	for localAddr := range udpTargetMap {
		go startUDPProxy(localAddr)
	}
	for localAddr := range tcpTargetMap {
		go startTCPProxy(localAddr, false)
	}

	if tcpRoutingHost > 0 {
		go startTCPProxy(fmt.Sprintf(":%d", tcpRoutingHost), true)
	}

	select {} // Keep main alive
}

// Parse command-line entry string (e.g., ":9000=127.0.0.1:8080,:9001=127.0.0.1:8081")
func parseEntries(entryString string) map[string]string {
	entryMap := make(map[string]string)
	entries := strings.Split(entryString, ",")
	for _, entry := range entries {
		parts := strings.Split(entry, "=")
		if len(parts) == 2 {
			entryMap[parts[0]] = parts[1]
		} else {
			fmt.Println("Invalid entry:", entry)
		}
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

	fmt.Println("UDP Proxy started on", localAddr, "forwarding to", udpTargetMap[localAddr])

	buffer := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from client:", err)
			continue
		}

		go handleUDPPacket(conn, buffer[:n], clientAddr, udpTargetMap[localAddr])
	}
}

func handleUDPPacket(conn *net.UDPConn, data []byte, clientAddr *net.UDPAddr, target string) {
	targetAddr, err := net.ResolveUDPAddr("udp", target)
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
	if !skipProxyHeader {
		proxyHeader := proxyproto.HeaderProxyFromAddrs(2, clientAddr, targetAddr)
		var proxyHeaderContent []byte
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
	n, _, err := srvConn.ReadFromUDP(respBuffer)
	if err != nil {
		fmt.Println("Error reading UDP response:", err)
		return
	}

	_, err = conn.WriteToUDP(respBuffer[:n], clientAddr)
	if err != nil {
		fmt.Println("Error sending UDP response to client:", err)
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

	if isRouting {
		fmt.Println("TCP Proxy started on", localAddr, "set to routing")
	} else {
		fmt.Println("TCP Proxy started on", localAddr, "forwarding to", tcpTargetMap[localAddr])
	}

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting TCP connection:", err)
			continue
		}

		if isRouting {
			go handleTCPConnection(clientConn, "", true)
		} else {
			go handleTCPConnection(clientConn, tcpTargetMap[localAddr], false)
		}
	}
}

func handleTCPConnection(clientConn net.Conn, target string, isRouting bool) {
	sourceAddr := clientConn.RemoteAddr().(*net.TCPAddr)

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
		if isRouting && !dontMinecraftHandshake && buffer[0] <= 0x7F { // Simple VarInt check
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

			if !dontHTTPHost {
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
		} else if isRouting && !dontTLS && buffer[0] == 0x16 && buffer[1] == 0x03 && buffer[2] <= 0x03 {
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
			target = newTarget
		}
	}

	srvConn, err := net.Dial("tcp", target)
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

	var hasModifiedBytes bool = false

	// Is it even smart to only send the Real-IP header once on connection?

	// Handle Proxy Protocol or X-Real-IP header
	if !skipProxyHeader {
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
