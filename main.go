package main

import (
	"bytes"
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
var skipProxyHeader bool

func main() {
	// Command-line flags for adding entries and skipping Proxy Protocol v2 header
	udpEntries := flag.String("udp", "", "Comma-separated list of UDP local:target address pairs (e.g., ':9000=127.0.0.1:8080,:9001=127.0.0.1:8081')")
	tcpEntries := flag.String("tcp", "", "Comma-separated list of TCP local:target address pairs (e.g., ':9002=127.0.0.1:8082,:9003=127.0.0.1:8083')")
	flag.BoolVar(&skipProxyHeader, "no-proxy-header", false, "Skip Proxy Protocol v2 header in packet forwarding")
	flag.Parse()

	// Parse the UDP and TCP entries
	if *udpEntries != "" {
		udpTargetMap = parseEntries(*udpEntries)
	}
	if *tcpEntries != "" {
		tcpTargetMap = parseEntries(*tcpEntries)
	}

	// Check if no entries were provided and print a message
	if len(udpTargetMap) == 0 && len(tcpTargetMap) == 0 {
		fmt.Println("No entries provided for proxying. Please provide UDP and/or TCP address mappings.")
		os.Exit(1) // Exit with an error code
	}

	// Start proxies
	for localAddr := range udpTargetMap {
		go startUDPProxy(localAddr)
	}
	for localAddr := range tcpTargetMap {
		go startTCPProxy(localAddr)
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

func startTCPProxy(localAddr string) {
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

	fmt.Println("TCP Proxy started on", localAddr, "forwarding to", tcpTargetMap[localAddr])

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting TCP connection:", err)
			continue
		}

		go handleTCPConnection(clientConn, tcpTargetMap[localAddr])
	}
}

func handleTCPConnection(clientConn net.Conn, target string) {
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

	sourceAddr := clientConn.RemoteAddr().(*net.TCPAddr)
	targetAddr := srvConn.RemoteAddr().(*net.TCPAddr)

	// Read the first few bytes to determine if it's HTTP
	buffer := make([]byte, 1024)
	n, err := clientConn.Read(buffer)
	if err != nil && err != io.EOF {
		fmt.Println("Error reading from client:", err)
		err := clientConn.Close()
		if err != nil {
			// Maybe dont return? Otherwise server connection will stay online?
			return
		}

		err = srvConn.Close()
		if err != nil {
			return
		}
		return
	}

	// Check if the data looks like an HTTP request
	isHTTP := false
	if n > 0 && (bytes.HasPrefix(buffer, []byte("GET")) || bytes.HasPrefix(buffer, []byte("POST"))) {
		isHTTP = true
	}

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
				_, err := srvConn.Write(modifiedBuffer)
				if err != nil {
					fmt.Println("Error sending modified Header to server:", err)
					return
				}
			} else {
				_, err := srvConn.Write(buffer[:n])
				if err != nil {
					fmt.Println("Error sending unmodified content to server:", err)
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
			_, err = srvConn.Write(buffer[:n])
			if err != nil {
				fmt.Println("Error forwarding TCP packet to server:", err)
				return
			}
		}
	} else {
		// Directly forward the buffer content
		_, err := srvConn.Write(buffer[:n])
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
