package main

import (
	"encoding/binary"
	"flag"
	"fmt"
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
		proxyHeader := createProxyProtocolV2Header(clientAddr.IP, clientAddr.Port, targetAddr.IP, targetAddr.Port, true)
		packet = append(proxyHeader, data...)
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
			return
		}
		return
	}

	sourceAddr := clientConn.RemoteAddr().(*net.TCPAddr)
	targetAddr := srvConn.RemoteAddr().(*net.TCPAddr)

	// Add Proxy Protocol header if the flag is not set
	if !skipProxyHeader {
		proxyHeader := createProxyProtocolV2Header(sourceAddr.IP, sourceAddr.Port, targetAddr.IP, targetAddr.Port, false)
		_, err = srvConn.Write(proxyHeader)
		if err != nil {
			fmt.Println("Error writing proxy header:", err)
		}
	}

	go func() {
		_, err := io.Copy(srvConn, clientConn)
		if err != nil {
			fmt.Println("Error forwarding TCP response to client:", err)
		}
	}()
	go func() {
		_, err := io.Copy(clientConn, srvConn)
		if err != nil {
			fmt.Println("Error forwarding TCP response to server:", err)
		}
	}()
}

func createProxyProtocolV2Header(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, isUDP bool) []byte {
	header := make([]byte, 16+4+len(srcIP)+len(dstIP))
	header[0] = 0x0D // Proxy Protocol v2 signature
	header[1] = 0x0A
	header[2] = 0x0D
	header[3] = 0x0A
	header[4] = 0x00
	header[5] = 0x0D
	header[6] = 0x0A
	header[7] = 0x51
	header[8] = 0x55
	header[9] = 0x49
	header[10] = 0x54
	header[11] = 0x0A

	// Command and address family
	header[12] = 0x21 // PROXY command, INET family
	if isUDP {
		header[13] = 0x12 // Datagram (UDP)
	} else {
		header[13] = 0x11 // Stream (TCP)
	}

	binary.BigEndian.PutUint16(header[14:], uint16(12+len(srcIP)+len(dstIP)))

	copy(header[16:], srcIP.To4())
	copy(header[20:], dstIP.To4())
	binary.BigEndian.PutUint16(header[24:], uint16(srcPort))
	binary.BigEndian.PutUint16(header[26:], uint16(dstPort))

	return header
}
