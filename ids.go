package main

import (
    "bufio"
    "fmt"
    "log"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

// Constants for thresholds and time windows in port scan detection.
const (
    PortScanThreshold = 100
    PortScanTimeWindow = 5 * time.Minute
    AnalyseBlacklistTraffic = false
)

// PortScanDetector detects port scanning activities.
type PortScanDetector struct {
    ipPortAttempts map[string]map[uint16]time.Time
    threshold      int
    blacklist      map[string]struct{}
    mutex          sync.Mutex
}

// NewPortScanDetector creates a new instance of PortScanDetector
func NewPortScanDetector() *PortScanDetector {
    return &PortScanDetector{
        ipPortAttempts: make(map[string]map[uint16]time.Time),
        threshold:      PortScanThreshold,
        blacklist:      make(map[string]struct{}),
    }
}

// SignatureDetector detects predefined patterns in packet payloads.
type SignatureDetector struct {
    signatures map[string]*regexp.Regexp
}

// NewSignatureDetector creates a new instance of SignatureDetector.
func NewSignatureDetector() *SignatureDetector {
    return &SignatureDetector{
        signatures: make(map[string]*regexp.Regexp),
    }
}

// AddSignature adds a new signature to the SignatureDetector
func (sd *SignatureDetector) AddSignature(name, pattern string) error {
    re, err := regexp.Compile(pattern)
    if err != nil {
        return err
    }
    sd.signatures[name] = re
    return nil
}

// Detecter checks if a given packet is part of a port scanning activity.
func (d *PortScanDetector) Detecter(packet gopacket.Packet) {
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer == nil {
        return
    }

    tcp, _ := tcpLayer.(*layers.TCP)

    // Check if the TCP packet is a SYN packet without an ACK.
    if !(tcp.SYN && !tcp.ACK) {
        return
    }

    // Check if the packet has an IPv4 layer, return immediately if it doesn't.
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer == nil {
        return
    }

    ip, _ := ipLayer.(*layers.IPv4)

    srcIP := ip.SrcIP.String()
    srcPort := uint16(tcp.SrcPort)

    d.mutex.Lock()
    defer d.mutex.Unlock()

    // If it's the first time seeing this source IP, initialize a map for it.
    if _, exists := d.ipPortAttempts[srcIP]; !exists {
        d.ipPortAttempts[srcIP] = make(map[uint16]time.Time)
    }

    d.ipPortAttempts[srcIP][srcPort] = time.Now()

    // Clean up port access attempts that are older than the defined time window.
    d.cleanUpOldAttempts(srcIP)

    if len(d.ipPortAttempts[srcIP]) > PortScanThreshold {
        d.handlePortScanDetection(srcIP)
    }
}


// cleanUpOldAttempts removes old port scanning attempts that are outside the time window.
func (d *PortScanDetector) cleanUpOldAttempts(srcIP string) {
    currentTime := time.Now()
    ports := d.ipPortAttempts[srcIP]
    for port, timestamp := range ports {
        if currentTime.Sub(timestamp) > PortScanTimeWindow {
            delete(ports, port)
        }
    }
    if len(ports) == 0 {
        delete(d.ipPortAttempts, srcIP)
    }
}

// handlePortScanDetection handles the detection of a port scan from a specific IP.
func (d *PortScanDetector) handlePortScanDetection(srcIP string) {
    d.mutex.Lock()
    defer d.mutex.Unlock()

    if _, exists := d.blacklist[srcIP]; !exists {
        fmt.Printf("Alert! Port scan detected from IP: %s\n", srcIP)
        d.blacklist[srcIP] = struct{}{}
        err := saveBlacklist(d.blacklist, "blacklist.txt")
        if err != nil {
            log.Printf("Error saving blacklist: %v", err)
        }
    }
}

// Detect checks if a given packet matches any of the predefined signatures.
func (sd *SignatureDetector) Detect(packet gopacket.Packet) {
    if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
        tcp, _ := tcpLayer.(*layers.TCP)
        payload := tcp.LayerPayload()

        // Check each payload against known signatures.
        for name, re := range sd.signatures {
            if re.Match(payload) {
                fmt.Printf("Signature detected: %s\n", name)
            }
        }
    }
}

// IsBlacklisted checks if an IP is in the blacklist.
func (d *PortScanDetector) IsBlacklisted(ip string) bool {
    d.mutex.Lock()
    defer d.mutex.Unlock()
    _, blacklisted := d.blacklist[ip]
    return blacklisted
}


// saveBlacklist saves the current blacklist to a file.
func saveBlacklist(blacklist map[string]struct{}, filename string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    // Write each blacklisted IP to the file.
    for ip := range blacklist {
        _, err := file.WriteString(ip + "\n")
        if err != nil {
            return err
        }
    }

    return nil
}

// readFileLineByLine reads a file line by line and processes each line with a given handler.
func readFileLineByLine(filename string, handleLine func(string) error) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        if err := handleLine(scanner.Text()); err != nil {
            return err
        }
    }

    return scanner.Err()
}

// LoadSignaturesFromFile loads signatures from a file into the SignatureDetector.
func (sd *SignatureDetector) LoadSignaturesFromFile(filename string) error {
    return readFileLineByLine(filename, func(line string) error {
        parts := strings.SplitN(line, ":", 2)
        if len(parts) != 2 {
            return fmt.Errorf("malformed signature line: %s", line)
        }
        if _, err := regexp.Compile(parts[1]); err != nil {
            return fmt.Errorf("invalid regexp in signature '%s': %v", parts[0], err)
        }
        return sd.AddSignature(parts[0], parts[1])
    })
}

// LoadBlacklistFromFile loads a blacklist from a file into the PortScanDetector.
func (d *PortScanDetector) LoadBlacklistFromFile(filename string) error {
    return readFileLineByLine(filename, func(line string) error {
        d.mutex.Lock()
        defer d.mutex.Unlock()
        d.blacklist[line] = struct{}{}
        return nil
    })
}


// Main execution function.
func main() {
    // Initialize the port scan detector.
    detector := NewPortScanDetector()

    // Load a list of blacklisted IPs from a file.
    err := detector.LoadBlacklistFromFile("blacklist.txt")
    if err != nil {
        log.Fatalf("Error loading blacklist: %v", err)
    }

    // Initialize the signature detector and load attack signatures.
    signatureDetector := NewSignatureDetector()
    
    err = signatureDetector.LoadSignaturesFromFile("signatures.txt")
    if err != nil {
        log.Fatalf("Error loading signatures: %v", err)
    }

    // Open a network interface for packet capture.
    handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    if err := handle.SetBPFFilter("tcp"); err != nil {
        log.Fatal(err)
    }

    // Create a source of packets from the network interface.
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    for packet := range packetSource.Packets() {
        ipLayer := packet.Layer(layers.LayerTypeIPv4)
        if ipLayer == nil {
            continue
        }
    
        ip, _ := ipLayer.(*layers.IPv4)
        srcIP := ip.SrcIP.String()
    
        // Check if the source IP of the packet is on the blacklist.
        if detector.IsBlacklisted(srcIP) {
            if !AnalyseBlacklistTraffic {
                fmt.Printf("Traffic from blacklisted IP %s ignored\n", srcIP)
                continue
            }
        }
    
        // Perform detection of port scans and analyze for known attack signatures.
        detector.Detecter(packet)
        signatureDetector.Detect(packet)
    }
}
