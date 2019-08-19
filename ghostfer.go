
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	iface		string
	snapshotLen	int32  = 1024
	promiscuous	bool   = true
	err		error
	timeout		time.Duration = 1 * time.Second
	handle		*pcap.Handle
	hosts		map[string]bool
)

func main() {
	fmt.Println("[+] Starting MAC Recon...")
	iface := flag.String("iface", "wlan0", "Interface use to sniffing")
	flag.Parse()
	hosts = make(map[string]bool)

	handle, err = pcap.OpenLive(*iface, snapshotLen, promiscuous, timeout)
	if err != nil {log.Fatal(err) }
	defer handle.Close()

	var filter string = "arp"
	err = handle.SetBPFFilter(filter)
	if err != nil { log.Fatal(err) }

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}

}

func printPacketInfo(packet gopacket.Packet) {
	arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
	macSrc := net.HardwareAddr(arp.SourceHwAddress)
	ipSrc := net.IP(arp.SourceProtAddress)

	buffer := bytes.Buffer{}
	buffer.WriteString(macSrc.String())
	buffer.WriteString("	")
	buffer.WriteString(ipSrc.String())
	stringCompleto := buffer.String()

	if _, ok := hosts[stringCompleto]; ok {
		return
	} else if ipSrc.String() == "0.0.0.0" {
		return
	} else{
		hosts[stringCompleto] = true
		fmt.Println(stringCompleto)
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
