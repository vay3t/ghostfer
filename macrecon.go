
package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"time"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
    device      string = os.Args[1]
    snapshotLen int32  = 1024
    promiscuous bool   = false
    err         error
    timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	hosts 		map[string]bool
)

func main() {
	hosts = make(map[string]bool)
	
	if len(os.Args) != 2{
		usage()
	}else{
		handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
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
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <iface>\n", os.Args[0])
	os.Exit(2)
}

func printPacketInfo(packet gopacket.Packet) {
	arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
	if arp.Operation == 2 {
		macSrc := net.HardwareAddr(arp.SourceHwAddress)
		ipSrc := net.IP(arp.SourceProtAddress)
		
		buffer := bytes.Buffer{}
		buffer.WriteString(macSrc.String())
		buffer.WriteString(" - ")
		buffer.WriteString(ipSrc.String())
		stringCompleto := buffer.String()
		
		if _, ok := hosts[stringCompleto]; ok {
			fmt.Print()
		}else{
			hosts[stringCompleto] = true
			fmt.Println(stringCompleto)
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
