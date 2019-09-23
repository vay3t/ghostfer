# ghostfer
Passive hosts enumeration written in golang.

# What is?
Sniffer that captures arp packets and delivers an output with the respective ip and mac address

# Why ghostfer?
It is made in a compiled language by what makes it more optimal, portable and lightweight, the only dependence you need for run it is libpcap.

# Usage
Need root

```bash
./ghostfer -i eth0
```

# Help
```bash
Usage: ./ghostfer [-i interface | -p pcapfile]

  -h	Show this help
  -i string
    	Interface use to sniffing
  -p string
    	Read PCAP file
```

# Install
```bash
sudo pacman -S libpcap
go get github.com/google/gopacket
git clone https://github.com/vay3t/ghostfer
cd ghostfer
go build ghostfer.go
```

# tshark eq
```
tshark -i eth0 -f arp -T fields -e arp.src.hw_mac -e arp.src.proto_ipv4
```
