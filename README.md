# ghostfer
Passive hosts enumeration written in golang.

# What is?
Sniffer that captures arp packets and delivers an output with the respective ip and mac address

# Why ghostfer?
It is made in a compiled language by what makes it more optimal, portable and lightweight, the only dependence you need for run it is libpcap.

# Usage
Need root

```bash
./ghostfer -iface eth0
```

# Help
```bash
./ghostfer -help
Usage of ./ghostfer:
  -iface string
    	Interface use to sniffing (default "wlan0")
```

# Install
```bash
sudo pacman -S libpcap
go get github.com/google/gopacket
git clone https://github.com/vay3t/ghostfer
cd ghostfer
go build ghostfer.go
```

# tshark command eq
```
sudo tshark -i eth0 -f arp -T fields -e arp.src.hw_mac -e arp.src.proto_ipv4
```
