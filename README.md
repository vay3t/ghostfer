# ghostfer
Passive hosts enumeration written in golang.

# what is?
Sniffer that captures arp packets and delivers an output with the respective ip and mac address

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
