# ghostfer
Passive hosts enumeration written in golang.

# what is?
Sniffer that captures arp packets and delivers an output with the respective ip and mac address

# Usage
Need root
```
./ghostfer -iface eth0
```

# Help
```
./ghostfer -help
Usage of ./macrecon:
  -iface string
    	Interface use to sniffing (default "wlan0")
```

# Install
```
go get github.com/google/gopacket
git clone https://github.com/vay3t/ghostfer
cd ghostfer
go build ghostfer.go
```
