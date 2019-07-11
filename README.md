# ghostfer
Passive hosts enumeration written in golang.

# what is?
Sniffer that captures arp packets and delivers an output with the respective ip and mac address

# Usage
Need root
```
./macrecon -iface eth0
```

# Help
```
./macrecon -help
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
