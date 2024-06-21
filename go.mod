module httpdump

go 1.13

require (
	github.com/asmcos/requests v0.0.0-20210319030608-c839e8ae4946
	github.com/google/gopacket v1.1.19
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	golang.org/x/net v0.0.0-20200324143707-d3edc9973b7e // indirect
)

replace github.com/google/gopacket => ../gopacket
