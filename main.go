package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"strings"
)

func main() {
	pcapFile := "N1-SSL VPN.pcap"
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	/*filter := "tcp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}*/

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.SkipDecodeRecovery = true
	packetSource.DecodeStreamsAsDatagrams = true
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}
}

func printPacketInfo(packet gopacket.Packet) {
	fmt.Println("--------------------------------")
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source Mac: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination Mac: ", ethernetPacket.DstMAC)
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		if ethernetPacket.EthernetType.String() == "IPv4" {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
				fmt.Println("Protocol: ", ip.Protocol)
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
					fmt.Println("Sequence number: ", tcp.Seq)
					fmt.Println("TCP flags: ", tcpFlag(tcp.SYN, "SYN"), tcpFlag(tcp.FIN, "FIN"), tcpFlag(tcp.ACK, "ACK"))
					tlsLayer := packet.Layer(layers.LayerTypeTLS)
					if tlsLayer != nil {
						tls2 := tlsLayer.(*layers.TLS)
						fmt.Println("TLS found!")
						for _, h := range tls2.Handshake {
							println(h.HandshakeType)
						}
					}

					applicationLayer := packet.ApplicationLayer()
					if applicationLayer != nil {
						payload := string(applicationLayer.Payload())
						if strings.HasPrefix(payload, "GET") || strings.HasPrefix(payload, "POST") {
							fmt.Println("HTTP found!")
							fmt.Println(payload)
						}
					}
				}
			}
		}
	}
}

func tcpFlag(flag bool, name string) string {
	if flag {
		return name + " "
	} else {
		return ""
	}
}
