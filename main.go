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
	pcapFile := "https.pcap"
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
	index := 1
	for packet := range packetSource.Packets() {
		printPacketInfo(index, packet)
		index += 1
	}
}

func printPacketInfo(index int, packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		//fmt.Println("Source Mac: ", ethernetPacket.SrcMAC)
		//fmt.Println("Destination Mac: ", ethernetPacket.DstMAC)
		//fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		if ethernetPacket.EthernetType.String() == "IPv4" {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				//ip, _ := ipLayer.(*layers.IPv4)
				//fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
				//fmt.Println("Protocol: ", ip.Protocol)
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					//tcp, _ := tcpLayer.(*layers.TCP)
					//fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
					//fmt.Println("Sequence number: ", tcp.Seq)
					//fmt.Println("TCP flags: ", tcpFlag(tcp.SYN, "SYN"), tcpFlag(tcp.FIN, "FIN"), tcpFlag(tcp.ACK, "ACK"))
					tlsLayer := packet.Layer(layers.LayerTypeTLS)
					if tlsLayer != nil {
						tls2 := tlsLayer.(*layers.TLS)
						if tls2.AppData == nil {
							fmt.Println(index, "\t", tls2.Version.String(), "\t", strings.Join(tls2.Summaries, ", "))
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
