package main

import (
	"flag"
	"log"
	"net"
	"os"

	"github.com/google/gopacket/pcap"
	"github.com/vodafon/ipspoof"
)

func main() {
	ipString := flag.String("ip", "", "target IP")
	hwString := flag.String("mac", "", "target MAC address")
	deviceName := flag.String("i", "eth0", "device/interface name")
	flag.Parse()
	if *ipString == "" || *hwString == "" || *deviceName == "" {
		flag.Usage()
		os.Exit(1)
	}

	handle, err := pcap.OpenLive(*deviceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Error opening device. ", err)
	}
	defer handle.Close()

	ip := net.ParseIP(*ipString).To4()
	hw, err := net.ParseMAC(*hwString)
	if err != nil {
		log.Fatal("Error parsing MAC address: ", err)
	}

	err = ipspoof.Listen(handle, ip, hw)
	if err != nil {
		log.Fatal("Error spoofing: ", err)
	}
}
