package ipspoof

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Listen to packets stream and auto-reply on Broadcast requests with given IP and MAC address.
func Listen(handle *pcap.Handle, targetIP net.IP, targetHW net.HardwareAddr) error {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arp := arpLayer.(*layers.ARP)
		if arp.Operation == layers.ARPRequest && targetIP.Equal(arp.DstProtAddress) {
			err := sendReply(handle, arp, targetIP, targetHW)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func layersInit() (layers.Ethernet, layers.ARP) {
	ethernetLayer := layers.Ethernet{
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := layers.ARP{
		Protocol: layers.EthernetTypeIPv4,
	}
	return ethernetLayer, arpLayer
}

func sendReply(handle *pcap.Handle, arp *layers.ARP, targetIP net.IP, targetHW net.HardwareAddr) error {
	ethernetLayer, arpLayer := layersInit()
	ethernetLayer.SrcMAC = targetHW
	ethernetLayer.DstMAC = arp.SourceHwAddress
	arpLayer.SourceProtAddress = targetIP
	arpLayer.DstProtAddress = arp.SourceProtAddress
	arpLayer.Operation = layers.ARPReply
	arpLayer.SourceHwAddress = targetHW
	arpLayer.DstHwAddress = arp.SourceHwAddress
	arpLayer.AddrType = arp.AddrType
	return send(handle, &ethernetLayer, &arpLayer)
}

func send(handle *pcap.Handle, l ...gopacket.SerializableLayer) error {
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, options, l...); err != nil {
		return err
	}
	return handle.WritePacketData(buffer.Bytes())
}
