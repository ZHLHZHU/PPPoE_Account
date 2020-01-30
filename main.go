package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

var (
	device                      = ""
	snapshotLen           int32 = 1024
	err                   error
	timeout               = 2 * time.Second
	handle                *pcap.Handle
	displayLengthOnResult = false
)

const (
	PADI        = 0x09
	PADO        = 0x07
	PADR        = 0x19
	PADS        = 0x65
	SessionData = 0x00

	PPPoEDiscovery = 0x8863
	PPPoESession   = 0x8864
)

func init() {
	flag.StringVar(&device, "d", "eth0", "specified network devices")
	flag.BoolVar(&displayLengthOnResult, "l", false, "display length on result")
	flag.Parse()
}

func main() {
	handle, err = pcap.OpenLive(device, snapshotLen, true, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		switch ethernetPacket.EthernetType {
		case layers.EthernetTypePPPoEDiscovery:
			go handlePPPoEDiscovery(ethernetPacket)
		case layers.EthernetTypePPPoESession:
			go handlePPPoESession(ethernetPacket)
		}

	}
}

func handlePPPoEDiscovery(ethernetPacket *layers.Ethernet) {
	pppoePacketRaw := gopacket.NewPacket(ethernetPacket.Payload, layers.LayerTypePPPoE, gopacket.NoCopy)
	pppoeLayer := pppoePacketRaw.Layer(layers.LayerTypePPPoE)
	pppoePacket := pppoeLayer.(*layers.PPPoE)
	switch pppoePacket.Code {
	case PADI:
		handlePADI(ethernetPacket.SrcMAC, pppoePacket)
	case PADR:
		handlePADR(ethernetPacket.SrcMAC, pppoePacket)
	}

}

func handlePADI(remoteMAC net.HardwareAddr, pppoePacket *layers.PPPoE) {
	hostUniq := getHostUniq(pppoePacket.Payload)
	payload := []byte{0x01, 0x02, 0x00, 0x04, 0x5a, 0x48, 0x4c, 0x48, 0x01, 0x01, 0x00, 0x00, 0x01, 0x04, 0x00, 0x14, 0xa3, 0x57, 0x32, 0x90, 0xbf, 0xfd, 0x57, 0x2e, 0xe6, 0x9b, 0xf0, 0xc7, 0x8f, 0x51, 0xe1, 0x26, 0x96, 0x1a, 0x00, 0x00}
	payload = bytes.Join([][]byte{payload, hostUniq}, []byte(""))
	sendPacket(remoteMAC, payload, PADO, pppoePacket.SessionId, PPPoEDiscovery, uint16(len(payload)))
}

func handlePADR(remoteMAC net.HardwareAddr, pppoePacket *layers.PPPoE) {
	hostUniq := getHostUniq(pppoePacket.Payload)
	headByte := []byte{0x01, 0x01, 0x00, 0x00}
	payload := bytes.Join([][]byte{headByte, hostUniq}, []byte(""))
	sendPacket(remoteMAC, payload, PADS, 0x0006, PPPoEDiscovery, uint16(len(payload)))
}

func handlePPPoESession(ethernetPacket *layers.Ethernet) {
	//todo 判断lcp阶段
	pppoePacketRaw := gopacket.NewPacket(ethernetPacket.Payload, layers.LayerTypePPPoE, gopacket.NoCopy)
	pppoeLayer := pppoePacketRaw.Layer(layers.LayerTypePPPoE)
	pppoePacket := pppoeLayer.(*layers.PPPoE)
	pppPacketRaw := gopacket.NewPacket(pppoePacket.Payload, layers.LayerTypePPP, gopacket.NoCopy)
	pppLayer := pppPacketRaw.Layer(layers.LayerTypePPP)
	pppPacket := pppLayer.(*layers.PPP)
	switch pppPacket.PPPType {
	case 0xc021:
		handleLCP(ethernetPacket.SrcMAC, pppoePacket, pppPacket.Payload[0])
	case 0xc023:
		//pap
		handlePAP(ethernetPacket.SrcMAC, pppoePacket)
	}
}

func handleLCP(remoteMAC net.HardwareAddr, pppoePacket *layers.PPPoE, Code byte) {
	switch Code {
	case 0x01: //Configuration Request
		handleConfigurationRequest(remoteMAC, pppoePacket)
	case 0x02: //Configuration ACK
		//直接抛弃
		return
	}
}

func handleConfigurationRequest(remoteMAC net.HardwareAddr, pppoePacket *layers.PPPoE) {
	//本端也发一个ConfigurationRequest,然后回应ConfigurationACK
	configurationRequestPayload := []byte{0xc0, 0x21, 0x01, 0x01, 0x00, 0x12, 0x01, 0x04, 0x05, 0xd4, 0x03, 0x04, 0xc0, 0x23, 0x05, 0x06, 0xb9, 0xa2, 0x7f, 0x69}
	sendPacket(remoteMAC, configurationRequestPayload, SessionData, 0x0006, PPPoESession, uint16(len(configurationRequestPayload)))
	configurationACKPayload := pppoePacket.Payload
	configurationACKPayload[2] = 2 // change LCP Code
	sendPacket(remoteMAC, configurationACKPayload, SessionData, 0x0006, PPPoESession, uint16(len(configurationACKPayload)))
}

func handlePAP(remoteMAC net.HardwareAddr, pppoePacket *layers.PPPoE) {
	idLength := pppoePacket.Payload[6]
	id := string(pppoePacket.Payload[7 : 7+idLength])
	passwordLength := pppoePacket.Payload[7+idLength]
	password := string(pppoePacket.Payload[7+idLength+1 : 7+idLength+1+passwordLength])
	if displayLengthOnResult {
		fmt.Printf("%s\tID(%d): %s\tPassword(%d): %s \n", time.Now().Format("2006-01-02 15:04:05"), idLength, id, passwordLength, password)
	} else {
		fmt.Printf("%s\tID: %s\tPassword: %s \n", time.Now().Format("2006-01-02 15:04:05"), id, password)
	}
	terminationRequest(remoteMAC)
}

func terminationRequest(remoteMAC net.HardwareAddr) {
	payload := []byte{0xc0, 0x21, 0x05, 0x02, 0x00, 0x19, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64}
	sendPacket(remoteMAC, payload, SessionData, 0x0006, PPPoESession, uint16(len(payload)))
}

func getHostUniq(payload []byte) []byte {
	hostUniqIndex := 0
	for i := 0; i < len(payload)-1; i++ {
		if payload[i] == 0x01 && payload[i+1] == 0x03 {
			hostUniqIndex = i
			break
		}
	}
	hostUniqLengthIndex := hostUniqIndex + 2
	length := binary.BigEndian.Uint16(payload[hostUniqLengthIndex : hostUniqLengthIndex+2])
	return payload[hostUniqIndex : hostUniqLengthIndex+2+int(length)]

}

func getMACAddr() net.HardwareAddr {
	interfaces, _ := net.Interfaces()
	for _, netInterface := range interfaces {
		if netInterface.Name == device {
			return netInterface.HardwareAddr
		}
	}
	return net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA}
}

func sendPacket(remoteMAC net.HardwareAddr, payload []byte, code layers.PPPoECode, sessionId uint16, protocol layers.EthernetType, length uint16) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	_ = gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       getMACAddr(),
			DstMAC:       remoteMAC,
			EthernetType: protocol,
		},
		&layers.PPPoE{
			Version:   uint8(1),
			Type:      uint8(1),
			Code:      code,
			SessionId: sessionId,
			Length:    length,
		},
		gopacket.Payload(payload),
	)
	_ = handle.WritePacketData(buffer.Bytes())
}
