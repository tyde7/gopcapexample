package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"syscall"
	"bytes"
	"compress/gzip"
	"regexp"
)

var (
	device       string = "eth0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 10 * time.Second
	handle       *pcap.Handle
	netid        int
)

func main() {
	var c []byte= []byte("abcdef");
	copy(c[2:4],[]byte("00"))
	fmt.Println(c)

	fmt.Println("Start pcap test.")
	devices, err := pcap.FindAllDevs()
	if err != nil{
		log.Fatal(err)
	}
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
	fmt.Println("Input the network card to listen:")
	fmt.Scanln(&netid)
	if netid < 0 || netid >= len(devices) {
		log.Fatal("Error Input!")
	}
	// Open device
	handle, err = pcap.OpenLive(devices[netid].Name, snapshot_len, promiscuous, timeout)
	if err != nil {log.Fatal(err) }
	defer handle.Close()

	// Set filter
	var filter string = "tcp and src port 80 and src host 219.217.228.102"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Only capturing TCP port 80 packets.")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//var packetStart,offset uint32;
	var responseArray []byte;
	for packet := range packetSource.Packets() {
		// Process packet here
		var gzipStatus bool = false;
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			fmt.Println("IPv4 Detected.")
			tcp, _ := tcpLayer.(*layers.TCP)
			responseArray = append(responseArray,tcp.Payload...)
			//if tcp.SYN {
			//	packetStart = tcp.Seq
			//	offset = 0
			//}
			if tcp.FIN {
				// Parse Response
				b := bytes.NewBuffer(responseArray)
				for ; ;  {
					read,err :=b.ReadBytes('\n')
					//if bytes.Contains(read,[]byte("gzip")) {
					//	gzipStatus = true;
					//}
					if !gzipStatus {
						_gzipStatus, _ := regexp.MatchString("(?i:^content-encoding:.*gzip.*)", string(read))
						gzipStatus = gzipStatus || _gzipStatus
					}
					//if bytes.Contains(read ,[]byte("Content-Length")) {
					if bytes.Compare(read,[]uint8{13,10}) == 0{
						// Last Line
						var content []byte = make([]byte,65530);
						if gzipStatus {
							// Create GZIP Reader
							unzip,_ := gzip.NewReader(b)
							unzip.Read(content)
							defer unzip.Close()
						}else{
							b.Read(content)
						}
						fmt.Printf("Content: %s.\n",string(content))
						fmt.Printf("Content Length: %d.\n", len(content))
					}
					if err!=nil {
						break
					}
				}
				fmt.Println("Finish one session. Continue? 0/1")
				var reply int
				fmt.Scanln(&reply)
				if reply != 1{syscall.Exit(0)}else{continue}
			}
			//("Source Port %d. Sequence: %d\n",tcp.SrcPort,tcp.Seq)
			fmt.Print(tcp.Payload)
		}
	}
}
