package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"net"
	"time"
	"flag"
	"sort"
)

// get the local ip and port based on our destination ip
func localIPPort(dstip net.IP) (net.IP, int) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		log.Fatal(err)
	}

	// We don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.
	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, udpaddr.Port
		}
	}
	log.Fatal("could not get local ip: " + err.Error())
	return nil, -1
}

func createSynPack(dstip net.IP, srcip net.IP, dstport layers.TCPPort, srcport layers.TCPPort, opts gopacket.SerializeOptions) ([]byte){
	ip := &layers.IPv4{
		SrcIP:    srcip,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		log.Fatal(err)
		return nil
	}
	return buf.Bytes()
}

func startRecvPack(conn net.PacketConn, dstip string, srcport layers.TCPPort, signal chan int, portlist map[uint16]bool){
	var i int = 0;
	for {
		b := make([]byte, 4096)
		//log.Println("reading from conn")
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			log.Println("error reading packet: ", err)
			break
		} else if addr.String() == dstip {
			// Decode a packet
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.DstPort == srcport {
					if tcp.SYN && tcp.ACK {
						//log.Printf("Port %d is OPEN\n", tcp.SrcPort)
						i++;
						//portlist.PushBack(tcp.SrcPort)
						portlist[uint16(tcp.SrcPort)] = true
					} else {
						//log.Printf("Port %d is CLOSED\n", tcp.SrcPort)
					}
				}
			}
		} else {
			//log.Printf("Got packet not matching addr")
		}
	}
	signal <- i;
}

func main() {
	//conn2, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	//fmt.Println(reflect.TypeOf(conn2))
	//var ss11 = conn2.(*net.IPConn)
	//var errmsg = ss11.SetWriteBuffer(1024*10);
	//if(errmsg == nil){
	//	fmt.Println("setsuccess")
	//	return
	//}
	//fmt.Println(errmsg)
	//return
	var remoteip string
	flag.StringVar(&remoteip, "rip", "", "scanner ip address")
	var start uint
	flag.UintVar(&start, "start", 1, "the port to begin scanner (default:1)")
	var end uint
	flag.UintVar(&end, "end", 65535, "the port to end scanner (default:65535)")
	var waitTime uint
	flag.UintVar(&waitTime, "wait", 5, "time to wait ack pack or rst pack (default:5 second)")
	flag.Parse()

	//if len(os.Args) != 2 {
	//	log.Printf("Usage: %s <host/ip>\n", os.Args[0])
	//	os.Exit(-1)
	//}
	//log.Println("starting")

	if (remoteip == "") {
		log.Fatal("miss remoteip")
	}

	dstaddrs, err := net.LookupIP(remoteip)
	if err != nil {
		log.Fatal(err)
	}

	// parse the destination host and port from the command line os.Args
	dstip := dstaddrs[0].To4()
	srcip, sport := localIPPort(dstip)
	srcport := layers.TCPPort(sport)
	log.Printf("using srcip: %v", srcip.String())


	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	var synpackages = make([][]byte, 65536)
	for i := start; i <= end; i++ {
		var temppack = createSynPack(dstip, srcip, layers.TCPPort(i), srcport, opts)
		synpackages[i] = temppack
	}


	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}
	var realcon = conn.(*net.IPConn)
	realcon.SetWriteBuffer(65535 * 100)
	realcon.SetReadBuffer(65535 * 100)
	if err := conn.SetDeadline(time.Now().Add(time.Duration(waitTime) * time.Second)); err != nil {
		log.Fatal(err)
	}
	signal := make(chan int)
	var portlist = make(map[uint16]bool)
	go startRecvPack(conn, dstip.String(), srcport, signal, portlist)
	defer conn.Close()

	for _, data := range synpackages{
		if data == nil{
			continue
		}
		_, err := conn.WriteTo(data,&net.IPAddr{IP: dstip} )
		if(err != nil){
			//log.Fatal(err)
			conn.WriteTo(data,&net.IPAddr{IP: dstip} )
		}
		time.Sleep(time.Duration(100)*time.Microsecond)
	}

	var t = <- signal;
	if(t == 0){
		return
	}
	var openport []int;
	for k, v := range portlist {
		//log.Printf("port:%d is open", k)
		if(v){
			openport = append(openport, int(k))
		}
	}
	log.Printf("count:%d", len(openport))
	sort.Ints(openport)
	for _, port := range openport{
		log.Printf("open port:%d", port)
	}
}