package main

import (
	"fmt"
	"time"
	"github.com/akamensky/argparse"
	"os"
	"net"
	"strings"
	"strconv"
	"sync"
	"github.com/fatih/color"
	"encoding/binary"
	"github.com/go-ping/ping"
	"runtime"
)

//Declare global variables for the IP Address, Port Range and whether it is a ICMP Scan
var argIP *string
var ip []string
var ports []string
var timeout int
var ICMP bool

// Common Ports to give description to port numbers
var commonPorts = map[int] string {
	21: "ftp",
	22: "ssh",
	23: "telnet",
	25: "smtp",
	53: "DNS",
	68: "DHCP",
	80 :"http",
	88: "kerberos",
	110: "pop3",
	111: "rpcbind",
	123: "NTP",
	135: "msrpc",
	139: "netbios-ssn",
	143: "imap",
	389: "LDAP",
	443: "https",
	445: "microsoft-ds",
	514: "syslog",
	520: "RIP",
	691: "MSExchange",
	993: "imaps",
	995: "pop3s",
	1434: "mysql-ds",
	3306: "mysql",
	3689: "iTunes",
	3690: "Subversion",
	3389: "ms-wbt-server",
	5432: "PostgreSQL",
	5900: "vnc",
	6347: "Gnutella",
	6999: "BitTorrent",
	8000: "Internet Radio",
	8080: "http-proxy",
	8200: "Internet Radio",
	11371: "OpenPGP",
	12345: "NetBus",
	33434: "traceroute",
}

type PortScan struct {
	Port int //Port Number
	IsOpen bool //Status
}

type HostScan struct {
	IP string //IP Address of Host
 	IsUP bool //Status
}

var result []PortScan // Port Scan Results
var resultHost []HostScan // Host Scan Results

//Ping an IP Address to check if its UP
func pingFunc(pingIP string) HostScan {
	res := &HostScan {
		IP: pingIP,
		IsUP: false,
	}
	pinger, err:= ping.NewPinger(pingIP)
	pinger.SetPrivileged(true)
	if err != nil {
		fmt.Println("Fatal Error while sending an ICMP packet to ", pingIP)
		os.Exit(1)
	}
	pinger.Count = 1
	pinger.Timeout = time.Millisecond * 500
	pinger.OnRecv  = func(pkt *ping.Packet) {
		res.IsUP = true
	}
	err = pinger.Run()
	if err != nil {
		fmt.Println("Fatal Error while sending an ICMP packet to ", pingIP)
		os.Exit(1)
	}
	return *res
}

//Checks if the host is up
func isHostUp(ip []string) {
		// Check for root privileges in Linux required to send raw ICMP Packets
		if runtime.GOOS == "linux" && os.Geteuid() != 0 {
			fmt.Printf("To do a host scan on Linux, you need Admin privileges. Run the binary with 'sudo'.")
			os.Exit(1)
		} else {
			ch := make(chan HostScan)
			//Launch goroutine
			go func() {
				var wg sync.WaitGroup
				wg.Add(len(ip))
				fmt.Println("IP Len - ", len(ip))
				for _, ip_elem := range ip {
					go func(ip_elem string) {
						defer wg.Done()
						res := pingFunc(ip_elem)
						if res.IsUP {
							ch <- res
						}
					}(ip_elem)
				}
				wg.Wait()
				close(ch)	
			}()
			//Append status updates over channel to resultHost
			for elem := range ch {
				resultHost = append(resultHost, elem)
			}
		}
}

//Parse CIDR IP Address to get a list of IP Addresses
func getIP(argIP string) []string {
	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(argIP)
	if err != nil {
		fmt.Println("Fatal error while parsing IP Address: ", argIP)
		os.Exit(1)
	}
	// convert IPNet struct mask and address to uint32
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	// find the start IP address
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	// find the final IP address
	finish := (start & mask) | (mask ^ 0xffffffff)
	// make a slice to return host addresses
	var hosts []string
	// loop through addresses as uint32.
    // I used "start + 1" and "finish - 1" to discard the network and broadcast addresses.
	for i := start + 1; i <= finish-1; i++ {
		// convert back to net.IPs
        // Create IP address of type net.IP. IPv4 is 4 bytes, IPv6 is 16 bytes.
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		hosts = append(hosts, ip.String())
	}
	// return a slice of strings containing IP addresses
	return hosts
}

//Print the result
func printHostResult(elapsed time.Duration){
	color.Cyan("Host Scan Results")
	for _, elem := range resultHost {
		color.Green("IP %s %v\n", elem.IP, elem.IsUP)
	}
	fmt.Printf("Scan duration - %s", elapsed)
}

//Connects to a port to check its status
func connect(ip string , port int, timeout int) PortScan{
	res := &PortScan {
		Port: port,
		IsOpen: false,
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), time.Duration(timeout)*time.Millisecond)
	if err == nil {
		conn.Close()
		res.IsOpen = true
	}
	return *res
}

//Check if the TCP Port is open 
func isPortOpen(ports []string) {
	ch := make(chan PortScan)
	//Launch goroutine
	go func() {
		var wg sync.WaitGroup
		wg.Add(len(ports))
		for _, port := range ports {
			port_int, err := strconv.Atoi(port)
			if err != nil {
				fmt.Println("Error with port : ", port_int)
				continue
			}
			go func(port_int int) {
				defer wg.Done()
				res := connect(ip[0], port_int, timeout)
				if res.IsOpen {
					ch <- res
				}
			}(port_int)
		}
		wg.Wait()
		close(ch)
	}()

	//Append status updates over channel to result
	for elem := range ch {
		result = append(result, elem)
	}
}

//Print the result
func printResult(elapsed time.Duration){
	color.Cyan("Port Scan Results")
	for _, elem := range result {
		desc, ok := commonPorts[elem.Port]
		if ok {
			color.Green("Port %d %s\n", elem.Port, desc)
		} else {
			color.Green("Port %d\n", elem.Port)
		}
	}
	fmt.Printf("Scan duration - %s", elapsed)
}

//Get a list of ports to scan
func getPortList(argPort string) []string {
	//For multiple ports - 80,443,520
	if strings.Contains(argPort, ",") {
		ports = strings.Split(argPort, ",")
		for p := range ports {
			_, err := strconv.Atoi(ports[p])
			if err != nil {
				fmt.Println("Invalid Port: ", ports[p])
				fmt.Println(os.Args[0] + "-h for Help")
				os.Exit(0)
			}
		}
		return ports
	//For a range of ports - 1-120
	} else if strings.Contains(argPort, "-"){
		ports = strings.Split(argPort, "-")
		ports_min, err := strconv.Atoi(ports[0])
		if err != nil {
			fmt.Println("Invalid Minimum Port Value: ", ports_min)
			fmt.Println(os.Args[0] + "-h for Help")
			os.Exit(1)
		}
		ports_max, err := strconv.Atoi(ports[1])
		if err != nil {
			fmt.Println("Invalid Minimum Port Value: ", ports_max)
			fmt.Println(os.Args[0] + "-h for Help")
			os.Exit(1)
		}
		var portsList []string
		for i := ports_min; i<=ports_max; i++ {
			portsList = append(portsList, strconv.Itoa(i))
		}
		return portsList
	} 
	//For single port value
	_, err := strconv.Atoi(argPort)
	if err != nil {
		fmt.Println("Invalid Port: ", argPort)
		fmt.Println(os.Args[0] + "-h for Help")
		os.Exit(1)
	}
	return []string{argPort}
}

// Argument parser and validator
func parseArgs() ([]string, []string, int, bool) {
	parser := argparse.NewParser("Go Port Scanner", "Scans for Open Ports on the given IP Address and Range of Ports.")
	//Create IP Flag
	argIP = parser.String("", "ip", &argparse.Options{Required: true, Help: "Target IP address with support for CIDR eg. 192.168.126.131/28"})
	//Create Port Flag
	argPort := parser.String("p", "port", &argparse.Options{Required: false, Help: "Ports to scan, can be a single value 80, or a range 80-120, or multiple values 80,91,443"})
	//Create Timeout Flag
	timeout := parser.Int("", "t", &argparse.Options{Required: false, Help: "Timeout in Millisecond, Default -> 500ms", Default: 500})
	//Create SYN Flag
	ICMP := parser.Flag("i", "icmp", &argparse.Options{Required: false, Help: "Run an ICMP scan to check on live hosts"})
	parser.Parse(os.Args)
	//Validate Arguments
	//If CIDR get a list of IP Addresses
	if strings.Contains(*argIP, "/") || *ICMP {
		ip = getIP(*argIP)
	} else {
		if net.ParseIP(*argIP) == nil {
			fmt.Println("IP Address: "+ *argIP + "is invalid")
			fmt.Println(os.Args[0] + " -h for Help")
			os.Exit(0)
		}
		ip = []string{*argIP}
		ports = getPortList(*argPort)
	}
	// Replace parser.Usage as the help message
	parser.HelpFunc = func(c *argparse.Command, msg interface{}) string {
		var help string
		help += fmt.Sprintf("Name: %s, Description: %s\n", c.GetName(), c.GetDescription())
		for _, arg := range c.GetArgs() {
			if arg.GetOpts() != nil {
				help += fmt.Sprintf("Sname: %s, Lname: %s, Help: %s\n", arg.GetSname(), arg.GetLname(), arg.GetOpts().Help)
			} else {
				help += fmt.Sprintf("Sname: %s, Lname: %s\n", arg.GetSname(), arg.GetLname())
			}
		}
		return help
	}

	return ip, ports, *timeout, *ICMP
}

func main() {
	color.Cyan("Go Port Scanner")
	ip, ports, timeout, ICMP = parseArgs()
	start := time.Now()
	fmt.Println("IP: ", *argIP, "\nTimeout: ", timeout, "ms \nICMP: ", ICMP)
	if ICMP {
		isHostUp(ip)
		elapsed := time.Since(start)
		printHostResult(elapsed)
	} else {
		isPortOpen(ports)
		elapsed := time.Since(start)
		printResult(elapsed)
	}
}
