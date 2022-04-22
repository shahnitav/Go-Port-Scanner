package main

import (
	"fmt"
	"time"
	"github.com/akamensky/argparse"
	"os"
	"net"
	"strings"
	"strconv"
)

//Declare global variables for the IP Address, Port Range and whether it is a SYN Scan
var ip string
var ports []string
var timeout int
var SYN bool


//Get a list of ports to scan
func getPortList(argPort string) []string {
	//For multiple ports - 80,443,520
	if strings.Contains(argPort, ",") {
		ports := strings.Split(argPort, ",")
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
		ports := strings.Split(argPort, "-")
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
func parseArgs() (string, []string, int, bool) {
	parser := argparse.NewParser("Go Port Scanner", "Scans for Open Ports on the given IP Address and Range of Ports.")
	//Create IP Flag
	ip := parser.String("", "ip", &argparse.Options{Required: true, Help: "Target IP"})
	//Create Port Flag
	argPort := parser.String("p", "port", &argparse.Options{Required: true, Help: "Ports to scan, can be a single value 80, or a range 80-120, or multiple values 80,91,443"})
	//Create Timeout Flag
	timeout := parser.Int("", "t", &argparse.Options{Required: false, Help: "Timeout in Millisecond, Default -> 1000ms", Default: 1000})
	//Create SYN Flag
	SYN := parser.Flag("s", "syn", &argparse.Options{Required: false, Help: "Will perform a SYN stealth scan to check for open ports"})
	parser.Parse(os.Args)
	//Validate Arguments
	if net.ParseIP(*ip) == nil {
		fmt.Printf("IP Address: %s is invalid", *ip)
		fmt.Printf(os.Args[0] + "-h for Help")
		os.Exit(0)
	}
	ports := getPortList(*argPort)

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

	return *ip, ports, *timeout, *SYN
}

func main() {
	fmt.Println("Go Port Scanner")
	ip, ports, timeout, SYN = parseArgs()
	start := time.Now()
	fmt.Println("IP: ", ip, "\nPorts: ", ports, "\nTimeout: ", timeout, "\nSYN: ", SYN)
	elapsed := time.Since(start)
	fmt.Printf("Scan duration - %s", elapsed)
}
