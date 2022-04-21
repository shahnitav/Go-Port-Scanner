package main

import (
	"fmt"
	"time"
	"github.com/akamensky/argparse"
	"os"
)

//Declare global variables for the IP Address, Port Range and whether it is a SYN Scan
var ip string
var ports string
var timeout int
var SYN bool

func parseArgs() (string, string, int, bool) {
	parser := argparse.NewParser("Go Port Scanner", "Scans for Open Ports on the given IP Address and Range of Ports.")
	//Create IP Flag
	ip := parser.String("", "ip", &argparse.Options{Required: true, Help: "Target IP"})
	//Create Port Flag
	port := parser.String("p", "port", &argparse.Options{Required: true, Help: "Ports to scan, can be a single value 80, or a range 80-120, or multiple values 80,91,443"})
	//Create Timeout Flag
	timeout := parser.Int("", "t", &argparse.Options{Required: false, Help: "Timeout in Millisecond, Default -> 1000ms", Default: 1000})
	//Create SYN Flag
	SYN := parser.Flag("s", "SYN", "syn")
	parser.Parse(os.Args)
	//Validate Arguments

	return ip, port, timeout, SYN
}

func main() {
	fmt.Println("Go Port Scanner")
	ip, ports, timeout, SYN = parseArgs()
	start := time.Now()

	elapsed := time.Since(start)
	fmt.Printf("Scan duration - %s", elapsed)
}
