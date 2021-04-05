package main
// Script discovers the authoritative nameservers for a domain and then queries
// each nameserver to identify anomalies which could indicate whether a DNS 
// takeover is possible

import (
	"io/ioutil"
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"regexp"
	"strings"
	"sync"
)

// NameServerRegex is used to extract the nameserver
const NameServerRegex = "\\s+NS\\s+(?P<ns>.*)"

// DigStatusRegex captures the status of the Resolution request made via dig
const DigStatusRegex = ",\\s*status:\\s+(?P<status>.*),"

// HostRegex is used to extract the host (A-value) from the line
const HostARegex = "\\s*A\\s+(?P<a>.*)"

// ScriptLabel is the relevant label for output from this script
const ScriptLabel = "goclouddnstakeover"

// VulnCheckStatuses lists the vulnerable status code when checking NS
var VulnCheckStatuses = [...]string {
	"SERVFAIL",
	"REFUSED",
}

// isIP returns true if IP is returned
func isIP(host string) bool {
	isIPFlag := true
	ip := net.ParseIP(host)
	if ip == nil {
		isIPFlag = false
	} 
	return isIPFlag
}


// execCmd executes command via shell on linux/mac/windows and return the output.
func execCmd(cmdToExec string) string {

    totalOut := ""
    l := ""

    // Prepare command to execute
    var cmd *exec.Cmd
    switch runtime.GOOS {
      case "windows":
        cmd = exec.Command("cmd.exe", "/c", cmdToExec)
      default:
        cmd = exec.Command("/bin/bash", "-c", cmdToExec)
    }

    // Write output/error commands
    stdout, _ := cmd.StdoutPipe()
    stderr, _ := cmd.StderrPipe()

    // Start command
    cmd.Start()


    // Read STDOUT output and store/display
    scanner := bufio.NewScanner(stdout)
    for scanner.Scan() {
        l = scanner.Text()
        if l != "" {
            totalOut += l + "\n"
        }
    }

    // Read STDERR and store/display
    scanner = bufio.NewScanner(stderr)
    for scanner.Scan() {
        l = scanner.Text()
        if l != "" {
            totalOut += l + "\n"
         }
    }
    cmd.Wait()

    // Return the output and error combined together
    return totalOut
}

// getRegexGroups is used to get info via capture groups
func getRegexGroups(regEx, textToSearch string) (paramsMap map[string]string) {      

    var compRegEx = regexp.MustCompile(regEx)
    match := compRegEx.FindStringSubmatch(textToSearch)

    paramsMap = make(map[string]string)
    for i, name := range compRegEx.SubexpNames() {
        if i > 0 && i <= len(match) {
            paramsMap[name] = match[i]
        }
    }
    return paramsMap
}


// performDNSResolution performs NS/A type DNS resolution on domain via specified
// nameserver and returns results
func performDNSResolution(domain string, nameserver string, qtype string,
	digBinary string) (string, []string) {

	//var dig dnsutil.Dig
	// dig.SetDNS("8.8.8.8") //or ns.xxx.com
	// dig.SetTimeOut(time.Millisecond * time.Duration(100))
	// ns, err := dig.NS("google.com")  // dig google.com @8.8.8.8
	// fmt.Println(ns[2], err)
	
	var results []string

	// Remove trailing dot
	ns := strings.TrimSuffix(nameserver, ".")
	

	var digStatus string

	if ns != "" {
		
		log.Printf("[*] Performing query: %s for domain: %s via ns: %s\n", qtype, domain, ns)
		if qtype == "NS" {

			cmdToExec := fmt.Sprintf("%s -t ns +noall +comments +answer +authority +time=1 %s @%s",
				digBinary, domain, ns)
			log.Printf("[*] Executing cmd: %s\n", cmdToExec)
			nstextlines := execCmd(cmdToExec)
			log.Printf("[*] Output:\n%s\n", nstextlines)
			
			for _, l := range strings.Split(nstextlines, "\n") {
				rg := getRegexGroups(NameServerRegex, l)
				if nameserver := rg["ns"]; nameserver != "" {
					results = append(results, nameserver)
				}

				rg = getRegexGroups(DigStatusRegex, l)
				if status := rg["status"]; status != "" {
					digStatus = status
				}
			}

		} else if qtype == "A" {

			cmdToExec := fmt.Sprintf("%s -t a +noall +comments +answer +authority +time=1 %s @%s",
				digBinary, domain, ns)
			log.Printf("[*] Executing cmd: %s\n", cmdToExec)
			atextlines := execCmd(cmdToExec)
			log.Printf("[*] Output:\n %s\n", atextlines)
			
			for _, l := range strings.Split(atextlines, "\n") {
				rg := getRegexGroups(HostARegex, l)
				if ip := rg["a"]; ip != "" {
					results = append(results, ip)
				}

				rg = getRegexGroups(DigStatusRegex, l)
				if status := rg["status"]; status != "" {
					digStatus = status
				}
			}
			
			
		} else {
			log.Printf("[-] Unknown DNS resolution type: %s\n", qtype)
		}
	}

	return digStatus, results
}


// countDomainLevels is used to count the number of levels present in a domain
func countDomainLevels(domain string) int {
	domainParts := strings.Split(domain, ".")
	return len(domainParts)	
}

// getDomainLevel gets the specified domain level starting from end e.g. 2 for 
// www.msn.com is msn.com, 1 for www.msn.com is com
func getDomainLevel(domain string, level int) string {
	domainParts := strings.Split(domain, ".")
	maxLevel := len(domainParts)
	domainLevel := ""
	for i := maxLevel-1; i >= maxLevel-level-1; i-- {
		if i >= maxLevel-1 {
			domainLevel = domainParts[i]
		} else {
			domainLevel = domainParts[i] + "." + domainLevel
		}
	}
	return domainLevel
}

// checkDomainWorker can be used to start checking each domain one-by-one by 
// splitting domain level, determining the authority nameservers from previous 
// domain level's nameserver 
func checkDomainWorker(domain string, startingNS string, timeout int, 
	digBinary string) {

	maxLevels := countDomainLevels(domain)

	var status string
	var prevLevelNS []string
	var currLevelNS []string

	nameserver := startingNS
	for l := 0; l < maxLevels; l++ {

		// Backup current set of authoritative nameservers 
		prevLevelNS = nil
		for _, n := range currLevelNS {
			prevLevelNS = append(prevLevelNS, n)
		}

		// Get the partial domain name to query
		domainLevel := getDomainLevel(domain, l)
		
		// Get authoritative nameservers
		status, currLevelNS = performDNSResolution(domainLevel, nameserver, "NS", 
			digBinary)
		log.Printf("[*] l: %d, domainLevel: %s, status: %s, currLevelNS: %s\n",
			l, domainLevel, status, currLevelNS)
		if len(currLevelNS) > 0 {
			nameserver = currLevelNS[0]	
		} else {
			break
		}
	}
	log.Printf("[*] domain: %s, final nameservers: %s, prevLevelNS: %s\n",
				domain, currLevelNS, prevLevelNS)

	// Loop through each nameserver to check for vulnerability
	nameServersToCheck := append(currLevelNS, prevLevelNS...)

	for _, ns := range nameServersToCheck {
		log.Printf("[*] Check domain: %s via ns: %s for takeover\n", domain, ns)
		status, results := performDNSResolution(domain, ns, "A", digBinary)
		log.Printf("[*] domain: %s, ns: %s, status: %s, result: %s\n",
			domain, ns, status, results)

		// If status matches ANY vulnerable status code, then report that as 
		// an issue
		for _, s := range VulnCheckStatuses {
			if strings.ToUpper(status) == s {
				fmt.Printf("[%s] domain: %s, ns: %s, status: %s\n", ScriptLabel,
					domain, ns, status)
				break
			}
			
		}

	}

}

func main() {
	var dnsTimeout int
	var nameserver string
	var numGoRoutines int
	var digBinary string
	var quietMode bool

	flag.StringVar(&digBinary, "d", "/usr/bin/dig", "Location of Dig binary")
	flag.StringVar(&nameserver, "ns", "8.8.8.8", "Default nameserver")
	flag.IntVar(&dnsTimeout, "t", 300, "DNS Timeout for query resolutions")
	flag.IntVar(&numGoRoutines, "n", 30, "Number of Goroutines for processing")
	flag.BoolVar(&quietMode, "q", false, "Quiet mode - don't print debug messages")
	flag.Parse()

	// Do not print verbose messages if not required
	if quietMode {
		log.SetOutput(ioutil.Discard)
	}
	
	// Check if 'dig' available
	if _, err := os.Stat(digBinary); os.IsNotExist(err) {
		log.Fatalf("[-] 'dig' binary not found at path: %s\n", digBinary)
	}

	var wg sync.WaitGroup	
	domainsToCheck := make(chan string)

	// Start workers to check the domains
	for i := 0; i < numGoRoutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainsToCheck {
				checkDomainWorker(domain, nameserver, dnsTimeout, digBinary)
			}
		}()
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
    	line := scanner.Text()
		if line != "" {
			domainsToCheck <- line
		}
	}

	close(domainsToCheck)
	wg.Wait()

}