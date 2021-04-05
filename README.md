# athena-cloud-dns-takeover

## Introduction 

This repository that contains scripts to perform cloud DNS takeover checks and exploits

More info about these types of takeovers is described here: 
* https://medium.com/@shivsahni2/aws-ns-takeover-356d2a293bca
* https://0xpatrik.com/subdomain-takeover-ns/
* https://thehackerblog.com/the-orphaned-internet-taking-over-120k-domains-via-a-dns-vulnerability-in-aws-google-cloud-rackspace-and-digital-ocean/

Currently, this project only provides script(s) to check for DNS takeover vulnerability. PoC scripts 
to exploit the vulnerability will also be added in the near future.

## Scripts

### Golang

#### recon
Script can be used to identify if there any domains susceptible to Cloud DNS 
takeover. The function is similar to the bash script described and relies on 
the `dig` utility being installed on the device.


Examples:
- Assuming we wish to check the following domains for vulnerability
```
$ cat /tmp/domains.txt
www.qantas.com.au
qantas.com.au
www.msn.com
mytestdomaindflkdflkalkad.com
```

Command to check the domains and output is as follows:
```
$ cat /tmp/test.txt | go run recon.go -q
[goclouddnstakeover] domain: mytestdomaindflkdflkalkad.com, ns: ns-543.awsdns-03.net., status: REFUSED
...
```

### Bash

Bash scripts

#### cloud_dns_takeover_check.sh

```
# Script uses 'dig' locally installed command to determine if DNS Subdomain takeover possible on    
# domains hosted with various Cloud providers such as AWS Route53 due to dangling DNS (non-existant) 
# record sets, Digital Ocean, Google Cloud and others.                                              
#                                                                                                   
# Script locates authority nameservers for subdomain AND its parent domain, checking response       
# provided when the subdomain is resolved through each authority nameserver. If particular response 
# returned such as SERVFAIL/REFUSED when querying the subdomain's nameserver and the parent domain's 
# nameserver, then it is possible to takeover this subdomain by creating the a new DNS recordset with 
# one of the same authority nameservers allocated through the cloud provider for the newly created  
# recordset.                                                                                        
#                                                                                                   
#                                                                                                   
# Args:                                                                                             
#     debug_flag: Set to 1 for debugging and print additional output, 0 for debugging. By default,  
#                 set to 0 to only print vulnerable domains.                                        
#                                                                                                   
# Prints:                                                                                           
#     Prints the vulnerable domains by default, and additional logging if debug_flag is set         
#                                                                                                   
# Input:                                                                                            
#     Supply the list of domains as a file OR one per line to this script to check for vulnerability
#                                                                                                   
# Examples:                                                                                         
#     To check if domain 'www.google.com' is vulnerable and print debug data:                       
#         echo "www.google.com" | ./vulscan_cloud_dns_takeover_check.sh 1                           
#                                                                                                   
#     To check domains from file 'input-domains.txt':                                               
#         cat input-domains.txt | ./vulscan_cloud_dns_takeover_check.sh                             
#                                                                                                   
#     To check the domains from input and run checks in parallel using the parallel command:        
#         cat input-domains.txt | parallel --will-cite --pipe -n1 ./vulscan_cloud_dns_takeover_check.sh
```

### aws_route53_takeover_exploit.sh

```
# Script uses 'awscli' to exploit Route53 Dangling entries in hosted zones.                         
#                                                                                                   
# Script first checks whether a domain is vulnerable using the check script in the existing         
# directory. If it is, then it will check if it has any AWS nameservers, extract these AWS authority 
# nameservers, and then start creating hosted zones in Route53 using the profile credentials until  
# it finds atleast one nameserver in the newly created hosted zone that matches the vulnerable      
# authority nameserver.                                                                             
#                                                                                                   
# Once a valid hosted zone, it will now attempt to create a new A record pointing in the new hosted 
# zone pointing to an IP of your choice.                                                            
#                                                                                                   
# Pre-requisites:                                                                                   
#     Pre-requisites for the check script                                                           
#     awscli                                                                                        
#     AWS credentials, configured in ~/.aws/credentials, with access to Route53 to Get, List and    
#         Create Hosted zones AND new DNS records                                                   
#                                                                                                   
# Args:                                                                                             
#     domain: Domain to attempt to compromise                                                       
#     aws_profile: Profile name in ~/.aws/credentials file                                          
#     redirect_host: IP address to point to                                                         
#     sleep_time: Time to sleep (in seconds)                                                        
#                                                                                                   
# Prints:                                                                                           
#     Prints the debug log as it tries to created hosted zones, if it creates a hosted zone with    
#     atleast one nameserver, it will report success AND also, create the A record describing it.   
#                                                                                                   
# Examples:                                                                                         
#   To try to takeover the domain, test.some-domain.com, confirmed to be on vulnerable to AWS       
#   Route53 for redirection to a random IP, 1.1.1.1 using 'default' AWS profile credentials:        
#       ./aws_route53_takeover_exploit.sh test.some-domain.com default 1.1.1.1                      
#
```
