# athena-cloud-dns-takeover

## Introduction 

This repository that contains scripts to perform cloud DNS takeover checks and exploits

More info about these types of takeovers is described here: 
* https://medium.com/@shivsahni2/aws-ns-takeover-356d2a293bca
* https://0xpatrik.com/subdomain-takeover-ns/
* https://thehackerblog.com/the-orphaned-internet-taking-over-120k-domains-via-a-dns-vulnerability-in-aws-google-cloud-rackspace-and-digital-ocean/

## Scripts

### cloud_dns_takeover_check.sh

```
# Script uses 'dig' installed to determine if DNS Subdomain takeover possible on Cloud providers    
# such as AWS Route53 due to dangling DNS (non-existant) record sets, Digital Ocean, Google Cloud   
# and others.                                                                                       
#                                                                                                   
# Script locates authority nameservers for subdomain AND its parent domain, checking response       
# provided when the subdomain is resolved through the authority nameserver. If a particular response
# returned such as SERVFAIL/REFUSED when querying the subdomain's nameserver and the parent domain's 
# nameserver, then it is possible to takeover this subdomain by creating the same DNS recordset with 
# the same Nameservers allocated through the cloud provider.                                        
#                                                                                                   
#                                                                                                   
# Args:                                                                                             
#     debug_flag: Set to 1 for debugging and print additional output, 0 for debugging. By default,  
#                 set to 0 to only print.                                                           
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
#
```
