#!/bin/bash

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
# 


# Vulnerability signature found from within A response
VULN_REGEX="(SERVFAIL|REFUSED)"

# DEBUG: Set flag to 1 for debugging and printing additional output, 0 for not debugging
DEBUG_FLAG=${1:-"0"}

function get_num_levels_in_domain {
    # Get the number of levels in the domain. E.g. msn.com has 2, www.google.com has 3.
    # 
    # Args
    #     domain: Domain to get the number of levels
    #
    # Returns
    #     Number of levels in the domain
    # 
    local domain="$1"

    local domain_parts=$(echo "$domain" | tr -s "." "\n")
    local num_domain_parts=$(echo "$domain_parts" | grep -c "")
    echo "$num_domain_parts"
}

function get_domain_level {
    # Function returns the domain at given level e.g. if domain is called www.google.com
    # then, 1st level: com
    #       2nd level: google.com
    #       3rd level: www.google.com
    # 
    # Args
    #     domain: Domain to get the level
    #     num_levels: Level of the domain to return
    # 
    # Returns
    #     Returns the domain level at the given level
    #
    local domain="$1"
    local num_levels="$2"
    
    local num_levels_in_domain=$(get_num_levels_in_domain "$domain")
    local domain_to_output=""
    local domain_parts=$(echo "$domain" | tr -s "." "\n")

    for ((i=($num_levels_in_domain-$num_levels+1); i<=$num_levels_in_domain; i++)); do
        local domain_part_to_add=$(echo "$domain_parts" | head -n $i | tail -n1 )
        domain_to_output="$domain_to_output$domain_part_to_add."
    done
    echo "$domain_to_output"
}

function perform_dns_resolution_via_dig {
    # Perform DNS resolution for a domain via the specified nameserver
    # 
    # Args
    #     domain: Domain to resolve
    #     nameserver: Nameserver to use for resolution
    #     type: Type of resolution to perform
    # 
    # Returns
    #     DNS resolution value performed with dig
    #
    local domain="$1"
    local nameserver="$2"
    local type="$3"

    dig -t "$type" +nostats +answer "$domain" @"$nameserver"
}

function get_nameservers_via_dig {
    # Function get the nameservers via dig. If nameserver not specified, then the default nameserver
    # for the domain is used.
    #
    # The function will first attempt to local the normal nameservers. If not found, then the 
    # authority nameservers are found.
    #
    # Args
    #     domain: Domain name to resolve
    #     nameserver: Nameserver to use
    # 
    # Returns
    #     Authority OR Normal nameservers
    # 
    local domain="$1" 
    local nameserver="$2"

    # First try to get the authority nameservers
    authority_ns=$(dig -t ns +noall +authority $domain @"$nameserver" \
        | grep "NS" \
        | egrep -io "[a-zA-Z0-9\_\.\-]+$")

    # If nothing available, then return the nameservers from the answer
    if [ ! -z "$authority_ns" ]; then
        echo "$authority_ns"
    else
        answer_ns=$(dig -t ns +noall +answer $domain @"$nameserver" \
            | grep "NS" \
            | egrep -io "[a-zA-Z0-9\_\.\-]+$")
        echo "$answer_ns"
    fi
}

# Get a list of all the domains from user to check
domains_to_check="$(cat -)"

# Start looping through each domain to check
IFS=$'\n'
for domain in $domains_to_check; do
    
    if [ "$DEBUG_FLAG" == "1" ]; then
        # Display the domain we are checking for user's benefit
        echo "[*] Checking domain: $domain"
    fi

    # Start with the DNS nameserver of Google, and a var to store the previous level nameservers
    nameservers="8.8.8.8"
    nameserver="8.8.8.8"
    prev_level_nameservers=""

    # Start going through each level for the domain
    num_levels=$(get_num_levels_in_domain "$domain")

    # for each subdomain level, starting with tld (level_no=1)
    for level_no in $(seq 1 $num_levels); do

        # get the domain e.g. for www.google.com, level_no=1 is com., level_no=2 is google.com.
        domain_level=$(get_domain_level "$domain" "$level_no")

        # Get the nameservers for this domain's level and previous level's
        prev_level_nameservers="$nameservers"
        nameservers=$(get_nameservers_via_dig "$domain_level" "$nameserver")
    
        # Get a single nameserver for resolution of previous level
        nameserver=$(echo "$nameservers" | head -n1)
        
        if [ "$DEBUG_FLAG" == "1" ]; then
            # DEBUG: Print domain_level, nameserver and prev level nameserver
            echo "[*] domain_level: $domain_level, nameservers: $nameservers, prev_level_nameservers: $prev_level_nameservers"
        fi

        if [ -z "$nameserver" ]; then
            break
        fi
    done

    # store dns resolution record results
    dns_resolution=""
    dns_resolution_prev_level=""
    
    # Check the authoritative nameservers for the current level
    if [ ! -z "$nameservers" ]; then
    
        # Loop through each nameserver found
        IFS=$'\n'
        for nameserver in $nameservers; do
            
            # Now, perform A DNS resolution on the nameserver
            dns_resolution=$(perform_dns_resolution_via_dig "$domain" "$nameserver" "A")
    
            if [ "$DEBUG_FLAG" == "1" ]; then
                # DEBUG statement: Print domain level and the nameserver
                echo "[*] domain_level: $domain_level, nameserver: $nameserver, dns_resolution: $dns_resolution"
            fi
    
            # If unusual response like Server failure, then takeover possible
            is_vulnerable=$(echo "$dns_resolution" | egrep -i "status" | egrep -i "$VULN_REGEX")
            if [ ! -z "$is_vulnerable" ]; then
                echo "[+] Vulnerable domain found. Domain: $domain, nameserver: $nameserver, domain_level: $domain_level"
            fi  
        done
    fi
    
    # Check previous level's nameservers as well, if not empty
    if [ ! -z "$prev_level_nameservers" ]; then
        
        # loop through each nameserver for previous level
        IFS=$'\n'
        for prev_level_nameserver in $prev_level_nameservers; do
    
            # Now, perform A DNS resolution on the nameserver
            dns_resolution_prev_level=$(perform_dns_resolution_via_dig "$domain" \
                                        "$prev_level_nameserver" "A")
    
            if [ "$DEBUG_FLAG" == "1" ]; then
                # DEBUG: Print the domain level, previous level's nameserver and resolution using the 
                # previous level's nameserver
                echo "[*] domain: $domain, nameserver: $prev_level_nameserver, dns_resolution_prev_level: $dns_resolution_prev_level"
            fi
            
            # If unusual response like Server failure, then takeover possible
            is_vulnerable=$(echo "$dns_resolution_prev_level" | egrep -i "status" | egrep -i "$VULN_REGEX")
            if [ ! -z "$is_vulnerable" ]; then
                echo "[+] Vulnerable domain found. Domain: $domain, nameserver: $prev_level_nameserver, domain_level: $domain_level"
            fi
        done
    fi

done

