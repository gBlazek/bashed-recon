#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

# Global variables
VERBOSE=false
ID="$1"

# Default configuration values
DEFAULT_MIN_DELAY=1
DEFAULT_MAX_DELAY=5
DEFAULT_JITTER=0.5
DEFAULT_LISTS_PATH="$(pwd)/lists"
DEFAULT_USER_AGENTS="$DEFAULT_LISTS_PATH/user-agents.txt"
DEFAULT_RESOLVERS1="$DEFAULT_LISTS_PATH/resolvers1.txt"
DEFAULT_RESOLVERS2="$DEFAULT_LISTS_PATH/resolvers2.txt"
DEFAULT_NMAP_TOP_PORTS=1000
DEFAULT_SCAN_PATH="$(pwd)/scans/${ID}_$(date +%s)"
DEFAULT_SCOPE_PATH="$(pwd)/scope/$ID"

# Utility functions
# Function to validate if the input is valid JSON
validate_json() {
    local json_input="$1"
    echo "$json_input" | jq . > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Invalid JSON data received."
        echo "$json_input"  # Optionally print the invalid JSON data for debugging
        exit 1
    fi
}

# Show help message
show_help() {
    cat << EOF
Usage: $0 [OPTIONS] <ID>

Performs a comprehensive web reconnaissance scan.

Positional Arguments:
  ID                    The identifier (folder name where roots.txt it's placed) for the scan (required).

Options:
  -h, --help            Show this help message and exit.
  -v                    Enable verbose output.
  -L <path>             Path to the lists directory (default: $DEFAULT_LISTS_PATH).
  -U <file>             Path to the user agents file (default: $DEFAULT_USER_AGENTS).
  -R1 <file>            Path to the first resolver list (default: $DEFAULT_RESOLVERS1).
  -R2 <file>            Path to the second resolver list (default: $DEFAULT_RESOLVERS2).
  -P <ports>            Number of top ports for nmap scanning (default: $DEFAULT_NMAP_TOP_PORTS).
  -S <path>             Path to store scan results (default: $DEFAULT_SCAN_PATH).
  -C <path>             Path to the scope directory (default: $DEFAULT_SCOPE_PATH).
  --min-delay <seconds> Minimum delay between operations (default: $DEFAULT_MIN_DELAY).
  --max-delay <seconds> Maximum delay between operations (default: $DEFAULT_MAX_DELAY).
  --jitter <value>      Jitter value for rate limiting (default: $DEFAULT_JITTER).
EOF
}

# Parse CLI arguments
parse_args() {
    local TEMP
    TEMP=$(getopt -o hvL:U:R1:R2:P:S:C: -l help,min-delay:,max-delay:,jitter: -n 'scan.sh' -- "$@")
    
    if [ $? != 0 ]; then
        echo "Error parsing arguments." >&2
        show_help
        exit 1
    fi
    
    eval set -- "$TEMP"

    # Loop through the CLI arguments and assign them to variables
    while true; do
        case "$1" in
            -h|--help) show_help; exit 0 ;;
            -v) VERBOSE=true; shift ;;
            -L) LISTS_PATH="$2"; shift 2 ;;
            -U) USER_AGENTS="$2"; shift 2 ;;
            -R1) RESOLVERS1="$2"; shift 2 ;;
            -R2) RESOLVERS2="$2"; shift 2 ;;
            -P) NMAP_TOP_PORTS="$2"; shift 2 ;;
            -S) SCAN_PATH="$2"; shift 2 ;;
            -C) SCOPE_PATH="$2"; shift 2 ;;
            --min-delay) MIN_DELAY="$2"; shift 2 ;;
            --max-delay) MAX_DELAY="$2"; shift 2 ;;
            --jitter) JITTER="$2"; shift 2 ;;
            --) shift; break ;;
            *) echo "Internal error!" >&2; exit 1 ;;
        esac
    done

    # Get the positional argument <ID>
    if [ $# -ne 1 ]; then
        echo "Error: <ID> is required." >&2
        show_help
        exit 1
    fi
    ID="$1"
}

# Main Functionality Modules

# Validation function to ensure inputs are valid
validate_inputs() {
    echo "Validating inputs..."

    # Validate directories
    if [ ! -d "$LISTS_PATH" ]; then
        echo "Error: Lists path '$LISTS_PATH' does not exist." >&2
        exit 1
    fi

    [ ! -d "$SCAN_PATH" ] && mkdir -p "$SCAN_PATH" && echo "Created scan directory at '$SCAN_PATH'."
    [ ! -d "$SCOPE_PATH" ] && { echo "Error: Scope path '$SCOPE_PATH' does not exist." >&2; exit 1; }

    # Validate files
    local required_files=("$USER_AGENTS" "$RESOLVERS1" "$RESOLVERS2")
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            echo "Error: Required file '$file' not found." >&2
            exit 1
        fi
    done

    # Validate numerical values
    for var in MIN_DELAY MAX_DELAY JITTER NMAP_TOP_PORTS; do
        if ! [[ "${!var}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            echo "Error: $var must be a positive number." >&2
            exit 1
        fi
    done

    echo "Validation completed."
}

# Rate limiting with jitter function
rate_limit() {
    local delay=$((RANDOM % (MAX_DELAY - MIN_DELAY + 1) + MIN_DELAY))
    local jitter_value=$(awk "BEGIN {print $delay * $JITTER}")
    sleep "$(echo "$jitter_value" | bc)"
}

# Subdomain enumeration module
subdomain_enumeration() {
    local scan_dir="$SCAN_PATH/${ID}_$(date +%s)"
    cp -v "$SCOPE_PATH/roots.txt" "$SCAN_PATH/roots.txt"

    echo "Starting subdomain enumeration..."
    subfinder -dL "$SCAN_PATH/roots.txt" -o "$SCAN_PATH/subs.txt" || echo "Error: subfinder failed."
}

# DNS resolution module
dns_resolution() {
    local scan_dir="$1"
    echo "Running DNS resolution with shuffledns..."
    shuffledns -d "$SCAN_PATH/subs.txt" -w "$LISTS_PATH/5000.txt" -r "$RESOLVERS1" -mode bruteforce | anew "$SCAN_PATH/subs_unique.txt" | wc -l || echo "Error: shuffledns failed."
}

# PureDNS Module
puredns_scanning(){
    local scan_dir="$1"
    echo "Running puredns..."
    puredns resolve "$SCAN_PATH/subs.txt" -r "$LISTS_PATH/resolvers1.txt" -w "$SCAN_PATH/resolved.txt" | wc -l
}

# DNSX Module
dnsx_scanning() {
    local scan_dir="$1"
    echo "Running dnsx..."
    dnsx -l "$SCAN_PATH/resolved.txt" -json -o "$SCAN_PATH/dns.json" | jq -r '.a?[]?' | sort -u | anew "$SCAN_PATH/ips.txt" || echo "Error: dnsx failed."

    # Validate the JSON output
    dns_json=$(cat "$SCAN_PATH/dns.json")
    validate_json "$dns_json"

    echo "$dns_json" | jq -r '.a?[]?' | sort -u > "$SCAN_PATH/ips.txt"
}

# Nmap Scanning Module
nmap_scanning() {
    local scan_dir="$1"
    echo "Starting nmap scan..."
    timeout 300 nmap -T4 -vv -iL "$SCAN_PATH/ips.txt" --top-ports "$NMAP_TOP_PORTS" -n --open -oX "$SCAN_PATH/nmap.xml" || echo "Error: nmap scan failed."
}

# HTTPx and crawling module
http_scanning() {
    local scan_dir="$1"
    echo "Running HTTPx scanning..."
    tew -x "$SCAN_PATH/nmap.xml" -dnsx "$SCAN_PATH/dns.json" --vhost -o "$SCAN_PATH/hostport.txt" | \
    httpx -sr -srd "$SCAN_PATH/responses" -json -o "$SCAN_PATH/http.json" -H "User-Agent: $(shuf -n 1 "$USER_AGENTS")" || echo "Error: httpx or tew failed."

    # Validate the JSON output
    http_json=$(cat "$SCAN_PATH/http.json")
    validate_json "$http_json"

    echo "$http_json" | jq -r '.url' | sed -e 's/:80$//g' -e 's/:443$//g' | sort -u > "$SCAN_PATH/http.txt" || echo "ERROR" "Processing http.json failed."

    echo "Running gospider for crawling..."
    gospider -S "$SCAN_PATH/http.txt" --json | grep "{" | jq -r '.output?' | tee "$SCAN_PATH/crawl.txt" || echo "Error: gospider failed."
}

# JavaScript extraction module
extract_js_files() {
    local scan_dir="$1"
    echo "Extracting JavaScript files..."
    mkdir -p "$SCAN_PATH/js"
    grep "\.js" "$SCAN_PATH/crawl.txt" | httpx -sr -srd "$SCAN_PATH/js" -H "User-Agent: $(shuf -n 1 "$USER_AGENTS")" || echo "Error: JS extraction failed."
}

# Main scanning workflow
main_scan() {
    local scan_dir="$SCAN_PATH/${ID}_$(date +%s)"
    
    subdomain_enumeration "$scan_dir"
    rate_limit
    
    dns_resolution "$scan_dir"
    rate_limit

    puredns_scanning "$scan_dir"
    rate_limit
    
    dnsx_scanning "$scan_dir"
    rate_limit
    
    nmap_scanning "$scan_dir"
    rate_limit
    
    http_scanning "$scan_dir"
    rate_limit
    
    extract_js_files "$scan_dir"
    
    echo "Scanning completed for ID $ID."
}

# Execute script
main() {
    LISTS_PATH=${LISTS_PATH:-$DEFAULT_LISTS_PATH}
    USER_AGENTS=${USER_AGENTS:-$DEFAULT_USER_AGENTS}
    RESOLVERS1=${RESOLVERS1:-$DEFAULT_RESOLVERS1}
    RESOLVERS2=${RESOLVERS2:-$DEFAULT_RESOLVERS2}
    NMAP_TOP_PORTS=${NMAP_TOP_PORTS:-$DEFAULT_NMAP_TOP_PORTS}
    SCAN_PATH=${SCAN_PATH:-$DEFAULT_SCAN_PATH}
    SCOPE_PATH=${SCOPE_PATH:-$DEFAULT_SCOPE_PATH}
    MIN_DELAY=${MIN_DELAY:-$DEFAULT_MIN_DELAY}
    MAX_DELAY=${MAX_DELAY:-$DEFAULT_MAX_DELAY}
    JITTER=${JITTER:-$DEFAULT_JITTER}

    parse_args "$@"
    validate_inputs
    main_scan
}

main "$@"
