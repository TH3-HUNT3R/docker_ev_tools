#!/bin/bash

# DockerPEAS - Docker Privilege Escalation Awesome Script
# A comprehensive enumeration tool for Docker containers
# Author: Your Name/Team
# Version: 1.0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Banner
print_banner() {
    echo -e "${BLUE}${BOLD}"
    cat << "EOF"
    ____             __            ____  __________   _____
   / __ \____  _____/ /_____  ____/ __ \/ ____/   | / ___/
  / / / / __ \/ ___/ //_/ _ \/ __/ /_/ / __/ / /| | \__ \ 
 / /_/ / /_/ / /__/ ,< /  __/ / / ____/ /___/ ___ |___/ / 
/_____/\____/\___/_/|_|\___/_/ /_/   /_____/_/  |_|____/  
                                                          
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}Docker Container Enumeration & Escape Vector Discovery Tool${NC}"
    echo -e "-------------------------------------------------------------"
}

# Helper Functions
print_info() { echo -e "${BLUE}[*] $1${NC}"; }
print_success() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_danger() { echo -e "${RED}[CRITICAL] $1${NC}"; }

check_container() {
    print_info "Checking if running inside a container..."
    if [ -f /.dockerenv ] || grep -q 'docker' /proc/1/cgroup; then
        print_success "Confirmed: Running inside a Docker container."
    else
        print_warning "Warning: Could not confirm Docker environment. Checks may be inaccurate."
    fi
}

check_capabilities() {
    print_info "Enumerating Capabilities..."
    # Capability list mapping (subset of common dangerous ones)
    # Value is bit position
    
    if command -v capsh >/dev/null 2>&1; then
        print_success "capsh found. Using capsh for accurate decoding."
        capsh --print
    else
        print_warning "capsh not found. Parsing /proc/1/status manually..."
        if [ -f /proc/1/status ]; then
            cap_eff=$(grep CapEff /proc/1/status | awk '{print $2}')
            print_info "Effective Capabilities (Hex): $cap_eff"
            
            # Simple check for CAP_SYS_ADMIN (Bit 21)
            # This is a bitwise check approximation in bash
            # 0x00000000a80425fb -> example
            
            # Converting hex to decimal for bitwise op
            # Note: This simple check might fail on huge numbers in basic shells, 
            # ideally we'd use python or perl if available.
            
            if command -v python3 >/dev/null 2>&1; then
                 is_sys_admin=$(python3 -c "print(1 if (int('$cap_eff', 16) & (1 << 21)) else 0)")
                 if [ "$is_sys_admin" -eq 1 ]; then
                     print_danger "CAP_SYS_ADMIN detected! (High risk of escape)"
                 fi
                 is_net_admin=$(python3 -c "print(1 if (int('$cap_eff', 16) & (1 << 12)) else 0)")
                 if [ "$is_net_admin" -eq 1 ]; then
                     print_danger "CAP_NET_ADMIN detected! (Network manipulation possible)"
                 fi
                 is_sys_module=$(python3 -c "print(1 if (int('$cap_eff', 16) & (1 << 16)) else 0)")
                 if [ "$is_sys_module" -eq 1 ]; then
                     print_danger "CAP_SYS_MODULE detected! (Kernel module loading possible)"
                 fi
            else
                print_warning "Python3 not found. Cannot accurately decode capability bits manually in pure bash safely."
                print_info "Install 'libcap2-bin' (capsh) or python3 to check capabilities."
            fi
        else
            print_warning "Could not read /proc/1/status"
        fi
    fi
}

check_mounts() {
    print_info "Checking Mounts..."
    
    # Check for docker socket
    if [ -e /var/run/docker.sock ]; then
        print_danger "Docker Socket found: /var/run/docker.sock"
        ls -l /var/run/docker.sock
        print_info "Attempting to list containers using socket..."
        if command -v curl >/dev/null 2>&1; then
             curl --unix-socket /var/run/docker.sock http://localhost/containers/json 2>/dev/null
             echo ""
        elif command -v docker >/dev/null 2>&1; then
             docker -H unix:///var/run/docker.sock ps 2>/dev/null
        else
             print_warning "No curl or docker client to test socket."
        fi
    fi

    # Check for root mount
    if mount | grep -q 'on / .*rprivate'; then
         # This is a heuristic, looking for unusual root mounts
         :
    fi
    
    # Look for mounts that give away host access
    mount | grep -E "/dev/|/sys|/proc|/etc|/root" | while read -r line; do
        if [[ "$line" == *"/dev/sd"* ]] || [[ "$line" == *"/dev/vd"* ]]; then
             print_danger "Possible Host Device Mount: $line"
        fi
        if [[ "$line" == *"/etc"* ]] && [[ "$line" != *"/etc/resolv.conf"* ]] && [[ "$line" != *"/etc/hostname"* ]] && [[ "$line" != *"/etc/hosts"* ]]; then
             print_danger "Possible Host /etc Mount: $line"
        fi
    done
}

check_privileged() {
    print_info "Checking for Privileged Mode..."
    
    # Method 1: Check available devices
    # Privileged containers can see many devices
    dev_count=$(ls /dev | wc -l)
    print_info "Device count in /dev: $dev_count"
    
    if [ "$dev_count" -gt 50 ]; then # Arbitrary threshold, usually valid
        print_danger "High number of devices found. Likely Privileged Mode."
    fi
    
    # Method 2: Check access to /dev/kmsg
    if [ -w /dev/kmsg ]; then
        print_danger "Write access to /dev/kmsg detected."
    fi
    
    # Method 3: Check /sys/kernel/security
    if [ -d /sys/kernel/security ] && mount | grep -q "/sys/kernel/security"; then
         print_warning "/sys/kernel/security is mounted."
    fi
}

check_kernel() {
    print_info "Checking Kernel Version..."
    uname -r
    
    # Simple check for Dirty COW range (heuristic)
    # Real detection requires more specific version matching
    kver=$(uname -r)
    if [[ "$kver" == *"2.6.22"* ]] || [[ "$kver" < "4.8.3" ]]; then
         print_warning "Kernel version might be vulnerable to Dirty COW (CVE-2016-5195)"
    fi
}

check_network() {
    print_info "Checking Network..."
    ip addr
    
    print_info "Checking for listening ports..."
    if command -v netstat >/dev/null 2>&1; then
        netstat -tuln
    elif command -v ss >/dev/null 2>&1; then
        ss -tuln
    else
        print_warning "netstat/ss not found."
    fi
    
    print_info "Checking default gateway (Host IP)..."
    ip route show | grep default
}

check_env_secrets() {
    print_info "Checking Environment Variables for Secrets..."
    env | grep -iE "pass|secret|key|token|auth|pwd"
}

check_files() {
    print_info "Searching for sensitive files..."
    
    # Common config files
    find / -name "*.conf" -o -name "*.config" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" 2>/dev/null | grep -v "/proc/" | grep -v "/sys/" | head -n 20
    
    # Check for SSH keys
    if [ -d /root/.ssh ] || [ -d /home/*/.ssh ]; then
        print_danger "SSH keys found!"
        ls -laR /root/.ssh 2>/dev/null
        ls -laR /home/*/.ssh 2>/dev/null
    fi
}

check_tools() {
    print_info "Checking Available Tools..."
    tools=("curl" "wget" "nc" "netcat" "nmap" "python" "python3" "perl" "gcc" "g++" "make" "docker" "kubectl")
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            print_success "$tool is installed."
        else
            print_warning "$tool is NOT installed."
        fi
    done
}

main() {
    print_banner
    check_container
    echo "-------------------------------------------------------------"
    check_capabilities
    echo "-------------------------------------------------------------"
    check_privileged
    echo "-------------------------------------------------------------"
    check_mounts
    echo "-------------------------------------------------------------"
    check_kernel
    echo "-------------------------------------------------------------"
    check_network
    echo "-------------------------------------------------------------"
    check_env_secrets
    echo "-------------------------------------------------------------"
    check_files
    echo "-------------------------------------------------------------"
    check_tools
    echo "-------------------------------------------------------------"
    print_success "Enumeration Complete."
}

main
