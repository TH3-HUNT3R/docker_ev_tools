#!/bin/bash

# DockerPEAS - Docker Container Privilege Escalation Awesome Script
# Automated Docker Container Security Enumeration & Escape Detection
# Usage: ./dockerpeas.sh [-o output_file]

# Color codes
RED='\033[0;31m'
LRED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
LGREEN='\033[1;32m'
BLUE='\033[0;34m'
LBLUE='\033[1;34m'
CYAN='\033[0;36m'
LCYAN='\033[1;36m'
NC='\033[0m' # No Color

# Output file
OUTPUT_FILE="dockerpeas_findings.json"
FINDINGS=()

# Banner
print_banner() {
    echo -e "${LCYAN}"
    cat << "EOF"
    ____             __            ____  _________    _____
   / __ \____  _____/ /_____  ____/ __ \/ ____/   |  / ___/
  / / / / __ \/ ___/ //_/ _ \/ __/ /_/ / __/ / /| |  \__ \ 
 / /_/ / /_/ / /__/ ,< /  __/ / / ____/ /___/ ___ | ___/ / 
/_____/\____/\___/_/|_|\___/_/ /_/   /_____/_/  |_|/____/  
                                                            
EOF
    echo -e "${BLUE}Docker Container Privilege Escalation Enumeration${NC}"
    echo -e "${CYAN}by Security Researcher | Inspired by PEASS-ng${NC}\n"
}

# Helper functions
print_header() {
    echo -e "\n${LBLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${LBLUE}[+] $1${NC}"
    echo -e "${LBLUE}═══════════════════════════════════════════════════════════${NC}"
}

print_critical() {
    echo -e "${LRED}[CRITICAL] $1${NC}"
}

print_high() {
    echo -e "${RED}[HIGH] $1${NC}"
}

print_medium() {
    echo -e "${YELLOW}[MEDIUM] $1${NC}"
}

print_low() {
    echo -e "${GREEN}[LOW] $1${NC}"
}

print_info() {
    echo -e "${CYAN}[INFO] $1${NC}"
}

# Add finding to JSON array
add_finding() {
    local severity="$1"
    local type="$2"
    local description="$3"
    local details="$4"
    local exploit_hint="$5"
    
    # Only add HIGH and CRITICAL findings
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

# Check if running in container
check_container_environment() {
    print_header "Container Environment Detection"
    
    IN_CONTAINER=false
    
    if [ -f "/.dockerenv" ]; then
        print_info "Found /.dockerenv - Running inside Docker container"
        IN_CONTAINER=true
    elif grep -qa docker /proc/1/cgroup 2>/dev/null; then
        print_info "Found docker in cgroup - Running inside container"
        IN_CONTAINER=true
    elif grep -qa kubepods /proc/1/cgroup 2>/dev/null; then
        print_info "Found kubepods in cgroup - Running inside Kubernetes pod"
        IN_CONTAINER=true
    else
        print_low "Container markers not found - might be running on host"
    fi
    
    # Check container runtime
    if command -v docker &> /dev/null; then
        print_info "Docker client available"
    fi
    
    print_info "Hostname: $(hostname)"
}

# Check for docker.sock
check_docker_sock() {
    print_header "Docker Socket Exposure Check"
    
    SOCK_PATHS="/var/run/docker.sock /run/docker.sock /var/run/docker.pid"
    
    for sock in $SOCK_PATHS; do
        if [ -S "$sock" ] || [ -e "$sock" ]; then
            print_critical "Docker socket found: $sock"
            echo -e "${LRED}    └─ Container can control Docker daemon!${NC}"
            echo -e "${LRED}    └─ Escape: docker run -v /:/mnt --rm -it alpine chroot /mnt sh${NC}"
            
            # Check permissions
            perms=$(ls -la "$sock" 2>/dev/null)
            echo "$perms"
            
            # Add to findings
            add_finding "CRITICAL" "DOCKER_SOCKET" \
                "Docker socket exposed at $sock" \
                "$perms" \
                "docker_socket_escape"
        fi
    done
}

# Check privileged mode
check_privileged_mode() {
    print_header "Privileged Mode Detection"
    
    # Check for device access
    devices=$(ls -la /dev/sda* /dev/dm-* /dev/vda* /dev/xvda* 2>/dev/null | grep "^b")
    if [ ! -z "$devices" ]; then
        print_critical "Block devices accessible in /dev!"
        echo -e "${LRED}    └─ Container likely running in --privileged mode${NC}"
        echo -e "${LRED}    └─ Escape: fdisk -l; mount /dev/sda1 /mnt${NC}"
        echo "$devices" | head -5
        
        # Get first device
        first_device=$(echo "$devices" | head -1 | awk '{print $NF}')
        
        add_finding "CRITICAL" "PRIVILEGED_MODE" \
            "Block devices accessible - privileged container detected" \
            "$devices" \
            "privileged_mount_escape|$first_device"
    fi
    
    # Check /sys mount
    if mount | grep -q "sysfs on /sys.*rw"; then
        print_high "/sys mounted as read-write"
        echo -e "${RED}    └─ Possible privileged mode indicator${NC}"
    fi
    
    # Check for full /proc access
    if [ -r /proc/sched_debug ]; then
        print_high "Can read /proc/sched_debug (host process info)"
    fi
}

# Decode and check capabilities
check_capabilities() {
    print_header "Linux Capabilities Analysis"
    
    if [ -f /proc/1/status ]; then
        CAP_EFF=$(grep CapEff /proc/1/status | awk '{print $2}')
        CAP_BSET=$(grep CapBnd /proc/1/status | awk '{print $2}')
        
        print_info "Effective Capabilities: 0x$CAP_EFF"
        print_info "Bounding Capabilities: 0x$CAP_BSET"
        
        # Decode if capsh available
        if command -v capsh &> /dev/null; then
            echo -e "${CYAN}Decoded Capabilities:${NC}"
            capsh --decode=$CAP_EFF
        fi
        
        # Convert hex to binary and check dangerous caps
        CAP_DEC=$((16#$CAP_EFF))
        
        # CAP_SYS_ADMIN = bit 21
        if [ $(( ($CAP_DEC >> 21) & 1 )) -eq 1 ]; then
            print_critical "CAP_SYS_ADMIN detected!"
            echo -e "${LRED}    └─ Can mount filesystems, load kernel modules${NC}"
            echo -e "${LRED}    └─ Check cgroup release_agent exploit${NC}"
            
            add_finding "CRITICAL" "CAP_SYS_ADMIN" \
                "CAP_SYS_ADMIN capability detected" \
                "Can exploit cgroup release_agent for container escape" \
                "cgroup_release_agent_escape"
        fi
        
        # CAP_SYS_MODULE = bit 16
        if [ $(( ($CAP_DEC >> 16) & 1 )) -eq 1 ]; then
            print_critical "CAP_SYS_MODULE detected!"
            echo -e "${LRED}    └─ Can load malicious kernel modules${NC}"
            
            add_finding "CRITICAL" "CAP_SYS_MODULE" \
                "CAP_SYS_MODULE capability detected" \
                "Can load kernel modules to escape container" \
                "kernel_module_escape"
        fi
        
        # CAP_SYS_PTRACE = bit 19
        if [ $(( ($CAP_DEC >> 19) & 1 )) -eq 1 ]; then
            print_high "CAP_SYS_PTRACE detected"
            echo -e "${RED}    └─ Can trace/inject into processes${NC}"
            
            add_finding "HIGH" "CAP_SYS_PTRACE" \
                "CAP_SYS_PTRACE capability detected" \
                "Can trace and inject into host processes if namespace shared" \
                "ptrace_injection"
        fi
        
        # CAP_DAC_READ_SEARCH = bit 2
        if [ $(( ($CAP_DEC >> 2) & 1 )) -eq 1 ]; then
            print_high "CAP_DAC_READ_SEARCH detected"
            echo -e "${RED}    └─ Can bypass file read permissions${NC}"
        fi
        
        # CAP_DAC_OVERRIDE = bit 1
        if [ $(( ($CAP_DEC >> 1) & 1 )) -eq 1 ]; then
            print_high "CAP_DAC_OVERRIDE detected"
            echo -e "${RED}    └─ Can bypass file write permissions${NC}"
        fi
        
        # CAP_NET_RAW = bit 13
        if [ $(( ($CAP_DEC >> 13) & 1 )) -eq 1 ]; then
            print_medium "CAP_NET_RAW detected"
            echo -e "${YELLOW}    └─ Can use raw sockets (network sniffing)${NC}"
        fi
        
        # CAP_SYS_RAWIO = bit 17
        if [ $(( ($CAP_DEC >> 17) & 1 )) -eq 1 ]; then
            print_critical "CAP_SYS_RAWIO detected!"
            echo -e "${LRED}    └─ Can access I/O ports, kernel memory${NC}"
            
            add_finding "CRITICAL" "CAP_SYS_RAWIO" \
                "CAP_SYS_RAWIO capability detected" \
                "Can access kernel memory and I/O ports" \
                "rawio_escape"
        fi
    else
        print_low "Cannot read /proc/1/status"
    fi
}

# Check dangerous mounts
check_mounts() {
    print_header "Dangerous Mount Points"
    
    # Check for root mount
    root_mount=$(mount | grep " / " | grep -v "overlay\|tmpfs")
    if echo "$root_mount" | grep -q "/dev/"; then
        print_critical "Host root filesystem appears to be mounted!"
        echo "$root_mount"
        
        add_finding "CRITICAL" "HOST_ROOT_MOUNT" \
            "Host root filesystem mounted in container" \
            "$root_mount" \
            "direct_host_access"
    fi
    
    # Check other dangerous paths
    DANGEROUS_PATHS="/host /etc /root /var/run /var/log /sys /boot"
    
    for danger in $DANGEROUS_PATHS; do
        mount_info=$(mount | grep " $danger " | head -1)
        if [ ! -z "$mount_info" ]; then
            if [[ "$danger" == "/host" || "$danger" == "/etc" || "$danger" == "/root" ]]; then
                print_critical "Host path mounted: $mount_info"
                echo -e "${LRED}    └─ Direct host filesystem access!${NC}"
                
                add_finding "CRITICAL" "HOST_PATH_MOUNT" \
                    "Sensitive host path mounted: $danger" \
                    "$mount_info" \
                    "host_path_exploit|$danger"
            fi
        fi
    done
    
    # Check for cgroup mounts with release_agent
    for cg in /sys/fs/cgroup/*/release_agent /sys/fs/cgroup/rdma/release_agent; do
        if [ -w "$cg" 2>/dev/null ]; then
            print_critical "Writable release_agent: $cg"
            echo -e "${LRED}    └─ CVE-2022-0492 exploit possible!${NC}"
            
            cgroup_path=$(dirname "$cg")
            add_finding "CRITICAL" "WRITABLE_RELEASE_AGENT" \
                "Writable cgroup release_agent detected" \
                "$cg" \
                "cgroup_release_agent_escape|$cgroup_path"
        fi
    done
    
    # Check for docker directory mounts
    if mount | grep -q "/var/lib/docker"; then
        print_critical "Docker storage directory mounted!"
        docker_mount=$(mount | grep "/var/lib/docker")
        
        add_finding "CRITICAL" "DOCKER_DIR_MOUNT" \
            "Docker storage directory mounted" \
            "$docker_mount" \
            "docker_dir_access"
    fi
}

# Check AppArmor/SELinux
check_security_modules() {
    print_header "Security Modules Status"
    
    # AppArmor
    if [ -f /sys/module/apparmor/parameters/enabled ]; then
        if grep -q "Y" /sys/module/apparmor/parameters/enabled; then
            print_info "AppArmor: Enabled"
            if [ -f /proc/1/attr/current ]; then
                profile=$(cat /proc/1/attr/current)
                echo -e "${CYAN}    └─ Profile: $profile${NC}"
                if echo "$profile" | grep -q "unconfined"; then
                    print_high "AppArmor profile is unconfined!"
                fi
            fi
        else
            print_medium "AppArmor: Disabled"
        fi
    fi
    
    # SELinux
    if command -v getenforce &> /dev/null; then
        status=$(getenforce 2>/dev/null)
        if [ "$status" = "Enforcing" ]; then
            print_info "SELinux: Enforcing"
        else
            print_medium "SELinux: $status"
        fi
    fi
    
    # Seccomp
    if [ -f /proc/1/status ]; then
        seccomp=$(grep Seccomp /proc/1/status | awk '{print $2}')
        if [ "$seccomp" = "0" ]; then
            print_high "Seccomp: Disabled"
        elif [ "$seccomp" = "2" ]; then
            print_info "Seccomp: Filtering mode"
        fi
    fi
}

# Check kernel version for known exploits
check_kernel_exploits() {
    print_header "Kernel Vulnerability Assessment"
    
    kernel=$(uname -r)
    print_info "Kernel version: $kernel"
    
    # Extract version numbers
    major=$(echo $kernel | cut -d. -f1)
    minor=$(echo $kernel | cut -d. -f2)
    patch=$(echo $kernel | cut -d. -f3 | cut -d- -f1)
    
    # Dirty COW (CVE-2016-5195)
    if [ "$major" -lt 4 ] || ([ "$major" -eq 4 ] && [ "$minor" -lt 8 ]); then
        print_critical "Kernel vulnerable to Dirty COW (CVE-2016-5195)!"
        echo -e "${LRED}    └─ Kernel < 4.8.3${NC}"
        
        add_finding "CRITICAL" "DIRTY_COW" \
            "Kernel vulnerable to Dirty COW (CVE-2016-5195)" \
            "Kernel version: $kernel" \
            "dirty_cow_exploit"
    elif [ "$major" -eq 4 ] && [ "$minor" -eq 8 ] && [ "$patch" -lt 3 ]; then
        print_critical "Kernel vulnerable to Dirty COW (CVE-2016-5195)!"
        
        add_finding "CRITICAL" "DIRTY_COW" \
            "Kernel vulnerable to Dirty COW (CVE-2016-5195)" \
            "Kernel version: $kernel" \
            "dirty_cow_exploit"
    fi
    
    # Other known vulnerabilities
    if [ "$major" -lt 5 ] || ([ "$major" -eq 5 ] && [ "$minor" -lt 8 ]); then
        print_high "Kernel may be vulnerable to various privilege escalation CVEs"
        echo -e "${RED}    └─ Consider checking exploit-db for kernel exploits${NC}"
    fi
}

# Check network exposure
check_network() {
    print_header "Network Configuration"
    
    # Check for Docker daemon port
    docker_port=$(netstat -tuln 2>/dev/null | grep ":2375\|:2376")
    if [ ! -z "$docker_port" ]; then
        print_critical "Docker daemon port exposed!"
        echo "$docker_port"
        
        add_finding "CRITICAL" "DOCKER_DAEMON_EXPOSED" \
            "Docker daemon port exposed on network" \
            "$docker_port" \
            "docker_api_exploit"
    fi
    
    # Check network namespace
    if [ -e /proc/1/ns/net ] && [ -e /proc/$$/ns/net ]; then
        ns1=$(readlink /proc/1/ns/net)
        ns2=$(readlink /proc/$$/ns/net)
        if [ "$ns1" = "$ns2" ]; then
            print_high "Sharing network namespace with host!"
            
            add_finding "HIGH" "SHARED_NET_NAMESPACE" \
                "Container shares network namespace with host" \
                "Network namespace: $ns1" \
                "host_network_access"
        fi
    fi
}

# Check for sensitive files
check_sensitive_files() {
    print_header "Sensitive Files & Credentials"
    
    # Check for cloud metadata services
    if timeout 1 curl -s http://169.254.169.254/latest/meta-data/ &>/dev/null; then
        print_critical "AWS metadata service accessible!"
        echo -e "${LRED}    └─ Can steal IAM credentials${NC}"
        
        add_finding "CRITICAL" "CLOUD_METADATA" \
            "AWS metadata service accessible" \
            "http://169.254.169.254/latest/meta-data/" \
            "cloud_metadata_steal"
    fi
    
    # Check for kubeconfig
    if [ -f /root/.kube/config ]; then
        print_high "Kubernetes config found: /root/.kube/config"
        add_finding "HIGH" "K8S_CONFIG" \
            "Kubernetes config file found" \
            "/root/.kube/config" \
            "k8s_config_exploit"
    fi
    
    if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
        print_high "Kubernetes service account token found!"
        add_finding "HIGH" "K8S_SA_TOKEN" \
            "Kubernetes service account token found" \
            "/var/run/secrets/kubernetes.io/serviceaccount/token" \
            "k8s_sa_exploit"
    fi
    
    # Check for Docker credentials
    if [ -f /root/.docker/config.json ]; then
        print_medium "Docker credentials found: /root/.docker/config.json"
    fi
}

# Check for container escape tools
check_tools() {
    print_header "Available Escape Tools"
    
    TOOLS="docker kubectl fdisk mount curl wget nc ncat netcat python python3 perl ruby gcc make"
    
    AVAILABLE_TOOLS=""
    for tool in $TOOLS; do
        if command -v $tool &> /dev/null; then
            print_info "$tool: $(which $tool)"
            AVAILABLE_TOOLS="$AVAILABLE_TOOLS $tool"
        fi
    done
}

# Check for writable areas
check_writable() {
    print_header "Writable Directories (Sample)"
    
    print_info "Checking common writable locations..."
    
    PATHS="/tmp /var/tmp /dev/shm / /etc /root /host"
    for path in $PATHS; do
        if [ -w "$path" 2>/dev/null ]; then
            if [ "$path" = "/" ] || [ "$path" = "/etc" ] || [ "$path" = "/root" ] || [ "$path" = "/host" ]; then
                print_high "Writable: $path"
            else
                print_info "Writable: $path"
            fi
        fi
    done
}

# Export findings to JSON
export_findings() {
    print_header "Exporting Findings"
    
    if [ ${#FINDINGS[@]} -eq 0 ]; then
        print_info "No critical or high severity findings to export"
        return
    fi
    
    # Create JSON output
    echo "{" > "$OUTPUT_FILE"
    echo "  \"scan_date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$OUTPUT_FILE"
    echo "  \"hostname\": \"$(hostname)\"," >> "$OUTPUT_FILE"
    echo "  \"kernel\": \"$(uname -r)\"," >> "$OUTPUT_FILE"
    echo "  \"findings\": [" >> "$OUTPUT_FILE"
    
    # Add findings
    for i in "${!FINDINGS[@]}"; do
        echo "    ${FINDINGS[$i]}" >> "$OUTPUT_FILE"
        if [ $i -lt $((${#FINDINGS[@]} - 1)) ]; then
            echo "," >> "$OUTPUT_FILE"
        else
            echo "" >> "$OUTPUT_FILE"
        fi
    done
    
    echo "  ]" >> "$OUTPUT_FILE"
    echo "}" >> "$OUTPUT_FILE"
    
    print_info "Findings exported to: $OUTPUT_FILE"
    echo -e "${LGREEN}    └─ Found ${#FINDINGS[@]} exploitable vulnerabilities${NC}"
    echo -e "${LGREEN}    └─ Use: ./dockerexploit.sh -r $OUTPUT_FILE${NC}"
}

# Generate escape suggestions
print_escape_suggestions() {
    print_header "Suggested Escape Techniques"
    
    echo -e "${CYAN}Based on findings, try these techniques:${NC}\n"
    
    echo -e "${YELLOW}1. Docker Socket Escape:${NC}"
    echo -e "   docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    
    echo -e "\n${YELLOW}2. Privileged Container + Device:${NC}"
    echo -e "   fdisk -l"
    echo -e "   mkdir /mnt/host"
    echo -e "   mount /dev/sda1 /mnt/host"
    
    echo -e "\n${YELLOW}3. CAP_SYS_ADMIN + cgroup release_agent:${NC}"
    echo -e "   # CVE-2022-0492 exploit"
    echo -e "   # Search for PoC on GitHub"
    
    echo -e "\n${YELLOW}4. Dirty COW (if vulnerable):${NC}"
    echo -e "   # Use public exploit from exploit-db"
    
    echo -e "\n${YELLOW}5. Check for CVE-2019-5736 (runC):${NC}"
    echo -e "   # If container can trigger docker exec"
    
    echo -e "\n${LGREEN}Remember: Only test on authorized systems!${NC}"
}

# Parse arguments
while getopts "o:h" opt; do
    case $opt in
        o)
            OUTPUT_FILE="$OPTARG"
            ;;
        h)
            echo "Usage: $0 [-o output_file]"
            echo "  -o: Specify output file for findings (default: dockerpeas_findings.json)"
            exit 0
            ;;
        *)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_banner
    
    check_container_environment
    check_docker_sock
    check_privileged_mode
    check_capabilities
    check_mounts
    check_security_modules
    check_kernel_exploits
    check_network
    check_sensitive_files
    check_tools
    check_writable
    export_findings
    print_escape_suggestions
    
    echo -e "\n${LGREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${LGREEN}Enumeration Complete!${NC}"
    echo -e "${LGREEN}═══════════════════════════════════════════════════════════${NC}\n"
}

# Run
main