#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# ================================================================
# PNPT Password Hunter
#
# Purpose:
#   Helper script for credential and context discovery during
#   Linux privilege escalation (manual-first workflow).
#
# What this script does NOT do:
#   - No exploitation
#   - No privilege escalation
#   - No password cracking
#
# Intended use:
#   Learning labs and authorized penetration tests only.
#
# Author: MB Cyberworks
# License: MIT
# ================================================================

VERSION="2.0"
SCRIPT_NAME="PNPT Password Hunter"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Configuration
OUTPUT_FILE="/tmp/password_hunt_$(date +%Y%m%d_%H%M%S).log"
QUICK_MODE=false
DEEP_MODE=false
QUIET_MODE=false

print_banner() {
    echo -e "${CYAN}"
    echo "================================================================"
    echo "   $SCRIPT_NAME v$VERSION - MB Cyberworks PNPT Series"
    echo "================================================================"
    echo -e "${NC}"
}

print_help() {
    echo -e "${YELLOW}Usage:${NC} $0 [OPTIONS]"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  -q, --quick     Quick scan (common locations only)"
    echo "  -d, --deep      Deep scan (comprehensive search)"
    echo "  -s, --silent    Quiet mode (minimal output)"
    echo "  -o, --output    Custom output file"
    echo "  -h, --help      Show this help message"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0                    # Standard scan (recommended)"
    echo "  $0 --quick            # Quick mode (common locations only)"
    echo "  $0 --deep --output /tmp/deep_scan.log"
    echo ""
}

log_output() {
    local message="$1"
    local level="$2"

    if [[ "$level" == "QUIET" && "$QUIET_MODE" == "true" ]]; then
        return
    fi

    echo -e "$message" | tee -a "$OUTPUT_FILE"
}

check_permissions() {
    log_output "\n${BLUE}[*] Current User Context:${NC}" "INFO"
    log_output "Host: $(hostname)" "INFO"
    log_output "Date: $(date)" "INFO"
    log_output "--------------------------------------" "INFO"
    log_output "User: $(whoami)" "INFO"
    log_output "UID: $(id -u)" "INFO"
    log_output "Groups: $(groups)" "INFO"
    log_output "Sudo privileges:" "INFO"
    timeout 3 sudo -l 2>/dev/null | head -10 | sed 's/^/  /' || log_output "  No sudo access or timeout" "INFO"
}

hunt_history_files() {
    log_output "\n${GREEN}[+] Hunting Password in History Files${NC}" "INFO"

    # User history files
    local history_files
    history_files=$(find /home -name ".*history" 2>/dev/null || true)
    local root_history="/root/.bash_history /root/.zsh_history /root/.fish_history"

    for hfile in $history_files $root_history; do
        if [[ -r "$hfile" ]]; then
            log_output "\n${YELLOW}[>] Checking: $hfile${NC}" "QUIET"

            # Look for suspicious commands
            local findings
            findings=$(grep -i "password\|passwd\|mysql\|ssh.*@\|ftp.*@\|su \|sudo \|psql" "$hfile" 2>/dev/null | head -20 || true)

            if [[ -n "$findings" ]]; then
                log_output "${RED}[!] SUSPICIOUS HISTORY ENTRIES FOUND:${NC}" "INFO"
                echo "$findings" | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
            fi
        fi
    done
}

hunt_config_files() {
    log_output "\n${GREEN}[+] Hunting Passwords in Configuration Files${NC}" "INFO"

    local config_dirs="/var/www /etc /opt /home"
    local config_extensions="*.conf *.config *.ini *.php *.env *.yml *.yaml *.json"

    for dir in $config_dirs; do
        if [[ -d "$dir" && -r "$dir" ]]; then
            log_output "${YELLOW}[>] Scanning $dir for config files...${NC}" "QUIET"

            for ext in $config_extensions; do
                local config_files
                config_files=$(find "$dir" -name "$ext" -readable 2>/dev/null | head -20 || true)

                for file in $config_files; do
                    log_output "${GRAY}[>] Checking: $file${NC}" "QUIET"

                    # Search for password patterns
                    local pass_findings
                    pass_findings=$(grep -i -E "(password|passwd|pwd|pass)\s*[:=]\s*[^'\"\s]+" "$file" 2>/dev/null | head -5 || true)

                    if [[ -n "$pass_findings" ]]; then
                        log_output "${RED}[!] CONFIG PASSWORDS:${NC}" "INFO"
                        echo "$pass_findings" | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
                    fi
                done
            done
        fi
    done
}

hunt_database_credentials() {
    log_output "\n${GREEN}[+] Hunting Database Credentials${NC}" "INFO"

    # WordPress configs
    local wp_configs
    wp_configs=$(find / -name "wp-config.php" -readable 2>/dev/null || true)
    for wp in $wp_configs; do
        if [[ -r "$wp" ]]; then
            log_output "${YELLOW}[>] WordPress config: $wp${NC}" "QUIET"
            local wp_creds
            wp_creds=$(grep -E "DB_(PASSWORD|USER|HOST)" "$wp" 2>/dev/null || true)
            if [[ -n "$wp_creds" ]]; then
                log_output "${RED}[!] WORDPRESS DB CREDS:${NC}" "INFO"
                echo "$wp_creds" | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
            fi
        fi
    done

    # Laravel .env files
    local env_files
    env_files=$(find / -name ".env" -readable 2>/dev/null || true)
    for env in $env_files; do
        if [[ -r "$env" ]]; then
            log_output "${YELLOW}[>] Environment file: $env${NC}" "QUIET"
            local env_creds
            env_creds=$(grep -i -E "(password|user|host|database)" "$env" 2>/dev/null || true)
            if [[ -n "$env_creds" ]]; then
                log_output "${RED}[!] ENVIRONMENT CREDS:${NC}" "INFO"
                echo "$env_creds" | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
            fi
        fi
    done

    # MySQL configs
    local mysql_configs="/etc/mysql/my.cnf /etc/my.cnf /root/.my.cnf"
    for mysql_conf in $mysql_configs; do
        if [[ -r "$mysql_conf" ]]; then
            log_output "${YELLOW}[>] MySQL config: $mysql_conf${NC}" "QUIET"
            local mysql_creds
            mysql_creds=$(grep -i "password" "$mysql_conf" 2>/dev/null || true)
            if [[ -n "$mysql_creds" ]]; then
                log_output "${RED}[!] MYSQL CREDS:${NC}" "INFO"
                echo "$mysql_creds" | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
            fi
        fi
    done
}

hunt_process_memory() {
    log_output "\n${GREEN}[+] Hunting Passwords in Process Memory${NC}" "INFO"

    # Environment variables
    log_output "${YELLOW}[>] Checking process environments...${NC}" "QUIET"
    local env_creds
    env_creds=$(cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i "password\|passwd\|mysql\|postgres" | head -10 || true)
    if [[ -n "$env_creds" ]]; then
        log_output "${RED}[!] PROCESS ENV CREDS:${NC}" "INFO"
        echo "$env_creds" | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
    fi

    # Command line arguments
    log_output "${YELLOW}[>] Checking process cmdlines...${NC}" "QUIET"
    local cmd_creds
    cmd_creds=$(cat /proc/*/cmdline 2>/dev/null | tr '\0' '\n' | grep -i "password\|passwd\|-p" | head -10 || true)
    if [[ -n "$cmd_creds" ]]; then
        log_output "${RED}[!] PROCESS CMD CREDS:${NC}" "INFO"
        echo "$cmd_creds" | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
    fi
}

hunt_shadow_files() {
    log_output "\n${GREEN}[+] Hunting Shadow Files and Hashes${NC}" "INFO"

    # Check shadow file accessibility
    if [[ -r "/etc/shadow" ]]; then
        log_output "${RED}[!] /etc/shadow is readable!${NC}" "INFO"
        local shadow_hashes
        shadow_hashes=$(cat /etc/shadow | head -10 || true)
        log_output "Shadow file contents:" "INFO"
        echo "$shadow_hashes" | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
    fi

    # Check passwd file
    if [[ -r "/etc/passwd" ]]; then
        log_output "${YELLOW}[>] /etc/passwd readable - checking for hashes${NC}" "QUIET"
        local passwd_hashes
        passwd_hashes=$(grep -v "^#" /etc/passwd | awk -F: '$2!="x" && $2!="" {print $1":"$2}' || true)
        if [[ -n "$passwd_hashes" ]]; then
            log_output "${RED}[!] PASSWD FILE HASHES:${NC}" "INFO"
            echo "$passwd_hashes" | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
        fi
    fi

    # Check for backup files
    local backup_files
    backup_files=$(find /var/backups /tmp -name "*passwd*" -o -name "*shadow*" 2>/dev/null || true)
    for backup in $backup_files; do
        if [[ -r "$backup" ]]; then
            log_output "${RED}[!] Backup shadow/passwd file: $backup${NC}" "INFO"
        fi
    done
}

hunt_logs() {
    log_output "\n${GREEN}[+] Hunting Passwords in Log Files${NC}" "INFO"

    local log_dirs="/var/log /var/logs"

    for logdir in $log_dirs; do
        if [[ -d "$logdir" && -r "$logdir" ]]; then
            log_output "${YELLOW}[>] Checking logs in $logdir...${NC}" "QUIET"

            # Look for log files containing password keywords
            local log_findings
            log_findings=$(find "$logdir" -name "*.log" -readable 2>/dev/null -exec grep -l -i "password\|passwd" {} \; | head -5 || true)

            for logfile in $log_findings; do
                local pass_entries
                pass_entries=$(grep -i "password\|passwd" "$logfile" 2>/dev/null | head -3 || true)
                if [[ -n "$pass_entries" ]]; then
                    log_output "${RED}[!] PASSWORDS IN LOG: $logfile${NC}" "INFO"
                    echo "$pass_entries" | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
                fi
            done
        fi
    done
}

hunt_ssh_keys() {
    log_output "\n${GREEN}[+] Hunting SSH Keys and Configs${NC}" "INFO"

    # SSH configs
    local ssh_configs
    ssh_configs=$(find /home -name "config" -path "*/.ssh/*" -readable 2>/dev/null || true)
    for ssh_conf in $ssh_configs; do
        log_output "${YELLOW}[>] SSH config: $ssh_conf${NC}" "QUIET"
        local ssh_info
        ssh_info=$(grep -i -E "host|hostname|user|password|identityfile" "$ssh_conf" 2>/dev/null || true)
        if [[ -n "$ssh_info" ]]; then
            log_output "${BLUE}[i] SSH CONFIG INFO:${NC}" "INFO"
            echo "$ssh_info" | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
        fi
    done

    # Private keys
    local private_keys
    private_keys=$(find /home -name "id_*" -path "*/.ssh/*" -not -name "*.pub" -readable 2>/dev/null || true)
    for key in $private_keys; do
        if [[ -r "$key" ]]; then
            log_output "${BLUE}[i] Private SSH key: $key${NC}" "INFO"

            # Check if password protected
            if grep -q "ENCRYPTED" "$key" 2>/dev/null; then
                log_output "    -> Password protected" "INFO"
            else
                log_output "    -> NOT password protected!" "INFO"
            fi
        fi
    done
}

hunt_interesting_files() {
    log_output "\n${GREEN}[+] Hunting Interesting Files${NC}" "INFO"

    # Common interesting file names
    local interesting_names="passwords.txt password.txt creds.txt credentials.txt pass.txt"
    interesting_names="$interesting_names notes.txt todo.txt readme.txt backup.sql dump.sql"
    interesting_names="$interesting_names config.php database.yml secrets.yml"

    for name in $interesting_names; do
        local found_files
        found_files=$(find /home /tmp /var -name "$name" -readable 2>/dev/null | head -5 || true)

        for file in $found_files; do
            log_output "${RED}[!] Interesting file found: $file${NC}" "INFO"

            # Show first few lines if readable
            if [[ -r "$file" ]]; then
                log_output "    Preview:" "INFO"
                head -5 "$file" 2>/dev/null | sed 's/^/        /' | tee -a "$OUTPUT_FILE" || true
            fi
        done
    done
}

create_summary() {
    log_output "\n${GREEN}[+] Summary of Findings${NC}" "INFO"

    if grep -q "\[!\]" "$OUTPUT_FILE"; then
        log_output "${RED}[!] IMPORTANT: Potential credentials or privilege-related findings detected.${NC}" "INFO"
        log_output "\n${YELLOW}Next steps (manual validation):${NC}" "INFO"
        log_output "1. Validate any credential lead in the right context (sudo, SSH, DB)" "INFO"
        log_output "2. Confirm access safely and document evidence (commands + output)" "INFO"
        log_output "3. Continue focused enumeration (sudo -l, SUID, cron, services)" "INFO"

    else
        log_output "${GREEN}[+] No obvious password findings in common locations.${NC}" "INFO"
        log_output "${YELLOW}[i] Consider:${NC}" "INFO"
        log_output "1. Running LinPEAS or LSE for deeper analysis" "INFO"
        log_output "2. Checking for SUID binaries or sudo misconfigurations" "INFO"
        log_output "3. Looking for other privilege escalation vectors" "INFO"
    fi
}

# Main execution function
main() {
    print_banner

    log_output "Starting password hunt at $(date)" "INFO"
    log_output "Scan mode: $([ "$QUICK_MODE" == "true" ] && echo "QUICK" || [ "$DEEP_MODE" == "true" ] && echo "DEEP" || echo "STANDARD")" "INFO"
    log_output "${YELLOW}[!] Note:${NC} Findings may include false positives. Always validate manually." "INFO"

    check_permissions
    hunt_history_files
    hunt_config_files
    hunt_database_credentials

    # Skip memory/log/interesting hunting in quick mode
    if [[ "$QUICK_MODE" != "true" ]]; then
        hunt_process_memory
        hunt_logs
        hunt_interesting_files
    fi

    # Deep mode additions
    if [[ "$DEEP_MODE" == "true" ]]; then
        hunt_shadow_files
        hunt_ssh_keys
    fi

    create_summary
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -q|--quick)
            QUICK_MODE=true
            shift
            ;;
        -d|--deep)
            DEEP_MODE=true
            shift
            ;;
        -s|--silent)
            QUIET_MODE=true
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_help
            exit 1
            ;;
    esac
done

# Create output directory if it doesn't exist
mkdir -p "$(dirname "$OUTPUT_FILE")" 2>/dev/null

# Check if running as root (warn only)
if [[ $(id -u) -eq 0 ]]; then
    echo -e "${YELLOW}[!] Warning:${NC} Running as root. This script is intended for post-foothold privilege escalation scenarios."
fi

# Run main function
main

exit 0
