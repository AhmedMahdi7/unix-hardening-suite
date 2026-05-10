#!/bin/bash

# ============================================
# Program 1: UNIX Security Auditor (audit.sh)
# Scans system for vulnerabilities
# Outputs findings to findings.txt
# ============================================

OUTPUT_FILE="findings.txt"
TIMESTAMP=$(date)

# Clear previous findings
> "$OUTPUT_FILE"

echo "============================================"
echo " UNIX Security Audit"
echo " Started: $TIMESTAMP"
echo "============================================"
echo ""

# ============================================
# 1. SUID/SGID FILES CHECK
# ============================================
echo "[*] Checking SUID/SGID files..."

# Known safe SUID binaries
SAFE_SUID=(
    "/usr/bin/passwd"
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/pkexec"
    "/usr/bin/newgrp"
    "/usr/bin/gpasswd"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/fusermount"
    "/usr/bin/fusermount3"
    "/usr/bin/ping"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/libexec/polkit-agent-helper-1"
    "/usr/bin/chage"
    "/usr/bin/expiry"
    # Kali-specific safe SUID
    "/usr/bin/kismet_cap_nxp_kw41z"
    "/usr/bin/kismet_cap_linux_bluetooth"
    "/usr/bin/kismet_cap_nrf_51822"
    "/usr/bin/kismet_cap_nrf_52840"
    "/usr/bin/kismet_cap_ubertooth_one"
    "/usr/bin/kismet_cap_ti_cc_2540"
    "/usr/bin/kismet_cap_linux_wifi"
    "/usr/bin/kismet_cap_nrf_mousejack"
    "/usr/bin/kismet_cap_hak5_wifi_coconut"
    "/usr/bin/kismet_cap_rz_killerbee"
    "/usr/bin/kismet_cap_ti_cc_2531"
    "/usr/bin/ntfs-3g"
    "/usr/bin/rsh-redone-rlogin"
    "/usr/bin/rsh-redone-rsh"
    "/usr/sbin/pppd"
    "/usr/sbin/mount.nfs"
    "/usr/sbin/mount.cifs"
    "/usr/sbin/exim4"
    "/usr/lib/xorg/Xorg.wrap"
    "/usr/lib/chromium/chrome-sandbox"
    "/usr/lib/polkit-1/polkit-agent-helper-1"
    "/usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool"
)

echo "[SUID_CHECK]" >> "$OUTPUT_FILE"
find / -perm -4000 -type f 2>/dev/null | while read file; do
    safe=0
    for s in "${SAFE_SUID[@]}"; do
        if [ "$file" = "$s" ]; then
            safe=1
            break
        fi
    done
    if [ $safe -eq 0 ]; then
        echo "SUSPICIOUS_SUID:$file" >> "$OUTPUT_FILE"
        echo "  [!] SUSPICIOUS SUID: $file"
    fi
done

# SGID check
echo "" >> "$OUTPUT_FILE"
echo "[SGID_CHECK]" >> "$OUTPUT_FILE"
find / -perm -2000 -type f 2>/dev/null | while read file; do
    echo "SGID_FILE:$file" >> "$OUTPUT_FILE"
    echo "  [*] SGID: $file"
done

echo ""

# ============================================
# 2. WORLD-WRITABLE DIRECTORIES CHECK
# ============================================
echo "[*] Checking world-writable directories..."

echo "[WORLD_WRITABLE]" >> "$OUTPUT_FILE"
find / -type d -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" 2>/dev/null | while read dir; do
    if [ -k "$dir" ]; then
        echo "WORLD_WRITABLE_STICKY:$dir" >> "$OUTPUT_FILE"
        echo "  [*] World-writable (sticky): $dir"
    else
        echo "WORLD_WRITABLE_NO_STICKY:$dir" >> "$OUTPUT_FILE"
        echo "  [!] World-writable (NO STICKY): $dir"
    fi
done

echo ""

# ============================================
# 3. WEAK SUDOERS RULES CHECK
# ============================================
echo "[*] Checking sudoers rules..."

echo "[SUDOERS]" >> "$OUTPUT_FILE"

if [ -f /etc/sudoers ]; then
    # Check NOPASSWD (skip comments)
    grep -r "^[^#]*NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read line; do
        echo "NOPASSWD_RULE:$line" >> "$OUTPUT_FILE"
        echo "  [!] NOPASSWD RULE: $line"
    done

    # Check for dangerous binaries - skip comments
    DANGEROUS_BINS=("vim" "vi" "nano" "less" "more" "find" "perl" "python" "python3" "ruby" "awk" "man" "git" "ftp" "scp" "rsync")
    for bin in "${DANGEROUS_BINS[@]}"; do
        grep -rE "^[^#]*[^a-zA-Z]$bin[^a-zA-Z]" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read line; do
            echo "DANGEROUS_SUDO_BIN:$bin -> $line" >> "$OUTPUT_FILE"
            echo "  [!] DANGEROUS SUDO BIN: $bin in: $line"
        done
    done
fi

echo ""

# ============================================
# 4. OPEN PORTS CHECK
# ============================================
echo "[*] Checking open ports..."

echo "[OPEN_PORTS]" >> "$OUTPUT_FILE"
ss -tlnp 2>/dev/null | grep LISTEN | while read line; do
    port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
    process=$(echo "$line" | awk '{print $NF}')
    echo "LISTENING:$port:$process" >> "$OUTPUT_FILE"
    echo "  [*] Port $port open: $process"
done

echo ""

# ============================================
# 5. INSECURE CRON JOBS CHECK
# ============================================
echo "[*] Checking cron jobs..."

echo "[CRON_JOBS]" >> "$OUTPUT_FILE"

# Check /etc/crontab permissions
if [ -f /etc/crontab ]; then
    cron_perm=$(stat -c "%a" /etc/crontab)
    if [ "$cron_perm" != "600" ] && [ "$cron_perm" != "644" ]; then
        echo "CRONTAB_PERM:$cron_perm:/etc/crontab" >> "$OUTPUT_FILE"
        echo "  [!] /etc/crontab has weak permissions: $cron_perm"
    fi
fi

# Check cron directories
CRON_DIRS=("/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/cron.d")
for dir in "${CRON_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        find "$dir" -type f -perm -0002 2>/dev/null | while read file; do
            echo "WORLD_WRITABLE_CRON:$file" >> "$OUTPUT_FILE"
            echo "  [!] World-writable cron script: $file"
        done
        
        find "$dir" -type f ! -user root 2>/dev/null | while read file; do
            echo "CRON_NOT_ROOT:$file" >> "$OUTPUT_FILE"
            echo "  [!] Cron script not owned by root: $file"
        done
    fi
done

# Check user crontabs for world-readable issues
for user in $(cut -d: -f1 /etc/passwd); do
    cronfile="/var/spool/cron/crontabs/$user"
    if [ -f "$cronfile" ]; then
        cron_perm=$(stat -c "%a" "$cronfile" 2>/dev/null)
        if [ -n "$cron_perm" ] && [ "$cron_perm" != "600" ]; then
            echo "USER_CRON_PERM:$user:$cron_perm" >> "$OUTPUT_FILE"
            echo "  [!] User $user crontab has permissions: $cron_perm"
        fi
    fi
done

echo ""

# ============================================
# 6. OUTDATED PACKAGES CHECK
# ============================================
echo "[*] Checking outdated packages..."

echo "[OUTDATED_PACKAGES]" >> "$OUTPUT_FILE"

if command -v apt &> /dev/null; then
    apt list --upgradable 2>/dev/null | grep -v "Listing..." | while read line; do
        if [ -n "$line" ]; then
            pkg_name=$(echo "$line" | cut -d/ -f1)
            echo "OUTDATED:$pkg_name" >> "$OUTPUT_FILE"
        fi
    done
fi

if command -v yum &> /dev/null; then
    yum check-update 2>/dev/null | while read line; do
        pkg_name=$(echo "$line" | awk '{print $1}')
        if [ -n "$pkg_name" ] && [ "$pkg_name" != "Loading" ]; then
            echo "OUTDATED:$pkg_name" >> "$OUTPUT_FILE"
        fi
    done
fi

echo ""

# ============================================
# SUMMARY
# ============================================
echo "============================================"
echo " AUDIT COMPLETE"
echo "============================================"
suid_count=$(grep -c "SUSPICIOUS_SUID" "$OUTPUT_FILE")
ww_count=$(grep -c "WORLD_WRITABLE_NO_STICKY" "$OUTPUT_FILE")
sudo_count=$(grep -c "NOPASSWD_RULE\|DANGEROUS_SUDO_BIN" "$OUTPUT_FILE")
port_count=$(grep -c "LISTENING" "$OUTPUT_FILE")
cron_count=$(grep -c "WORLD_WRITABLE_CRON\|CRON_NOT_ROOT\|CRONTAB_PERM\|USER_CRON_PERM" "$OUTPUT_FILE")
pkg_count=$(grep -c "OUTDATED" "$OUTPUT_FILE")

echo "  Suspicious SUID files: $suid_count"
echo "  World-writable dirs (no sticky): $ww_count"
echo "  Weak sudoers rules: $sudo_count"
echo "  Open ports: $port_count"
echo "  Insecure cron issues: $cron_count"
echo "  Outdated packages: $pkg_count"
echo ""
echo "  Findings saved to: $OUTPUT_FILE"
