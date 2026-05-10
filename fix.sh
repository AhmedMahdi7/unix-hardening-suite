#!/bin/bash

# ============================================
# Program 3: Automated Remediation (fix.sh)
# Reads findings.txt and fixes issues with user approval
# Usage: sudo ./fix.sh
# ============================================

INPUT_FILE="findings.txt"
BACKUP_DIR="backups_$(date +%Y%m%d_%H%M%S)"
FIXED_COUNT=0
SKIPPED_COUNT=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Must run as root (sudo ./fix.sh)${NC}"
    exit 1
fi

if [ ! -f "$INPUT_FILE" ]; then
    echo -e "${RED}[ERROR] findings.txt not found. Run audit.sh first.${NC}"
    exit 1
fi

mkdir -p "$BACKUP_DIR"
echo "Backups will be saved to: $BACKUP_DIR"
echo ""

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}     AUTOMATED REMEDIATION MODULE${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# ============================================
# FIX SUSPICIOUS SUID FILES
# ============================================
echo -e "${YELLOW}[*] Fixing suspicious SUID files...${NC}"

while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f2)
    if [ -f "$file" ]; then
        echo ""
        echo -e "  ${RED}[!] Suspicious SUID: $file${NC}"
        echo -e "  Current perms: $(stat -c '%A' "$file")"
        echo -n "  Remove SUID bit? [y/N]: "
        read answer < /dev/tty
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            cp "$file" "$BACKUP_DIR/" 2>/dev/null
            chmod u-s "$file"
            echo -e "  ${GREEN}[✓] SUID removed from $file${NC}"
            FIXED_COUNT=$((FIXED_COUNT + 1))
        else
            echo -e "  ${YELLOW}[✗] Skipped${NC}"
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        fi
    fi
done < <(grep "SUSPICIOUS_SUID" "$INPUT_FILE" 2>/dev/null)

# ============================================
# FIX WORLD-WRITABLE DIRECTORIES (NO STICKY)
# ============================================
echo ""
echo -e "${YELLOW}[*] Fixing world-writable directories without sticky bit...${NC}"

while IFS= read -r line; do
    dir=$(echo "$line" | cut -d: -f2)
    if [ -d "$dir" ]; then
        echo ""
        echo -e "  ${RED}[!] No sticky bit: $dir${NC}"
        echo -e "  Current perms: $(stat -c '%A' "$dir")"
        echo -n "  Add sticky bit? [y/N]: "
        read answer < /dev/tty
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            chmod +t "$dir"
            echo -e "  ${GREEN}[✓] Sticky bit added to $dir${NC}"
            FIXED_COUNT=$((FIXED_COUNT + 1))
        else
            echo -e "  ${YELLOW}[✗] Skipped${NC}"
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        fi
    fi
done < <(grep "WORLD_WRITABLE_NO_STICKY" "$INPUT_FILE" 2>/dev/null)

# ============================================
# FIX WEAK SUDOERS RULES
# ============================================
echo ""
echo -e "${YELLOW}[*] Fixing weak sudoers rules...${NC}"
echo -e "  ${RED}WARNING: sudoers fixes require manual review.${NC}"

while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f2)
    content=$(echo "$line" | cut -d: -f3-)
    echo ""
    echo -e "  ${RED}[!] NOPASSWD rule in: $file${NC}"
    echo -e "  Rule: $content"
    echo -n "  Comment out this rule? [y/N]: "
    read answer < /dev/tty
    if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file")" 2>/dev/null
        sed -i 's/^\([^#].*NOPASSWD.*\)/# REMEDIATED: \1/' "$file" 2>/dev/null
        echo -e "  ${GREEN}[✓] Rule commented out in $file${NC}"
        FIXED_COUNT=$((FIXED_COUNT + 1))
    else
        echo -e "  ${YELLOW}[✗] Skipped${NC}"
        SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
    fi
done < <(grep "NOPASSWD_RULE" "$INPUT_FILE" 2>/dev/null)

# ============================================
# FIX WORLD-WRITABLE CRON SCRIPTS
# ============================================
echo ""
echo -e "${YELLOW}[*] Fixing world-writable cron scripts...${NC}"

while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f2)
    if [ -f "$file" ]; then
        echo ""
        echo -e "  ${RED}[!] World-writable cron: $file${NC}"
        echo -e "  Current perms: $(stat -c '%A' "$file")"
        echo -n "  Set permissions to 755? [y/N]: "
        read answer < /dev/tty
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            cp "$file" "$BACKUP_DIR/" 2>/dev/null
            chmod 755 "$file"
            echo -e "  ${GREEN}[✓] Permissions set to 755 on $file${NC}"
            FIXED_COUNT=$((FIXED_COUNT + 1))
        else
            echo -e "  ${YELLOW}[✗] Skipped${NC}"
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        fi
    fi
done < <(grep "WORLD_WRITABLE_CRON" "$INPUT_FILE" 2>/dev/null)

# ============================================
# FIX CRON JOBS NOT OWNED BY ROOT
# ============================================
echo ""
echo -e "${YELLOW}[*] Fixing cron scripts not owned by root...${NC}"

while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f2)
    if [ -f "$file" ]; then
        owner=$(stat -c '%U' "$file")
        echo ""
        echo -e "  ${RED}[!] Cron owned by $owner: $file${NC}"
        echo -n "  Change ownership to root? [y/N]: "
        read answer < /dev/tty
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            chown root:root "$file"
            echo -e "  ${GREEN}[✓] Ownership changed to root for $file${NC}"
            FIXED_COUNT=$((FIXED_COUNT + 1))
        else
            echo -e "  ${YELLOW}[✗] Skipped${NC}"
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        fi
    fi
done < <(grep "CRON_NOT_ROOT" "$INPUT_FILE" 2>/dev/null)

# ============================================
# FIX WEAK CRONTAB PERMISSIONS
# ============================================
echo ""
echo -e "${YELLOW}[*] Fixing crontab permissions...${NC}"

while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f3)
    echo ""
    echo -e "  ${RED}[!] Weak permissions on: $file${NC}"
    echo -n "  Set permissions to 600? [y/N]: "
    read answer < /dev/tty
    if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
        chmod 600 "$file"
        echo -e "  ${GREEN}[✓] Permissions set to 600 on $file${NC}"
        FIXED_COUNT=$((FIXED_COUNT + 1))
    else
        echo -e "  ${YELLOW}[✗] Skipped${NC}"
        SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
    fi
done < <(grep "CRONTAB_PERM" "$INPUT_FILE" 2>/dev/null)

# ============================================
# FIX USER CRONTAB PERMISSIONS
# ============================================
echo ""
echo -e "${YELLOW}[*] Fixing user crontab permissions...${NC}"

while IFS= read -r line; do
    user=$(echo "$line" | cut -d: -f2)
    cronfile="/var/spool/cron/crontabs/$user"
    echo ""
    echo -e "  ${RED}[!] Weak permissions on $user's crontab${NC}"
    if [ -f "$cronfile" ]; then
        echo -n "  Set permissions to 600? [y/N]: "
        read answer < /dev/tty
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            chmod 600 "$cronfile"
            echo -e "  ${GREEN}[✓] Permissions set to 600 on $cronfile${NC}"
            FIXED_COUNT=$((FIXED_COUNT + 1))
        else
            echo -e "  ${YELLOW}[✗] Skipped${NC}"
            SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        fi
    fi
done < <(grep "USER_CRON_PERM" "$INPUT_FILE" 2>/dev/null)

# ============================================
# SUMMARY
# ============================================
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}     REMEDIATION COMPLETE${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "  ${GREEN}Fixed: $FIXED_COUNT${NC}"
echo -e "  ${YELLOW}Skipped: $SKIPPED_COUNT${NC}"
echo -e "  Backups saved to: $BACKUP_DIR"
echo ""
echo -e "  Run audit.sh again to see new score."
echo -e "${CYAN}============================================${NC}"
