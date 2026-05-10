#!/bin/bash

# ============================================
# Program 2: Security Scoring System (score.sh)
# Reads findings.txt and calculates 0-100 score
# Usage: ./score.sh
# ============================================

INPUT_FILE="findings.txt"
SCORE=100
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ ! -f "$INPUT_FILE" ]; then
    echo -e "${RED}[ERROR] findings.txt not found. Run audit.sh first.${NC}"
    exit 1
fi

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}       SECURITY SCORE CALCULATION${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# ============================================
# CRITICAL ISSUES (-25 each)
# ============================================

# NOPASSWD ALL (full root without password)
NOPASSWD_ALL=$(grep -c "NOPASSWD.*ALL" "$INPUT_FILE" 2>/dev/null)
if [ "$NOPASSWD_ALL" -gt 0 ]; then
    for i in $(seq 1 $NOPASSWD_ALL); do
        SCORE=$((SCORE - 25))
        CRITICAL=$((CRITICAL + 1))
    done
    echo -e "  ${RED}[CRITICAL -25]${NC} $NOPASSWD_ALL NOPASSWD ALL rule(s) — full root without password"
fi

# Dangerous sudo binaries
DANGEROUS_SUDO=$(grep -c "DANGEROUS_SUDO_BIN" "$INPUT_FILE" 2>/dev/null)
if [ "$DANGEROUS_SUDO" -gt 0 ]; then
    for i in $(seq 1 $DANGEROUS_SUDO); do
        SCORE=$((SCORE - 25))
        CRITICAL=$((CRITICAL + 1))
    done
    echo -e "  ${RED}[CRITICAL -25]${NC} $DANGEROUS_SUDO dangerous sudo binary rule(s)"
fi

# World-writable cron scripts
CRON_WW=$(grep -c "WORLD_WRITABLE_CRON" "$INPUT_FILE" 2>/dev/null)
if [ "$CRON_WW" -gt 0 ]; then
    for i in $(seq 1 $CRON_WW); do
        SCORE=$((SCORE - 25))
        CRITICAL=$((CRITICAL + 1))
    done
    echo -e "  ${RED}[CRITICAL -25]${NC} $CRON_WW world-writable cron script(s)"
fi

# ============================================
# HIGH ISSUES (-15 each)
# ============================================

# Suspicious SUID files
SUID_COUNT=$(grep -c "SUSPICIOUS_SUID" "$INPUT_FILE" 2>/dev/null)
if [ "$SUID_COUNT" -gt 0 ]; then
    for i in $(seq 1 $SUID_COUNT); do
        SCORE=$((SCORE - 15))
        HIGH=$((HIGH + 1))
    done
    echo -e "  ${YELLOW}[HIGH -15]${NC} $SUID_COUNT suspicious SUID file(s)"
fi

# Limited NOPASSWD rules
LIMITED_NOPASSWD=$(grep "NOPASSWD" "$INPUT_FILE" 2>/dev/null | grep -v "NOPASSWD.*ALL" | wc -l)
if [ "$LIMITED_NOPASSWD" -gt 0 ]; then
    for i in $(seq 1 $LIMITED_NOPASSWD); do
        SCORE=$((SCORE - 15))
        HIGH=$((HIGH + 1))
    done
    echo -e "  ${YELLOW}[HIGH -15]${NC} $LIMITED_NOPASSWD limited NOPASSWD rule(s)"
fi

# ============================================
# MEDIUM ISSUES (-10 each)
# ============================================

# World-writable dirs without sticky bit
WW_NO_STICKY=$(grep -c "WORLD_WRITABLE_NO_STICKY" "$INPUT_FILE" 2>/dev/null)
if [ "$WW_NO_STICKY" -gt 0 ]; then
    for i in $(seq 1 $WW_NO_STICKY); do
        SCORE=$((SCORE - 10))
        MEDIUM=$((MEDIUM + 1))
    done
    echo -e "  ${YELLOW}[MEDIUM -10]${NC} $WW_NO_STICKY world-writable dir(s) without sticky bit"
fi

# Cron scripts not owned by root
CRON_NOT_ROOT=$(grep -c "CRON_NOT_ROOT" "$INPUT_FILE" 2>/dev/null)
if [ "$CRON_NOT_ROOT" -gt 0 ]; then
    for i in $(seq 1 $CRON_NOT_ROOT); do
        SCORE=$((SCORE - 10))
        MEDIUM=$((MEDIUM + 1))
    done
    echo -e "  ${YELLOW}[MEDIUM -10]${NC} $CRON_NOT_ROOT cron script(s) not owned by root"
fi

# Weak crontab permissions
CRONTAB_PERM=$(grep -c "CRONTAB_PERM" "$INPUT_FILE" 2>/dev/null)
if [ "$CRONTAB_PERM" -gt 0 ]; then
    for i in $(seq 1 $CRONTAB_PERM); do
        SCORE=$((SCORE - 10))
        MEDIUM=$((MEDIUM + 1))
    done
    echo -e "  ${YELLOW}[MEDIUM -10]${NC} $CRONTAB_PERM weak crontab permission(s)"
fi

# User crontab permission issues
USER_CRON=$(grep -c "USER_CRON_PERM" "$INPUT_FILE" 2>/dev/null)
if [ "$USER_CRON" -gt 0 ]; then
    for i in $(seq 1 $USER_CRON); do
        SCORE=$((SCORE - 10))
        MEDIUM=$((MEDIUM + 1))
    done
    echo -e "  ${YELLOW}[MEDIUM -10]${NC} $USER_CRON user crontab permission issue(s)"
fi

# ============================================
# LOW ISSUES (-5 each)
# ============================================

# Unexpected open ports (more than 10)
PORT_COUNT=$(grep -c "LISTENING" "$INPUT_FILE" 2>/dev/null)
if [ "$PORT_COUNT" -gt 10 ]; then
    EXTRA=$((PORT_COUNT - 10))
    for i in $(seq 1 $EXTRA); do
        SCORE=$((SCORE - 5))
        LOW=$((LOW + 1))
    done
    echo -e "  ${GREEN}[LOW -5]${NC} $EXTRA unexpected open port(s) (total: $PORT_COUNT)"
else
    echo -e "  ${GREEN}[OK]${NC} $PORT_COUNT open port(s) — acceptable"
fi

# Outdated packages
PKG_COUNT=$(grep -c "OUTDATED" "$INPUT_FILE" 2>/dev/null)
if [ "$PKG_COUNT" -gt 100 ]; then
    # Cap at 3 deductions max for outdated packages (reasonable penalty)
    PENALTY=3
    for i in $(seq 1 $PENALTY); do
        SCORE=$((SCORE - 5))
        LOW=$((LOW + 1))
    done
    echo -e "  ${GREEN}[LOW -5]${NC} $PENALTY deduction(s) for $PKG_COUNT outdated packages"
elif [ "$PKG_COUNT" -gt 50 ]; then
    PENALTY=2
    for i in $(seq 1 $PENALTY); do
        SCORE=$((SCORE - 5))
        LOW=$((LOW + 1))
    done
    echo -e "  ${GREEN}[LOW -5]${NC} $PENALTY deduction(s) for $PKG_COUNT outdated packages"
elif [ "$PKG_COUNT" -gt 10 ]; then
    PENALTY=1
    SCORE=$((SCORE - 5))
    LOW=$((LOW + 1))
    echo -e "  ${GREEN}[LOW -5]${NC} 1 deduction for $PKG_COUNT outdated packages"
else
    echo -e "  ${GREEN}[OK]${NC} $PKG_COUNT outdated package(s) — acceptable"
fi

# FINAL SCORE
# ============================================

if [ $SCORE -lt 0 ]; then
    SCORE=0
fi

TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "  Total issues found: ${RED}$TOTAL${NC}"
echo -e "    Critical: ${RED}$CRITICAL${NC}"
echo -e "    High:     ${YELLOW}$HIGH${NC}"
echo -e "    Medium:   ${YELLOW}$MEDIUM${NC}"
echo -e "    Low:      ${GREEN}$LOW${NC}"
echo ""

# Score with color
if [ $SCORE -ge 80 ]; then
    echo -e "  SECURITY SCORE: ${GREEN}$SCORE / 100${NC}"
elif [ $SCORE -ge 50 ]; then
    echo -e "  SECURITY SCORE: ${YELLOW}$SCORE / 100${NC}"
else
    echo -e "  SECURITY SCORE: ${RED}$SCORE / 100${NC}"
fi

echo -e "${CYAN}============================================${NC}"
echo ""
echo "  Score saved to: score.txt"
