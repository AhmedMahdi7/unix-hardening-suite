#!/bin/bash

# ============================================
# Program 4: HTML Report Generator (report.sh)
# Generates a before/after comparison HTML report
# Usage: ./report.sh
# ============================================

BEFORE_FINDINGS="findings_before.txt"
AFTER_FINDINGS="findings.txt"
BEFORE_SCORE="score_before.txt"
AFTER_SCORE="score.txt"
OUTPUT_HTML="security_report_$(date +%Y%m%d_%H%M%S).html"

GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}Generating HTML report...${NC}"

# Get scores
SCORE_BEFORE=$(grep "SCORE:" "$BEFORE_SCORE" 2>/dev/null | cut -d: -f2)
SCORE_AFTER=$(grep "SCORE:" "$AFTER_SCORE" 2>/dev/null | cut -d: -f2)
SCORE_BEFORE=${SCORE_BEFORE:-"?"}
SCORE_AFTER=${SCORE_AFTER:-"?"}

# Score colors
if [ "$SCORE_BEFORE" -ge 80 ] 2>/dev/null; then BEFORE_COLOR="#27ae60"
elif [ "$SCORE_BEFORE" -ge 50 ] 2>/dev/null; then BEFORE_COLOR="#f39c12"
else BEFORE_COLOR="#e74c3c"; fi

if [ "$SCORE_AFTER" -ge 80 ] 2>/dev/null; then AFTER_COLOR="#27ae60"
elif [ "$SCORE_AFTER" -ge 50 ] 2>/dev/null; then AFTER_COLOR="#f39c12"
else AFTER_COLOR="#e74c3c"; fi

# Count function
count() { grep -c "$1" "$2" 2>/dev/null || echo "0"; }

# Before counts
B_SUID=$(count "SUSPICIOUS_SUID" "$BEFORE_FINDINGS")
B_WW=$(count "WORLD_WRITABLE_NO_STICKY" "$BEFORE_FINDINGS")
B_NOPASSWD=$(count "NOPASSWD_RULE" "$BEFORE_FINDINGS")
B_DSUDO=$(count "DANGEROUS_SUDO_BIN" "$BEFORE_FINDINGS")
B_CRONWW=$(count "WORLD_WRITABLE_CRON" "$BEFORE_FINDINGS")
B_CRONNR=$(count "CRON_NOT_ROOT" "$BEFORE_FINDINGS")
B_PORTS=$(count "LISTENING" "$BEFORE_FINDINGS")
B_PKGS=$(count "OUTDATED" "$BEFORE_FINDINGS")

# After counts
A_SUID=$(count "SUSPICIOUS_SUID" "$AFTER_FINDINGS")
A_WW=$(count "WORLD_WRITABLE_NO_STICKY" "$AFTER_FINDINGS")
A_NOPASSWD=$(count "NOPASSWD_RULE" "$AFTER_FINDINGS")
A_DSUDO=$(count "DANGEROUS_SUDO_BIN" "$AFTER_FINDINGS")
A_CRONWW=$(count "WORLD_WRITABLE_CRON" "$AFTER_FINDINGS")
A_CRONNR=$(count "CRON_NOT_ROOT" "$AFTER_FINDINGS")
A_PORTS=$(count "LISTENING" "$AFTER_FINDINGS")
A_PKGS=$(count "OUTDATED" "$AFTER_FINDINGS")

# Status badge
badge() {
    if [ "$1" = "0" ]; then echo "CLEAN"; else echo "$1 FOUND"; fi
}

# Fixed status
fixed() {
    if [ "$1" != "0" ] && [ "$2" = "0" ]; then echo "FIXED";
    elif [ "$1" = "0" ] && [ "$2" = "0" ]; then echo "CLEAN";
    else echo "NOT FIXED"; fi
}

# Build row HTML
build_row() {
    local category="$1"
    local desc="$2"
    local b_val="$3"
    local a_val="$4"
    local fix_val="$5"
    
    local b_color="#e74c3c"; if [ "$b_val" = "CLEAN" ]; then b_color="#27ae60"; fi
    local a_color="#e74c3c"; if [ "$a_val" = "CLEAN" ]; then a_color="#27ae60"; fi
    local f_color="#e74c3c"
    if [ "$fix_val" = "FIXED" ]; then f_color="#27ae60"; fi
    if [ "$fix_val" = "CLEAN" ]; then f_color="#7f8c8d"; fi
    
    echo "<tr>"
    echo "<td><strong>$category</strong><br><small>$desc</small></td>"
    echo "<td style='color:$b_color; font-weight:bold;'>$b_val</td>"
    echo "<td style='color:$a_color; font-weight:bold;'>$a_val</td>"
    echo "<td style='color:$f_color; font-weight:bold;'>$fix_val</td>"
    echo "</tr>"
}

# Build full HTML
cat > "$OUTPUT_HTML" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UNIX Security Audit Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 40px;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding: 30px;
            background: #161b22;
            border-radius: 12px;
            border: 1px solid #30363d;
        }
        .header h1 { font-size: 28px; color: #58a6ff; margin-bottom: 10px; }
        .header p { color: #8b949e; font-size: 14px; }
        .score-comparison {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        .score-box {
            padding: 30px;
            border-radius: 12px;
            text-align: center;
            border: 2px solid #30363d;
            background: #161b22;
        }
        .score-box h3 {
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
            color: #8b949e;
        }
        .score-number { font-size: 64px; font-weight: bold; }
        .score-label { font-size: 18px; margin-top: 5px; color: #8b949e; }
        table {
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid #30363d;
        }
        th {
            background: #21262d;
            padding: 14px 16px;
            text-align: left;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #8b949e;
            border-bottom: 1px solid #30363d;
        }
        td {
            padding: 12px 16px;
            border-bottom: 1px solid #21262d;
            font-size: 14px;
        }
        tr:last-child td { border-bottom: none; }
        tr:hover { background: #1c2128; }
        small { color: #8b949e; font-weight: normal; }
        .footer {
            text-align: center;
            margin-top: 30px;
            color: #484f58;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>UNIX Security Audit Report</h1>
            <p>Automated Hardening Audit Tool — Before vs After Comparison</p>
            <p style="margin-top:8px;">Generated: $(date) | Hostname: $(hostname)</p>
        </div>

        <div class="score-comparison">
            <div class="score-box">
                <h3>BEFORE HARDENING</h3>
                <div class="score-number" style="color:$BEFORE_COLOR;">$SCORE_BEFORE</div>
                <div class="score-label">/ 100</div>
            </div>
            <div class="score-box">
                <h3>AFTER HARDENING</h3>
                <div class="score-number" style="color:$AFTER_COLOR;">$SCORE_AFTER</div>
                <div class="score-label">/ 100</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Vulnerability Category</th>
                    <th>Before</th>
                    <th>After</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                $(build_row "Suspicious SUID Files" "Privilege escalation risk" "$(badge $B_SUID)" "$(badge $A_SUID)" "$(fixed $B_SUID $A_SUID)")
                $(build_row "World-Writable Dirs (No Sticky)" "Unauthorized file modification" "$(badge $B_WW)" "$(badge $A_WW)" "$(fixed $B_WW $A_WW)")
                $(build_row "NOPASSWD Sudo Rules" "Passwordless root access" "$(badge $B_NOPASSWD)" "$(badge $A_NOPASSWD)" "$(fixed $B_NOPASSWD $A_NOPASSWD)")
                $(build_row "Dangerous Sudo Binaries" "GTFOBins escalation vectors" "$(badge $B_DSUDO)" "$(badge $A_DSUDO)" "$(fixed $B_DSUDO $A_DSUDO)")
                $(build_row "World-Writable Cron Scripts" "Persistence &amp; escalation" "$(badge $B_CRONWW)" "$(badge $A_CRONWW)" "$(fixed $B_CRONWW $A_CRONWW)")
                $(build_row "Cron Scripts Not Owned by Root" "Privilege escalation via cron" "$(badge $B_CRONNR)" "$(badge $A_CRONNR)" "$(fixed $B_CRONNR $A_CRONNR)")
                $(build_row "Open Ports" "Network attack surface" "$B_PORTS listening" "$A_PORTS listening" "$([ "$B_PORTS" = "$A_PORTS" ] && echo 'NO CHANGE' || echo 'REDUCED')")
                $(build_row "Outdated Packages" "Known CVEs &amp; exploits" "$B_PKGS packages" "$A_PKGS packages" "$([ "$B_PKGS" = "$A_PKGS" ] && echo 'NOT ADDRESSED' || echo 'REDUCED')")
            </tbody>
        </table>

        <div class="footer">
            <p>UNIX Hardening Suite | Operating Systems Security Project | $(date)</p>
        </div>
    </div>
</body>
</html>
EOF

echo ""
echo "============================================"
echo "  HTML REPORT GENERATED"
echo "============================================"
echo ""
echo "  Report: $OUTPUT_HTML"
echo "  Before score: $SCORE_BEFORE / 100"
echo "  After score:  $SCORE_AFTER / 100"
echo ""
echo "  Open: firefox $OUTPUT_HTML"
echo "============================================"
