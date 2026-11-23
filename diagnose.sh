#!/usr/bin/env bash
# Collects everything needed to see why traffic isn't reaching WALLED DLP.
# Writes diagnose_report.txt next to this script. Nothing is sent anywhere.
cd "$(dirname "$0")"
OUT="diagnose_report.txt"
APP="$HOME/Library/Application Support/WalledDLP"
LOGS="$HOME/Library/Logs/WalledDLP"
sec() { echo; echo "===== $* ====="; }
{
sec "date / macOS"; date; sw_vers 2>/dev/null
sec "python / venv"
ls -d .venv 2>/dev/null && .venv/bin/python --version || echo "NO .venv - install.sh did not finish"
sec "walled_dlp status"; .venv/bin/python -m walled_dlp status 2>&1
sec "processes"; ps aux | grep -i "walled_dlp" | grep -v grep || echo "WALLED DLP is NOT running"
sec "listening ports 8765/8766"; lsof -nP -iTCP:8765 -iTCP:8766 -sTCP:LISTEN 2>&1
sec "PAC served"; curl -s -m 3 http://127.0.0.1:8766/proxy.pac | head -12 || echo "PAC not reachable"
sec "EFFECTIVE system proxy (scutil --proxy)"; scutil --proxy
sec "per-service proxy settings"
networksetup -listallnetworkservices 2>&1 | tail -n +2 | while IFS= read -r s; do
  s="${s#\*}"; echo "--- $s"; networksetup -getautoproxyurl "$s"; networksetup -getwebproxy "$s" | head -3; networksetup -getsecurewebproxy "$s" | head -3
done
sec "network service order"; networksetup -listnetworkserviceorder 2>&1 | head -30
sec "VPN / network extensions"; scutil --nc list 2>&1
systemextensionsctl list 2>&1 | grep -iE "network|filter|proxy|vpn" || true
sec "security / VPN agents running"
ps axo comm | grep -iE "zscaler|netskope|warp|cloudflare|globalprotect|pangps|anyconnect|cisco|forcepoint|umbrella|crowdstrike|falcon|sentinel|tailscale|wireguard|openvpn|fortinet|forti|jamf|kandji|mosyle|intune|proxy" | sort -u || echo "none matched"
sec "MDM enrollment"; profiles status -type enrollment 2>&1
sec "Chrome managed policy (proxy-related)"
for f in "/Library/Managed Preferences/com.google.Chrome.plist" "/Library/Managed Preferences/$USER/com.google.Chrome.plist"; do
  [ -f "$f" ] && { echo "$f"; plutil -p "$f" | grep -iE "proxy|QuicAllowed|DnsOverHttps" ; }
done
defaults read com.google.Chrome 2>/dev/null | grep -iE "proxy" || echo "no user-level Chrome proxy policy"
sec "CA in login keychain"
security find-certificate -c "WALLED DLP Local CA" -Z "$HOME/Library/Keychains/login.keychain-db" 2>&1 | grep -E "SHA-256|alis|labl" || echo "CA NOT FOUND in login keychain"
security dump-trust-settings 2>&1 | grep -A3 -i "walled" || echo "no user trust setting for WALLED CA"
sec "direct test THROUGH the proxy to chatgpt.com"
if [ -f "$APP/ca/walled-dlp-ca.pem" ]; then
  curl -s -m 20 -o /dev/null -x http://127.0.0.1:8765 --cacert "$APP/ca/walled-dlp-ca.pem" \
    -w "http_code=%{http_code} ssl_verify=%{ssl_verify_result}\n" -v https://chatgpt.com/ 2>&1 \
    | grep -E "issuer:|subject:|http_code|SSL certificate|error|< HTTP|cf-mitigated" | head -12
fi
sec "app log (last 60 lines)"; grep -v "DISCOVER GET .*/cdn/assets/" "$LOGS/walled-dlp.log" | tail -n 80 2>&1
sec "launchd logs"; tail -n 20 "$LOGS/launchd.err.log" 2>/dev/null
sec "recolour activity"; grep -E "RECOLOUR|FLOW ERROR|REJECTED|BYPASS" "$LOGS/walled-dlp.log" | tail -n 30
sec "last HTML injection dump"; cat "$LOGS/last_injection.txt" 2>/dev/null || echo "no injection dump yet"
sec "audit log (last 10)"; tail -n 10 "$LOGS/audit.jsonl" 2>&1
} > "$OUT" 2>&1
echo "Report written to $(pwd)/$OUT"
