#!/usr/bin/env bash
# Checks Chrome-side reasons for bypassing the system proxy. Writes chrome_report.txt here.
cd "$(dirname "$0")"
OUT="chrome_report.txt"
CH="$HOME/Library/Application Support/Google/Chrome"
{
echo "===== Chrome processes / command-line flags ====="
ps axo pid,args | grep -E "Google Chrome( |$|\.app/Contents/MacOS/Google Chrome)" | grep -v -- "--type=" | grep -v grep | cut -c1-400
echo; echo "===== proxy-related flags on ANY Chrome process ====="
ps axo args | grep -i "chrome" | grep -oE -- "--(proxy|no-proxy|proxy-pac|proxy-server|winhttp|host-resolver)[^ ]*" | sort -u || true
echo; echo "===== Chrome version ====="
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --version 2>/dev/null
echo; echo "===== Profiles ====="
ls "$CH" 2>/dev/null | grep -E "^(Default|Profile [0-9]+)$"
echo; echo "===== Extensions with the 'proxy' permission (these override system proxy) ====="
/usr/bin/python3 - "$CH" <<'PY'
import json, sys, glob, os
base = sys.argv[1]
for prof in sorted(glob.glob(os.path.join(base, "Default")) + glob.glob(os.path.join(base, "Profile *"))):
    try:
        prefs = json.load(open(os.path.join(prof, "Secure Preferences"))) 
    except Exception:
        prefs = {}
    try:
        p2 = json.load(open(os.path.join(prof, "Preferences")))
    except Exception:
        p2 = {}
    print(f"--- {os.path.basename(prof)}  proxy pref: {p2.get('proxy', '(none)')}")
    settings = {**p2.get("extensions", {}).get("settings", {}), **prefs.get("extensions", {}).get("settings", {})}
    for ext_id, s in settings.items():
        m = s.get("manifest", {})
        perms = m.get("permissions", []) + m.get("optional_permissions", [])
        name = m.get("name", "?")
        ctrl = s.get("preferences", {}).get("proxy") or s.get("regular_only_preferences", {}).get("proxy")
        if "proxy" in perms or ctrl:
            state = "ENABLED" if s.get("state", 1) == 1 and not s.get("disable_reasons") else "disabled"
            print(f"   {ext_id}  {name}  [{state}]  controls_proxy_now={bool(ctrl)}")
    for d in glob.glob(os.path.join(prof, "Extensions", "*", "*", "manifest.json")):
        try:
            m = json.load(open(d))
        except Exception:
            continue
        perms = m.get("permissions", []) + m.get("optional_permissions", [])
        if "proxy" in perms:
            print(f"   (on disk) {d.split('/Extensions/')[1].split('/')[0]}  {m.get('name')}")
PY
echo; echo "===== Managed Chrome policies (any) ====="
ls -la "/Library/Managed Preferences/" 2>/dev/null
for f in /Library/Managed\ Preferences/com.google.Chrome.plist /Library/Managed\ Preferences/$USER/com.google.Chrome.plist /Library/Preferences/com.google.Chrome.plist; do
  [ -f "$f" ] && { echo "$f:"; plutil -p "$f" | head -40; }
done
defaults read com.google.Chrome 2>/dev/null | head -30
echo; echo "===== OpenVPN state ====="
ifconfig | grep -E "^utun|inet " | head -20
netstat -rn -f inet | head -15
} > "$OUT" 2>&1
echo "Report written to $(pwd)/$OUT"
