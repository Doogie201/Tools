#!/bin/zsh
###############################################################################
#  macDeepDive.sh  ·  Sequoia‑ready full audit (Apple Silicon)                #
#  Author: ChatGPT (rev‑Sequoia‑15.4.1)  ·  Last update: 2025‑05‑03           #
###############################################################################
set -euo pipefail
LOG="$HOME/Desktop/mac_audit_$(date +%Y-%m-%d_%H-%M).txt"
sudo_cmd() { sudo /usr/bin/env "$@"; }   # call sudo only when needed
header() { printf "\n%s\n%s\n" "### $1" "$(printf '─%.0s' {1..60})" >> "$LOG"; }

echo "macDeepDive — $(date)" | tee "$LOG"

###############################################################################
# 1. Hardware snapshot                                                        #
###############################################################################
header "1. Hardware"
system_profiler SPHardwareDataType | awk '/Chip|Total Number|Memory/' >>"$LOG"

###############################################################################
# 2. Display & GPU                                                            #
###############################################################################
header "2. Display / GPU"
system_profiler SPDisplaysDataType | awk '/Chipset|Resolution/' >>"$LOG"

###############################################################################
# 3. Thunderbolt / USB4 devices                                               #
###############################################################################
header "3. Thunderbolt / USB4"
system_profiler SPThunderboltDataType 2>/dev/null | \
grep -E 'Device Name:|Route String:' || echo "No external TB/USB4 devices" >>"$LOG"

###############################################################################
# 4. SSD wear (requires smartmontools)                                        #
###############################################################################
header "4. SSD SMART wear"
if command -v smartctl &>/dev/null; then
  DISK=$(diskutil list | awk '/Apple_APFS/ {print $NF; exit}')
  sudo_cmd smartctl -a "/dev/$DISK" | \
   awk '/Percentage Used/{gsub(/[^0-9]/,"",$3); wear=$3}
        /Available Spare/{gsub(/[^0-9]/,"",$3); spare=$3}
        END{
          if (wear=="") {print "⚠️  SMART attributes missing (Apple NVMe opaque)";}
          else {printf "Wear used: %s%%  |  Spare blocks: %s%%\n",
                       wear, (spare!=""?spare:"n/a")}
        }' >>"$LOG"
else
  echo "smartmontools missing — brew install smartmontools" >>"$LOG"
fi

###############################################################################
# 5. Battery health                                                           #
###############################################################################
header "5. Battery"
ioreg -r -c AppleSmartBattery | \
awk '/CycleCount/{cc=$3} /DesignCapacity/{dc=$3} /MaxCapacity/{mc=$3}
     END{printf "Cycles: %d   |  Health: %.1f%%\n", cc, mc/dc*100}' >>"$LOG"

###############################################################################
# 6. Thermal & power (sample once)                                            #
###############################################################################
header "6. Thermal (powermetrics sample)"
sudo_cmd powermetrics --samplers smc --samples 1 | \
awk '/CPU die temperature|GPU die temperature|CPU power/' >>"$LOG"

###############################################################################
# 7. Memory & swap                                                            #
###############################################################################
header "7. Memory & swap"
vm_stat | awk '
/Pageouts/   {po=$3}
/SwapUsage/  {gsub(/[()KMG ]/,"",$3); swap=$3}
/memorystatus:/ {mp=$3}
END{printf "Swap used: %.2f GB | Memory pressure: %d%% | Pageouts: %d\n",
      swap/1024/1024, mp, po}' >>"$LOG"

###############################################################################
# 8. Intel / Rosetta processes                                                #
###############################################################################
header "8. Intel (Rosetta) processes"
ps -Ao pid,comm,arch | awk '$3=="i386"{print}' >>"$LOG" || \
 echo "✅  No Intel processes running" >>"$LOG"

###############################################################################
# 9. LaunchAgents & LaunchDaemons (non‑Apple)                                 #
###############################################################################
header "9. Third‑party LaunchAgents/Daemons"
for dir in /Library/Launch* ~/Library/Launch*; do
  [[ -d $dir ]] || continue
  find "$dir" -maxdepth 1 -name "*.plist" | while read plist; do
    [[ $plist =~ com\.apple|org\.apple ]] && continue
    label=$(basename "$plist")
    enabled=$(defaults read "$plist" RunAtLoad 2>/dev/null || echo "1")
    [[ "$enabled" == "0" ]] && status="⏸ DISABLED" || status="▶️  ENABLED"
    echo "$status  $label  ($dir)" >>"$LOG"
  done
done

###############################################################################
# 10. Security baseline                                                       #
###############################################################################
header "10. Security baseline"
echo "Gatekeeper : $(spctl --status)"                               >>"$LOG"
echo "SIP        : $(csrutil status | awk '{print $NF}')"           >>"$LOG"
echo "FileVault  : $(fdesetup status | awk '{print $3,$4}')"        >>"$LOG"
fw_state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate)
echo "Firewall   : $fw_state"                                        >>"$LOG"
stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode)
echo "Stealth    : $stealth"                                         >>"$LOG"
profiles list 2>/dev/null | grep -c profileIdentifier | \
  awk '{print "Config profiles:",$1}'                               >>"$LOG"
dscl . -read /Groups/admin GroupMembership                          >>"$LOG"

###############################################################################
# 11. Bluetooth — currently connected                                         #
###############################################################################
header "11. Bluetooth (connected)"
system_profiler SPBluetoothDataType | awk '
/Connected: Yes/{c=1}
/Address:/{mac=$2}
/^\s+Name:/{name=$2}
c && /Services/{printf "%-20s  %s\n",name,mac; c=0}' >>"$LOG" \
 || echo "No active Bluetooth connections" >>"$LOG"

###############################################################################
# 12. Energy top‑talkers                                                      #
###############################################################################
header "12. Top 5 energy consumers"
ps -Ao pid,etime,comm,energy -r | head -6 >>"$LOG"

###############################################################################
# 13. Pending updates                                                         #
###############################################################################
header "13. Software updates"
if command -v mas &>/dev/null; then
  echo "-- Mac App Store --" >>"$LOG"
  mas outdated >>"$LOG" || echo "No App Store updates" >>"$LOG"
else
  echo "mas not installed — brew install mas" >>"$LOG"
fi
if command -v brew &>/dev/null; then
  echo "\n-- Homebrew cask updates --" >>"$LOG"
  brew outdated --cask >>"$LOG" || echo "No Brew cask updates" >>"$LOG"
fi

###############################################################################
# 14. Wi‑Fi scan (CoreWLAN, requires sudo)                                    #
###############################################################################
header "14. Wi‑Fi scan (CoreWLAN)"
swift_tmp=$(mktemp /tmp/wifiScan.XXXX.swift)
cat <<'EOF' >"$swift_tmp"
import CoreWLAN
if let iface = CWWiFiClient.shared().interface() {
  do {
    let nets = try iface.scanForNetworks(withName: nil)
    print("SSID                            RSSI  CHAN")
    print("----------------------------------------------")
    for n in nets.sorted(by: {$0.rssiValue > $1.rssiValue}) {
      let ssid = n.ssid ?? "<hidden>"
      let chan = n.wlanChannel()?.channelNumber ?? 0
      print(String(format:"%-30s  %-4d %3d", ssid, n.rssiValue, chan))
    }
  } catch {
    print("CoreWLAN scan failed: \\(error)")
  }
} else { print("No Wi‑Fi interface found.") }
EOF
sudo_cmd swift "$swift_tmp" >>"$LOG" 2>/dev/null
rm -f "$swift_tmp"

echo "\nAudit complete  →  $LOG"#!/bin/zsh
###############################################################################
#  macDeepDive.sh — full machine health report (Sequoia 15.4.1)              #
#  Run:  ./macDeepDive.sh                                                    #
#  Output: ~/Desktop/mac_audit_YYYY‑MM‑DD_HH‑MM.txt                           #
###############################################################################
set -euo pipefail
LOG="$HOME/Desktop/mac_audit_$(date +%Y-%m-%d_%H-%M).txt"

header() { printf "\n%s\n%s\n" "### $1" "$(printf '─%.0s' {1..60})" >>"$LOG"; }
r()      { sudo /usr/bin/env "$@" ; }       # wrapper for sudo calls

echo "macDeepDive — $(date)" | tee "$LOG"

###############################################################################
header "1. Hardware snapshot"
system_profiler SPHardwareDataType | grep -E 'Chip|Memory' >>"$LOG"

header "2. Display & GPU"
system_profiler SPDisplaysDataType | awk '/Chipset|Resolution/' >>"$LOG"

header "3. Thunderbolt / USB4 devices"
system_profiler SPThunderboltDataType | grep -E 'Device Name:|Route String:' >>"$LOG" \
  || echo "No Thunderbolt / USB4 peripherals" >>"$LOG"

###############################################################################
header "4. SSD wear (SMART)"
sudo_cmd smartctl -a "/dev/$DISK" | \
  awk '
    /Percentage Used/{wear=$3+0}
    /Available Spare[^T]/{spare=$3+0}
    END{printf "Wear used: %s%%  |  Spare blocks: %s%%\n", wear, spare}'


header "5. Battery health"
ioreg -r -c AppleSmartBattery | awk '
/CycleCount/{cc=$3}
/DesignCapacity/{dc=$3}
/MaxCapacity/{mc=$3}
END{printf "Cycles: %d   | Health: %.1f%%\n",cc,mc/dc*100}' >>"$LOG"

###############################################################################
header "6. Thermal & power (10 s sample)"
r powermetrics --samplers smc --samples 1 | \
 awk '/CPU die temperature|GPU die temperature|CPU power/' >>"$LOG"

header "7. Memory & swap status"
vm_stat | awk '
/Pageouts/ {po=$3}
/SwapUsage/ {gsub(/[()KMG ]/,"",$3); swap=$3}
/memorystatus:/ {mp=$3}
END{printf "Swap used: %.2f GB | Mem pressure: %d%% | Pageouts: %d pages\n",
swap/1024/1024, mp, po}' >>"$LOG"

header "8. Rosetta (Intel) processes"
ps -Ao pid,comm,arch | awk '$3=="i386"{print}' >>"$LOG" \
  || echo "✅  No Intel processes" >>"$LOG"

###############################################################################
header "9. Security baseline"
echo "Gatekeeper : $(spctl --status)"                                       >>"$LOG"
echo "SIP        : $(csrutil status | awk '{print $NF}')"                   >>"$LOG"
echo "FileVault  : $(fdesetup status | awk '{print $3,$4}')"                >>"$LOG"
echo "Firewall   : $(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate)" >>"$LOG"
echo "Stealth    : $(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode)" >>"$LOG"
profiles list 2>/dev/null | grep -c profileIdentifier | \
  awk '{print "Config profiles:",$1}'                                       >>"$LOG"
dscl . -read /Groups/admin GroupMembership                                  >>"$LOG"

###############################################################################
header "10. Top energy consumers (ps energy)"
ps -Ao pid,etime,comm,energy -r | head -6 >>"$LOG"

header "11. Bluetooth — connected devices"
system_profiler SPBluetoothDataType | awk '
/Connected: Yes/{c=1}
/Address:/{mac=$2}
/^\s+Name:/{name=$2}
c && /Services/{print name, mac; c=0}' >>"$LOG" \
  || echo "No active Bluetooth connections" >>"$LOG"

###############################################################################
header "12. Pending software updates"
if command -v mas &>/dev/null; then
  echo "-- Mac App Store --" >>"$LOG"
  mas outdated >>"$LOG" || echo "No App Store updates" >>"$LOG"
else
  echo "mas not installed (brew install mas)" >>"$LOG"
fi
if command -v brew &>/dev/null; then
  echo "\n-- Homebrew cask updates --" >>"$LOG"
  brew outdated --cask >>"$LOG" || echo "No Brew cask updates" >>"$LOG"
fi

echo -e "\nAudit complete. Report saved to $LOG"
