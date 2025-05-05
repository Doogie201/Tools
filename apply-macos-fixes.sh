#!/usr/bin/env bash
set -euo pipefail

FILE="nextLevel3.sh"
BACKUP="${FILE}.bak.$(date +%Y%m%d%H%M%S)"
cp "\$FILE" "\$BACKUP"
echo "🔖 Backup: \$BACKUP"

# 1) Replace the awk‐based PrimaryService lookup with BSD‐sed version
perl -0777 -i -pe '
  s{
    # Section 2: Detect currently active service via scutil.*?fi\n
  }{
# 2) Detect currently active service via scutil
log INFO "Detecting active network service…"
PRIMARY_SERVICE_ID=\$(scutil <<<'open\nshow State:/Network/Global/IPv4\nd.show' 2>/dev/null \\
  | awk -F\': \' '/PrimaryService/ {gsub(/"/,""); print \$2}')

if [[ -n "\$PRIMARY_SERVICE_ID" ]]; then
  PRIMARY_SERVICE=\$(
    networksetup -listnetworkserviceorder \\
      | sed -n "1{h;d}; /Device: \$PRIMARY_SERVICE_ID/{x;p;q}; h" \\
      | sed -E 's/^\\([0-9]+\\)\\s*//'
  )
fi

  }gsx
' "\$FILE"

# 2) Swap out the old weeklyaudit load/remove for lint→bootout→bootstrap logic
perl -0777 -i -pe '
  s{
    run "launchctl remove com\.local\.weeklyaudit.*?launchctl load -w \\$HOME/Library/LaunchAgents/com\.local\.weeklyaudit\.plist"
  }{
# Weekly audit agent: lint, unload any existing, then bootstrap (or fallback to load)
run "plutil -lint \\$HOME/Library/LaunchAgents/com.local.weeklyaudit.plist"
run "launchctl list com.local.weeklyaudit && launchctl bootout gui/\\$(id -u) \\$HOME/Library/LaunchAgents/com.local.weeklyaudit.plist || true"
if launchctl bootstrap gui/\\$(id -u) \\$HOME/Library/LaunchAgents/com.local.weeklyaudit.plist; then
  log INFO "Bootstrapped weekly audit agent ✔"
else
  run "launchctl load -w \\$HOME/Library/LaunchAgents/com.local.weeklyaudit.plist"
fi

  }gsx
' "\$FILE"

echo "✅ Done—patched \$FILE (backup: \$BACKUP)"
