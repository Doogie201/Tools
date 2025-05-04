#!/bin/zsh
###############################################################################
# nextLevel.sh – one-shot upgrade for M2 Pro Mac (Sequoia 15.4.1) + NordVPN  #
###############################################################################
set -euo pipefail
GREEN=$'\033[0;32m'; RESET=$'\033[0m'
log(){ echo "${GREEN}▶ $1${RESET}"; }

###############################################################################
# 0. Prereqs: Xcode CLT + Homebrew (ARM)                                      #
###############################################################################
if ! xcode-select -p &>/dev/null; then
  log "Installing Xcode Command-Line Tools…"
  xcode-select --install
  echo "⌘ ⇠ Wait for the pop-up, let it finish, rerun the script." && exit 1
fi

if [[ ! -d /opt/homebrew ]]; then
  log "Installing ARM Homebrew…"
  arch -arm64 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
fi
eval "$(/opt/homebrew/bin/brew shellenv)"

###############################################################################
# 1. Core formulae & casks                                                    #
###############################################################################
log "Installing formulae & apps…"
brew update >/dev/null
brew install docker docker-buildx docker-compose
brew install --cask \
  volta macs-fan-control raycast warp rectangle-pro \
  betterdisplay hummingbird \
  yubico-yubikey-manager yubico-authenticator \
  knockknock blockblock

###############################################################################
# 2. Developer setup: mise, Colima, aliases                                   #
###############################################################################
log "Configuring mise & toolchain…"
grep -q 'mise activate' ~/.zshrc || echo 'eval "$(mise activate zsh)"' >> ~/.zshrc
mise use -g node@lts python@3.12 rust@stable go@1.22

log "Starting Colima (vz backend, GPU passthrough is now automatic)…"
colima start --arch aarch64 --vm-type vz --vz-rosetta || true

###############################################################################
# 3. Power & fan profiles                                                     #
###############################################################################
echo 'alias lpm-on="sudo powermetrics -q --lowpowermode on"'  >> ~/.zshrc
echo 'alias lpm-off="sudo powermetrics -q --lowpowermode off"' >> ~/.zshrc

###############################################################################
# 4. Security hardening                                                       #
###############################################################################
log "Enabling stealth firewall & TouchID sudo…"
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
grep -q pam_tid /etc/pam.d/sudo || \
  echo "auth       sufficient     pam_tid.so" | sudo tee -a /etc/pam.d/sudo >/dev/null

log "Generating YubiKey SSH key (if a key is plugged)…"
if command -v ssh-keygen >/dev/null && \
   ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk -N "" \
     -O resident -O application=ssh:$(whoami)@$(hostname) 2>/dev/null; then
  log "✓  YubiKey SSH key created"
else
  log "→ No FIDO2 key detected; skipping SSH-SK keygen"
fi

###############################################################################
# 5. LaunchAgents (battery alert, weekly audit)                               #
###############################################################################
log "Installing LaunchAgents…"
mkdir -p ~/Library/LaunchAgents ~/Scripts ~/AuditLogs

# 5a. battery alert script
cat > ~/Scripts/battAlert.sh <<'EOF'
#!/bin/zsh
pct=$(pmset -g batt | awk '/Internal/ {gsub(/;/,""); print $3}')
if (( pct > 85 )); then
  osascript -e 'display notification "Unplug to preserve battery health" with title "Battery"'
fi
EOF
chmod +x ~/Scripts/battAlert.sh

cat > ~/Library/LaunchAgents/com.local.battalert.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.local.battalert</string>
  <key>ProgramArguments</key><array>
    <string>$HOME/Scripts/battAlert.sh</string>
  </array>
  <key>StartInterval</key><integer>1800</integer>
</dict></plist>
PLIST

launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.local.battalert.plist 2>/dev/null || true
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.local.battalert.plist
launchctl enable   gui/$(id -u)/com.local.battalert

# 5b. weekly audit
cat > ~/Scripts/weeklyAudit.sh <<'EOF'
#!/bin/zsh
~/Tools/macDeepDive.sh > ~/AuditLogs/$(date +%F_%H-%M).txt
cd ~/AuditLogs && git add . && git commit -m "audit $(date +%F)"
EOF
chmod +x ~/Scripts/weeklyAudit.sh

cat > ~/Library/LaunchAgents/com.local.weeklyaudit.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.local.weeklyaudit</string>
  <key>ProgramArguments</key><array>
    <string>$HOME/Scripts/weeklyAudit.sh</string>
  </array>
  <key>StartCalendarInterval</key>
    <dict><key>Weekday</key><integer>1</integer><key>Hour</key><integer>9</integer></dict>
</dict></plist>
PLIST

launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.local.weeklyaudit.plist 2>/dev/null || true
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.local.weeklyaudit.plist
launchctl enable   gui/$(id -u)/com.local.weeklyaudit

###############################################################################
# 6. NordVPN auto-launch                                                     #
###############################################################################
log "Launching NordVPN GUI (will auto-connect if you’ve enabled it)…"
open -a NordVPN || true

###############################################################################
# 7. Prune Logitech updaters                                                  #
###############################################################################
log "Removing Logitech launch agents…"
setopt nullglob
files=(/Library/LaunchAgents/com.logi.*)
if (( ${#files} )); then
  for p in "${files[@]}"; do
    sudo launchctl bootout system "$p" 2>/dev/null || true
    sudo rm -f "$p"
  done
  log "✓  Logitech agents removed"
else
  log "→ No Logitech agents found; skipping"
fi
unsetopt nullglob

###############################################################################
# 8. Finish                                                                   #
###############################################################################
log "Setup complete ✔  — open a new terminal or source ~/.zshrc"
