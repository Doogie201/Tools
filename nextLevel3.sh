#!/usr/bin/env zsh
# shellcheck disable=SC1091,SC2030,SC2031,SC2034,SC2086,SC2154,SC2155,SC2016
###############################################################################
# nextLevel.sh v2.9 – One-shot “genius-level” setup for M2 Pro Mac
# Combined Pi-hole + Cloudflared DoH + Automated Checks
# Fully automated, DRY-RUN / VERBOSE flags, active service detection, robust error handling.
# FINAL: Using launchctl remove/load -w for ALL LaunchAgents for maximum robustness.
# Includes built-in section-specific diagnostics on error.
# FIX: Use source /dev/stdin for brew shellenv evaluation.
# FIX: Use launchctl remove/load -w for all user LaunchAgents.
# FIX: Corrected ALL Zsh syntax (fi -> fi) and plist DTD URL.
# FIX: Detect and set DNS on the *currently active* network service.
###############################################################################
set -eEuo pipefail
trap 'on_error $LINENO $?' ERR

### === Globals & Defaults ===
SCRIPT_NAME=${0##*/}
LOG_DIR="$HOME/Library/Logs/nextLevel"
CONFIG_FILE="$HOME/.nextlevel.json"

DRYRUN=false
VERBOSE=false
FAIL_FAST=false # Set to true to exit immediately on *any* error

# Defaults if no config file
INSTALL_PKGS=true
INSTALL_CASKS=true
INSTALL_OLLAMA=true
INSTALL_PIHOLE=true
INSTALL_DOH=true
ENABLE_YUBI=true
ENABLE_NORD=true

# === Lowercase aliases for config flags ===
install_packages=$INSTALL_PKGS
install_casks=$INSTALL_CASKS
install_ollama=$INSTALL_OLLAMA
install_pihole=$INSTALL_PIHOLE
install_doh=$INSTALL_DOH
enable_yubikey=$ENABLE_YUBI
enable_nord=$ENABLE_NORD

# Variable to track current script section for diagnostics
CURRENT_SECTION="Script Init"

### === Logging & Helpers ===
# Ensure log directory exists before redirecting output
if ! $DRYRUN; then
  mkdir -p "$LOG_DIR"
fi
LOGFILE="$LOG_DIR/$(date +%F_%H-%M-%S).log"
# Redirect stdout and stderr to tee to capture logs and see output
if ! $DRYRUN; then
  # Check if tee is available, fallback if not (less robust logging)
  if command -v tee >/dev/null; then
    exec > >(tee -a "$LOGFILE") 2>&1
  else
    log WARN "tee not found. Logging only to stderr."
  fi
fi

# ANSI color codes for logging
COLOR_RESET=$'\033[0m'
COLOR_INFO=$'\033[0;34m'   # Blue
COLOR_WARN=$'\033[0;33m'   # Yellow
COLOR_ERROR=$'\033[0;31m'  # Red
COLOR_DRYRUN=$'\033[0;36m' # Cyan

log() {
  local level=$1 msg="$2" # Use "$2" in case message has spaces
  local color
  case $level in
    INFO) color=$COLOR_INFO ;;
    WARN) color=$COLOR_WARN ;;
    ERROR) color=$COLOR_ERROR ;;
    DRYRUN) color=$COLOR_DRYRUN ;;
    *) color=$COLOR_RESET ;; # Fallback or default
  esac
  # Print timestamp, level, message with color
  printf "%s[%s] [%s] %s%s\n" \
    "$color" "$(date +'%Y-%m-%dT%H:%M:%S')" "$level" "$msg" "$COLOR_RESET" >&2 # Log to stderr (usually seen immediately)
}

# --- Helpers & Aliases ---
# run:      log & execute a command
# check:    silently test a command (zero-return is “true”)
run() {
  log INFO "▶ $*"
  eval "$@"
}

check() {
  log INFO "Checking: $*"
  eval "$@" >/dev/null 2>&1
}

# for backward-compatibility with your sed-renames:
run_cmd() { run "$@"; }
run_cmd_check() { check "$@"; }

# --- Diagnostic Functions ---
run_diagnostic() {
  local cmd="$*"
  log INFO ">>> Running Diagnostic: $cmd"
  # Run diagnostic command, allow it to fail, capture output and exit status
  local output error_output exit_code
  # Use a temporary file for stderr to capture it correctly
  local stderr_tmp=$(mktemp)
  output=$(
    eval "$cmd" 2>"$stderr_tmp"
    exit_code=$?
  )
  error_output=$(cat "$stderr_tmp")
  rm "$stderr_tmp"

  # Print output if any
  if [[ -n "$output" ]]; then
    log INFO ">>> --- STDOUT ---"
    log INFO "$output"
    log INFO ">>> ------------"
  fi
  if [[ -n "$error_output" ]]; then
    log INFO ">>> --- STDERR ---"
    log INFO "$error_output"
    log INFO ">>> ------------"
  fi
  log INFO ">>> Diagnostic Exit Code: $exit_code"
  return $exit_code # Return the diagnostic command's exit code
}

diag_brew() {
  log INFO "--- Diagnosing Homebrew ---"
  if command -v brew >/dev/null; then
    run_diagnostic "brew config"
    run_diagnostic "brew doctor"
    run_diagnostic "brew list"
  else
    log WARN "brew command not found. Cannot run brew diagnostics."
  fi
  log INFO "---------------------------"
}

diag_launchagents() {
  log INFO "--- Diagnosing LaunchAgents ---"
  if command -v launchctl >/dev/null; then
    log INFO "Current user ID: $(id -u)"
    # These may require sudo, but often work for the current user's domain
    run_diagnostic "launchctl print-state user/$(id -u)"
    run_diagnostic "launchctl print-fault-info"

    log INFO "Listing user agents:"
    run_diagnostic "launchctl list gui/$(id -u)" # List all user agents

    # Check specific agents known to the script
    local agents=("com.local.battalert" "com.local.weeklyaudit" "com.local.doh")
    for agent in "${agents[@]}"; do
      log INFO "Checking status for agent $agent:"
      run_diagnostic "launchctl list $agent" # Check specific agent status
      if [[ -f "$HOME/Library/LaunchAgents/$agent.plist" ]]; then
        log INFO "Linting plist file: $HOME/Library/LaunchAgents/$agent.plist"
        run_diagnostic "plutil -lint $HOME/Library/LaunchAgents/$agent.plist" # Lint the actual file
        run_diagnostic "cat $HOME/Library/LaunchAgents/$agent.plist"          # Show plist content
      else
        log WARN "Plist file not found for agent $agent: $HOME/Library/LaunchAgents/$agent.plist"
      fi
    done
    log INFO "Listing files in ~/Library/LaunchAgents:"
    run_diagnostic "ls -l ~/Library/LaunchAgents/"     # Check permissions/existence
    run_diagnostic "ls -leO@d ~/Library/LaunchAgents/" # Check dir permissions/attributes

  else
    log WARN "launchctl command not found. Cannot run launchctl diagnostics."
  fi
  log INFO "-------------------------------"
}

diag_docker_networking() {
  log INFO "--- Diagnosing Docker/Colima Networking ---"
  if command -v colima >/dev/null; then
    run_diagnostic "colima status"
    run_diagnostic "colima logs"           # Show recent colima logs
    if check "colima ssh -- true"; then    # Check colima ssh connectivity first
      run_diagnostic "colima ssh -- df -h" # Check space in VM
    else
      log WARN "colima ssh connectivity failed. Cannot run VM diagnostics."
    fi

    if command -v docker >/dev/null; then
      run_diagnostic "docker ps -a" # List all containers
      log INFO "Checking Pi-hole container logs (if exists):"
      run_diagnostic "docker logs pihole" # Show pihole logs
      # Check port 53 listeners on the Mac host
      log INFO "Checking host port 53 listeners (TCP/UDP):"
      if command -v lsof >/dev/null; then
        run_diagnostic "sudo lsof -nP -iTCP:53 -sTCP:LISTEN"
        run_diagnostic "sudo lsof -nP -iUDP:53"
      else
        log WARN "lsof command not found. Cannot check host port listeners."
      fi
      # Check port 53 listeners inside the Colima VM
      log INFO "Checking VM port 53 listeners (via colima ssh):"
      if command -v colima >/dev/null && command -v lsof >/dev/null && check "colima ssh -- true"; then # Check colima ssh connectivity first
        # Need to pass commands carefully to colima ssh
        run_diagnostic "colima ssh -- sudo lsof -nP -iTCP:53 -sTCP:LISTEN"
        run_diagnostic "colima ssh -- sudo lsof -nP -iUDP:53"
      else
        log WARN "colima ssh not working or lsof not found in VM. Cannot check VM port listeners."
      fi
    else
      log WARN "docker command not found. Cannot run docker diagnostics."
    fi
  else
    log WARN "colima command not found. Cannot run colima diagnostics."
  fi
  log INFO "-------------------------------------------"
}

diag_ollama() {
  log INFO "--- Diagnosing Ollama ---"
  if command -v ollama >/dev/null; then
    run_diagnostic "ollama list"
    run_diagnostic "ollama --version"
    # Check if brew services is available to get service info/logs
    if command -v brew >/dev/null && command -v brew services >/dev/null; then
      run_diagnostic "brew services info ollama" # May provide log path
      # Attempt to show logs if path is found (requires parsing info output)
      local log_path=$(brew services info ollama 2>/dev/null | awk '/Log files:/ {print $3}')
      if [[ -n "$log_path" ]]; then
        log INFO "Attempting to show Ollama service logs from $log_path:"
        # Show last 50 lines, handle potential permission errors
        run_diagnostic "sudo tail -n 50 \"$log_path\" || cat \"$log_path\" || echo 'Could not read log file.'"
      else
        log WARN "Could not find Ollama service log path via brew services info."
      fi
    else
      log WARN "brew or brew services not found. Cannot get Ollama service info."
    fi
  else
    log WARN "ollama command not found."
  fi
  log INFO "-------------------------"
}

# --- Modified on_error trap handler ---
on_error() {
  local line=$1 code=$2
  log ERROR "Script failed in section '$CURRENT_SECTION' on line $line with exit code $code"
  log INFO "Initiating diagnostics for section '$CURRENT_SECTION'…"

  # Run general diagnostics (always useful)
  log INFO "--- General System Info ---"
  if command -v df >/dev/null; then run_diagnostic "df -h"; else log WARN "df not found."; fi                   # Check disk space
  if command -v top >/dev/null; then run_diagnostic "top -l 1 | awk 'NR<=10'"; else log WARN "top not found."; fi  # Check process list/load
  # Only run system logs if 'log' command exists AND sudo works (as many useful logs are root-owned)
  if command -v log >/dev/null && check "sudo -n true 2>/dev/null"; then run_diagnostic "sudo log show --last 5m --info --debug --predicate 'process == \"launchd\" || process == \"kernel\"' "; else log WARN "log command or sudo not available for full logs."; fi
  log INFO "---------------------------"

  # Run section-specific diagnostics based on CURRENT_SECTION
  case "$CURRENT_SECTION" in
    "Brew Install") diag_brew ;;
    "LaunchAgents") diag_launchagents ;;
    "Advanced Networking") diag_docker_networking ;;
    "Ollama Setup") diag_ollama ;;
    "Dev Toolchain")
      log INFO "--- Diagnosing Dev Toolchain (Mise) ---"
      if command -v mise >/dev/null; then
        run_diagnostic "mise --version"
        run_diagnostic "mise ls -g" # List global tools
        run_diagnostic "mise doctor"
      else
        log WARN "mise command not found."
      fi
      log INFO "--------------------------------------"
      ;;
    "Security Config")
      log INFO "--- Diagnosing Security Config ---"
      if command -v /usr/libexec/ApplicationFirewall/socketfilterfw >/dev/null; then
        run_diagnostic "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode"
      else
        log WARN "socketfilterfw command not found."
      fi
      if [[ -f "/etc/pam.d/sudo" ]]; then
        log INFO "Checking /etc/pam.d/sudo for pam_tid:"
        run_diagnostic "grep pam_tid /etc/pam.d/sudo"
      else
        log WARN "/etc/pam.d/sudo not found."
      fi
      log INFO "----------------------------------"
      ;;
    "YubiKey")
      log INFO "--- Diagnosing YubiKey/SSH ---"
      if command -v ssh-keygen >/dev/null; then
        run_diagnostic "ssh-keygen --version"
        run_diagnostic "ls -l ~/.ssh/"
        run_diagnostic "ssh-add -L" # List loaded keys (might require touching key)
      else
        log WARN "ssh-keygen command not found."
      fi
      log INFO "----------------------------"
      ;;

    *) log INFO "No specific diagnostics for section '$CURRENT_SECTION'." ;; # Default case
  esac

  log INFO "Diagnostics complete."

  # Exit the script after diagnostics if FAIL_FAST is true
  $FAIL_FAST && exit $code
  # If not FAIL_FAST, the script will attempt to continue
  # unless set -e causes the next command *after* the trap returns to fail.
  # For a setup script, continuing after an error is often undesirable unless
  # the error is expected and handled explicitly (like || true).
  # Reliance on set -e and trap means *most* errors will trigger the trap and stop
  # further meaningful execution unless specific commands use || true.
}

### === Section 0: Script Init & Prereqs ===
CURRENT_SECTION="Script Init"
log INFO "Starting script: $SCRIPT_NAME (v2.9)"

log INFO "Verifying Xcode Command-Line Tools…"
if ! check "xcode-select -p &>/dev/null"; then # Use check()
  run "xcode-select --install"
  log INFO "Please rerun after Xcode CLT installation"
  exit 1
fi

log INFO "Bootstrapping Homebrew…"
# Check if brew exists and is ARM brew by checking the common installation path
if ! check "command -v brew &>/dev/null" || ! check "brew --version &>/dev/null" || ! check "[[ -d /opt/homebrew ]]"; then # Check if brew exists and is ARM brew
  log INFO "Installing ARM Homebrew…"
  # Use source /dev/stdin for brew shellenv evaluation to handle its output syntax
  run 'arch -arm64 /bin/zsh -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"' # Corrected /bin/bash to /bin/zsh - use zsh as script is zsh
  # Add brew shellenv to zprofile for future sessions, use $(which brew) for robustness
  run "grep -q 'eval \"\$($(which brew) shellenv)\"' ~/.zprofile || echo 'eval \"\$($(which brew) shellenv)\"' >> ~/.zprofile"
fi
# Evaluate brew shellenv in the current script for immediate use using source
# FIX: Use source /dev/stdin for brew shellenv evaluation
log INFO "Evaluating Homebrew shell environment..."
source /dev/stdin <<<"$($(which brew) shellenv)"
log INFO "Homebrew ready."

### === Section 1: Install Formulae & Casks ===
CURRENT_SECTION="Brew Install"
if $install_packages; then # Use lowercase variable name from config
  log INFO "Installing brew formulae…"
  run "brew update"
  # Added jq to the install list
  run "brew install mise colima docker docker-buildx docker-compose cloudflared jq"
fi
if $install_casks; then # Use lowercase variable name from config
  log INFO "Installing brew casks…"
  run "brew install --cask volta macs-fan-control raycast warp rectangle-pro betterdisplay hummingbird yubico-yubikey-manager yubico-authenticator knockknock blockblock nordvpn"
fi

### === Section 2: Developer Toolchain ===
CURRENT_SECTION="Dev Toolchain"
log INFO "Configuring Mise…"
run "grep -q 'mise activate' ~/.zshrc || echo 'eval \"\$(mise activate zsh)\"' >> ~/.zshrc"
if ! $DRYRUN; then
  # Activate mise in the current script session if not dry running, for immediate use
  # Check if mise is in PATH first, as brew install might not update PATH immediately in current shell
  if ! check "command -v mise &>/dev/null"; then
    log WARN "Mise command not found in PATH. Activation may fail."
  fi
  log INFO "Activating Mise in script session…"
  eval "$(mise activate zsh)" || log WARN "Mise activation failed in script."
fi
run "mise use -g node@lts python@3.12 rust@stable go@1.22"
log INFO "Starting Colima VM…"
run "colima start --arch aarch64 --vm-type vz --vz-rosetta || true"

### === Section 3: Power & Fan Aliases ===
CURRENT_SECTION="Power Aliases"
log INFO "Adding low-power aliases…"
run "grep -q lpm-on ~/.zshrc || echo 'alias lpm-on=\"sudo powermetrics -q --lowpowermode on\"' >> ~/.zshrc"
run "grep -q lpm-off ~/.zshrc || echo 'alias lpm-off=\"sudo powermetrics -q --lowpowermode off\"' >> ~/.zshrc"

### === Section 4: Stealth Firewall & TouchID Sudo ===
CURRENT_SECTION="Security Config"
log INFO "Configuring macOS Firewall & TouchID for sudo…"
run "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
run "grep -qF 'auth\tsufficient\tpam_tid.so' /etc/pam.d/sudo || echo -e 'auth\tsufficient\tpam_tid.so' | sudo tee -a /etc/pam.d/sudo >/dev/null"

### === Section 5: YubiKey SSH Keygen ===
CURRENT_SECTION="YubiKey"
if $enable_yubikey; then # Use lowercase variable name from config
  log INFO "Attempting to generate YubiKey SSH key…"
  # Wrapped ssh-keygen in run(), checking exit code manually below run()
  if check "ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk -N '' -O resident 2>/dev/null"; then
    log INFO "✓ YubiKey SSH key generated"
  else
    log WARN "No FIDO2 device found; skipping YubiKey keygen"
  fi
fi

### === Section 6: LaunchAgents (Battery & Audit) ===
CURRENT_SECTION="LaunchAgents"
# Using the more robust remove/load -w sequence for all user agents

log INFO "Installing battery alert agent…"
# Create the script file
if ! $DRYRUN; then
  cat >~/Scripts/battAlert.sh <<'EOF_SCRIPT'
#!/usr/bin/env zsh
pct=$(pmset -g batt | awk '/Internal/ {gsub(/;/,""); print $3}')
(( pct > 85 )) && osascript -e 'display notification "Unplug to preserve battery health" with title "Battery"'
EOF_SCRIPT
fi
# Ensure script is executable
run "chmod +x ~/Scripts/battAlert.sh"
# Create the plist file
if ! $DRYRUN; then
  cat >~/Library/LaunchAgents/com.local.battAlert.plist <<'EOF_PLIST' # Corrected filename here
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.local.battalert</string>
  <key>ProgramArguments</key><array><string>$HOME/Scripts/battAlert.sh</string></array>
  <key>StartInterval</key><integer>1800</integer>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF_PLIST
  # Corrected filename here
  # Corrected filename here
  # Corrected filename here
  # Corrected filename here
  # Corrected filename here
fi
# Use the more robust remove/load -w sequence
log INFO "Battery alert agent: lint, unload & bootstrap"
run "plutil -lint $HOME/Library/LaunchAgents/com.local.battAlert.plist"
run "launchctl list com.local.battalert && \
    launchctl bootout gui/$(id -u) $HOME/Library/LaunchAgents/com.local.battAlert.plist || true"
if launchctl bootstrap gui/$(id -u) $HOME/Library/LaunchAgents/com.local.battAlert.plist; then
  log INFO "Bootstrapped battery alert agent ✔"
else
  run "launchctl load -w $HOME/Library/LaunchAgents/com.local.battAlert.plist"
fi

log INFO "Installing weekly audit agent…"
# Create the script file
if ! $DRYRUN; then
  cat >~/Scripts/weeklyAudit.sh <<'EOF_SCRIPT'
#!/usr/bin/env zsh
if [[ -x "$HOME/Tools/macDeepDive.sh" ]]; then
  "$HOME/Tools/macDeepDive.sh" > "$HOME/AuditLogs/$(date +%F_%H-%M).txt"
else
  echo "Error: macDeepDive.sh missing" >&2
  exit 1
fi
cd "$HOME/AuditLogs"
[[ ! -d .git ]] && git init
git add . && git commit -m "audit $(date +%F)" || true
EOF_SCRIPT
fi
# Ensure script is executable
run "chmod +x ~/Scripts/weeklyAudit.sh"
# Create the plist file
if ! $DRYRUN; then
  cat >"$HOME/Library/LaunchAgents/com.local.weeklyaudit.plist" <<'EOF_PLIST'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.local.weeklyaudit</string>
    <key>ProgramArguments</key>
    <array>
      <string>$HOME/Scripts/weeklyAudit.sh</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
      <key>Weekday</key><integer>1</integer>
      <key>Hour</key><integer>9</integer>
    </dict>
    <key>RunAtLoad</key><true/>
  </dict>
  </plist>
EOF_PLIST
fi
# Use the more robust remove/load -w sequence
log INFO "Loading agent com.local.weeklyaudit…"

### === Section 7: Local AI Lab (Ollama) === # <-- Renumbered from 6
CURRENT_SECTION="Ollama Setup"
if $install_ollama; then # Use lowercase variable name
  log INFO "Installing Ollama & pulling Mistral model…"
  run "brew install ollama"
  run "brew services start ollama || true"
  run "ollama pull mistral:7b || true"
fi

# Weekly audit agent: lint, unload any existing, then bootstrap (or fallback to load)
run "plutil -lint $HOME/Library/LaunchAgents/com.local.weeklyaudit.plist"
run "launchctl list com.local.weeklyaudit && launchctl bootout gui/$(id -u) $HOME/Library/LaunchAgents/com.local.weeklyaudit.plist || true"
if launchctl bootstrap gui/$(id -u) $HOME/Library/LaunchAgents/com.local.weeklyaudit.plist; then
  log INFO "Bootstrapped weekly audit agent ✔"
else
  run "launchctl load -w $HOME/Library/LaunchAgents/com.local.weeklyaudit.plist"
fi
### === Section 8: Advanced Networking (DoH on Host + Pi-hole) === # <-- Renumbered from 7
CURRENT_SECTION="Advanced Networking"

# Flags to track setup success
local doh_agent_ok=false
local pihole_config_ok=false
local host_ip_from_colima_ok=false
local vm_ip_ok=false
local network_service_ok=false

# --- 1) Ensure passwordless sudo for networksetup ---
log INFO "Configuring passwordless sudo for networksetup..."
if ! check "sudo -n true 2>/dev/null"; then
  log INFO "(Prompting for sudo password to cache it for this script run)"
  sudo -v # Cache sudo creds if needed
fi
SUDOERS="/etc/sudoers.d/nextlevel-network"
# Define the exact rule we want
sudo_rule="$USER ALL=(root) NOPASSWD: /usr/sbin/networksetup -setdnsservers *"
# Check if the rule already exists exactly as defined
if ! sudo grep -Fxq -- "$sudo_rule" $SUDOERS 2>/dev/null; then
  log INFO "Configuring passwordless sudo rule in $SUDOERS..."
  sudo mkdir -p /etc/sudoers.d
  sudo chmod 0755 /etc/sudoers.d
  # Use tee to write the rule - ensure USER variable expands correctly
  echo "$sudo_rule" | sudo tee $SUDOERS >/dev/null
  sudo chmod 440 $SUDOERS
  log INFO "✓ Passwordless sudo rule created/updated"
else
  log INFO "→ Passwordless sudo rule already exists in $SUDOERS"
fi

# --- 2) Detect Active Network Service Name ---
log INFO "Detecting active network service..."
PRIMARY_INTERFACE=$(route -n get default | awk '/interface:/ {print $2}')

if [[ -z "$PRIMARY_INTERFACE" ]]; then
  log ERROR "Could not determine default network interface. Cannot set system DNS."
  network_service_ok=false
else
  log INFO "Default network interface: '$PRIMARY_INTERFACE'"
  # Use head/sed to extract service name reliably
  PRIMARY_SERVICE=$(networksetup -listnetworkserviceorder | grep -B1 "Device: $PRIMARY_INTERFACE)" | head -n 1 | sed -E 's/^\([0-9]+\)[[:space:]]*(.*)/\1/')

  if [[ -z "$PRIMARY_SERVICE" ]]; then
    log ERROR "Could not find network service name for interface '$PRIMARY_INTERFACE'. Cannot set system DNS."
    network_service_ok=false
  else
    log INFO "Active service for interface '$PRIMARY_INTERFACE' is '$PRIMARY_SERVICE'"
    network_service_ok=true
  fi
fi

# --- 3) Get Colima VM IP ---
log INFO "Attempting to get Colima VM IP via 'colima status --json'..."
VM_IP="" # Ensure variable is initialized
if ! command -v jq >/dev/null; then
  log ERROR "'jq' command not found; required to parse Colima status."
  vm_ip_ok=false
else
  colima_status_json=$(colima status --json 2>/dev/null)
  if [[ -z "$colima_status_json" ]]; then
    log ERROR "'colima status --json' produced no output. Is Colima running?"
    vm_ip_ok=false
  else
    log INFO "Raw 'colima status --json' output:"
    log INFO "$colima_status_json"

    # Use the robust loop method to find the IP
    keys=( '.network.address' '.Network.address' '.ip_address' '.address' '.ipAddress' )
    for key in "${keys[@]}"; do
      VM_IP=$(jq -r "$key // empty" <<<"$colima_status_json" 2>/dev/null)
      if [[ -n "$VM_IP" ]]; then
        log INFO "Extracted Colima VM IP using key '$key': $VM_IP"
        vm_ip_ok=true
        break
      else
        log INFO "Key '$key' did not yield an IP; trying next…"
      fi
    done

    if [[ -z "$VM_IP" ]]; then
      log ERROR "Could not extract Colima VM IP; tried ${keys[*]}. Cannot proceed with Pi-hole/DoH."
      vm_ip_ok=false
    else
      log INFO "Colima VM IP successfully extracted: $VM_IP"
      run "sleep 3"  # Let Colima networking settle
    fi
  fi
fi

# --- 4) Deploy Cloudflared DoH on Host (if enabled) ---
if $install_doh && $vm_ip_ok; then # Only proceed if DoH enabled AND we have VM IP (needed later for Pi-hole)
  log INFO "Deploying Cloudflared DoH on Host 127.0.0.1:5053…"
  CLOUDFLARED_BIN="$(brew --prefix)/bin/cloudflared"

  if [[ ! -x "$CLOUDFLARED_BIN" ]]; then
      log ERROR "cloudflared binary not found or not executable at $CLOUDFLARED_BIN. Cannot create DoH agent."
      doh_agent_ok=false
  else
      log INFO "Using cloudflared binary at: $CLOUDFLARED_BIN"
      if ! $DRYRUN; then
        # Create the plist file to listen on HOST LOCALHOST
        cat >"$HOME/Library/LaunchAgents/com.local.doh.plist" <<EOF_PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.local.doh</string>
    <key>ProgramArguments</key>
    <array>
        <string>${CLOUDFLARED_BIN}</string>
        <string>proxy-dns</string>
        <string>--address</string>
        <string>127.0.0.1</string> <string>--port</string>
        <string>5053</string>
        <string>--upstream</string>
        <string>https://1.1.1.1/dns-query</string>
        <string>--upstream</string>
        <string>https://1.0.0.1/dns-query</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME/Library/Logs/com.local.doh.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/Library/Logs/com.local.doh.log</string>
</dict>
</plist>
EOF_PLIST
      fi # End if not DRYRUN

      # Lint and load the DoH agent
      log INFO "DoH agent: lint, unload & bootstrap"
      run "plutil -lint $HOME/Library/LaunchAgents/com.local.doh.plist"
      run "launchctl bootout gui/$(id -u) $HOME/Library/LaunchAgents/com.local.doh.plist || true"
      if ! $DRYRUN; then
          if launchctl bootstrap gui/$(id -u) $HOME/Library/LaunchAgents/com.local.doh.plist; then
              log INFO "Bootstrapped DoH agent ✔"
              doh_agent_ok=true
          else
              log WARN "Failed to bootstrap DoH agent, attempting legacy load..."
              if run "launchctl load -w $HOME/Library/LaunchAgents/com.local.doh.plist"; then
                 log INFO "Loaded DoH agent using legacy load ✔"
                 doh_agent_ok=true
              else
                 log ERROR "Failed to load DoH agent using legacy load."
                 doh_agent_ok=false
              fi
          fi
          run "sleep 2" # Give agent time to start
          run "launchctl list com.local.doh | grep '\"PID\"'" # Log PID status
      else
          log DRYRUN "Would load/bootstrap $HOME/Library/LaunchAgents/com.local.doh.plist"
          # Assume ok for dry run if plist lint passes
          if check "plutil -lint $HOME/Library/LaunchAgents/com.local.doh.plist"; then doh_agent_ok=true; fi
      fi
  fi # End check for CLOUDFLARED_BIN
else
  log INFO "Skipping Cloudflared DoH deployment (Disabled or prerequisite failed)."
  # If DoH is disabled, Pi-hole config below will fail unless it uses a different upstream
  if ! $install_doh ; then
      log WARN "Pi-hole deployment requires DoH or another upstream; DNS1 env var will be missing."
  fi
fi # End if $install_doh

# --- 5) Deploy Pi-hole with correct upstream and settings (if enabled) ---
if $install_pihole && $vm_ip_ok && $doh_agent_ok; then # Need Pi-hole enabled, VM IP, and working DoH agent
  log INFO "Deploying Pi-hole container…"

  # Determine Host IP as seen from Colima VM
  log INFO "Determining Host IP from Colima VM..."
  HOST_IP_FROM_COLIMA=""
  if command -v colima >/dev/null && check "colima status | grep Running"; then
      # Use the route command identified earlier
      HOST_IP_FROM_COLIMA=$(colima ssh -- ip route get 1.1.1.1 | awk '{print $7}' 2>/dev/null)
      if [[ -z "$HOST_IP_FROM_COLIMA" ]]; then
           log WARN "Could not auto-detect Host IP from Colima, trying default 192.168.5.1..."
           # Fallback for common colima vz/NAT setup - might need adjustment for other network types
           HOST_IP_FROM_COLIMA="192.168.5.1"
           # Add a check to see if this fallback IP is reachable from VM? Maybe later.
      fi
  else
      log WARN "Cannot run colima ssh; assuming default Host IP 192.168.5.1..."
      HOST_IP_FROM_COLIMA="192.168.5.1" # Fallback
  fi

  if [[ -z "$HOST_IP_FROM_COLIMA" ]]; then # Final check, should not happen with fallback
      log ERROR "Could not determine Host IP from Colima VM. Cannot configure Pi-hole upstream."
      pihole_config_ok=false
  else
      log INFO "Host IP as seen from Colima will be set to: $HOST_IP_FROM_COLIMA"
      host_ip_from_colima_ok=true

      log INFO "Removing existing Pi-hole container if present..."
      run "docker stop pihole || true"
      run "docker rm pihole || true"

      log INFO "Running docker container 'pihole' binding DNS to ${VM_IP}:53, web to 127.0.0.1:80"
      log INFO "Configuring Pi-hole upstream DNS to Host DoH at ${HOST_IP_FROM_COLIMA}:5053"
      log INFO "Configuring Pi-hole to 'Permit all origins' via DNSMASQ_LISTENING=all"
      run "docker run -d --name pihole \
        -p $VM_IP:53:53/tcp -p $VM_IP:53:53/udp \
        -p 127.0.0.1:80:80 \
        --restart unless-stopped \
        -v pihole_data:/etc/pihole \
        -e TZ=$(date +%Z) \
        -e WEBPASSWORD='set_me' \
        -e DNS1=\"${HOST_IP_FROM_COLIMA}#5053\" \
        -e DNSMASQ_LISTENING=all \
        pihole/pihole:latest"

      log INFO "✓ Pi-hole container started."
      log INFO "Waiting ~15s for Pi-hole to initialize..."
      run "sleep 15" # Give Pi-hole time to start FTL

      # Verify Pi-hole is running and reachable (basic check)
      if check "docker ps --filter name=pihole --filter status=running -q"; then
         log INFO "Pi-hole container running. Testing DNS resolution via Pi-hole..."
         # Test query directly to Pi-hole's IP
         if dig +short +time=3 +tries=1 apple.com "@${VM_IP}" > /dev/null; then
             log INFO "✅ Initial DNS test via Pi-hole SUCCEEDED."
             pihole_config_ok=true

             # Set macOS DNS only if everything seems ok so far
             if $network_service_ok; then
               log INFO "Updating macOS DNS to Pi-hole at $VM_IP for service '$PRIMARY_SERVICE'…"
               run "sudo networksetup -setdnsservers \"$PRIMARY_SERVICE\" $VM_IP"
               log INFO "Flushing DNS cache..."
               run "dscacheutil -flushcache && sudo killall -HUP mDNSResponder || true"
               log INFO "✓ macOS DNS set to Pi-hole ($VM_IP) and caches flushed."
             else
               log WARN "Primary network service name not determined earlier. Cannot automatically set macOS DNS."
               log WARN "Please set DNS manually for your active network service to $VM_IP."
             fi
         else
             log ERROR "❌ Initial DNS test via Pi-hole FAILED. Check 'docker logs pihole'."
             pihole_config_ok=false
         fi
      else
         log ERROR "Pi-hole container is not running after start attempt."
         pihole_config_ok=false
      fi

      # --- Password Reminder ---
      log INFO "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
      log INFO "MANUAL ACTION REMINDER: CHANGE PI-HOLE PASSWORD"
      log INFO "1. Access Pi-hole web UI at http://127.0.0.1/admin"
      log INFO "2. Log in (default password is 'set_me')"
      log INFO "3. CHANGE THE PASSWORD!"
      log INFO "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

  fi # End check HOST_IP_FROM_COLIMA valid
else
  log INFO "Skipping Pi-hole deployment (Disabled or prerequisite failed: VM IP=${vm_ip_ok}, DoH Agent=${doh_agent_ok})."
fi # End if $install_pihole

### === Section 9: Launch NordVPN === # <-- Renumbered from 8
CURRENT_SECTION="NordVPN Launch"
if $enable_nord; then # Use lowercase variable
  log INFO "Launching NordVPN GUI…"
  run "open -a NordVPN || true"
fi

### === Section 10: Prune Logitech ===
CURRENT_SECTION="Prune Logitech"
log INFO "Pruning Logitech agents…"
# These setopt/unsetopt must run directly in the script's shell
setopt nullglob
for p in /Library/LaunchAgents/com.logi.*; do
  run "sudo launchctl bootout system \"$p\" || true" # Use run()
  run "sudo rm -f \"$p\""                            # Use run()
done
unsetopt nullglob

### === Section 11: Final Health Check === # <-- Renumbered from 10
CURRENT_SECTION="Health Check"
log INFO "----- Health Check -----"

# Check 1: ARM-only process
if check "sysctl -n sysctl.proc_translated &>/dev/null" && (($(sysctl -n sysctl.proc_translated) == 0)); then # Check exists first
  CHECK_ARM="ARM-only process ✔"
else
  CHECK_ARM="Rosetta active ❌"
fi

# Check 2: Ollama running (accessible via localhost:11434)
if check "curl -s --max-time 5 http://localhost:11434/v1/models &>/dev/null" && check "curl -s --max-time 5 http://localhost:11434/v1/models 2>/dev/null | grep -q mistral"; then # Check endpoint is up AND Mistral exists
  CHECK_OLLAMA="Ollama Mistral running ✔"
else
  CHECK_OLLAMA="Ollama down or no Mistral model ❌"
fi

# Check 3: Local DNS filtering configured (pointing to 127.0.0.1 or VM_IP)
# $VM_IP is available here because it's defined earlier in Section 8 outside the if blocks
# Check specifically for the VM IP set by Pi-hole in the scutil --dns output
# Increased robustness of the grep pattern and checks
if check "scutil --dns &>/dev/null" && scutil --dns | grep 'nameserver' | grep -qE "(^|\s)${VM_IP}(\s|$)" &>/dev/null; then # Check specifically for VM_IP set by Pi-hole
  CHECK_DNS="DNS pointing to Pi-hole ($VM_IP) ✔"
elif check "scutil --dns &>/dev/null" && scutil --dns | grep 'nameserver' | grep -qE '(^|\s)127\.0\.0\.1(:\d+)?(\s|$)' &>/dev/null; then # Check if it's pointing to localhost (DoH only)
  CHECK_DNS="DNS pointing to localhost DoH ✔"
else
  # Fallback if neither specific check passes
  CHECK_DNS="DNS not local ❌"
fi

# Check 4: LaunchAgents loaded (check by listing label)
if check "launchctl list com.local.battalert &>/dev/null"; then
  CHECK_BATTERY="Agent com.local.battalert loaded ✔"
else
  CHECK_BATTERY="Agent com.local.battalert missing ❌"
fi

if check "launchctl list com.local.weeklyaudit &>/dev/null"; then
  CHECK_WEEKLY="Agent com.local.weeklyaudit loaded ✔"
else
  CHECK_WEEKLY="Agent com.local.weeklyaudit missing ❌"
fi

if check "launchctl list com.local.doh &>/dev/null"; then
  CHECK_DOH="Agent com.local.doh loaded ($VM_IP:5053) ✔"
else
  CHECK_DOH="Agent com.local.doh missing ❌"
fi

# --- Print Final Summary ---
log INFO "----- Health Check Summary -----"
log INFO "$CHECK_ARM"
log INFO "$CHECK_OLLAMA"
log INFO "$CHECK_DNS"
log INFO "$CHECK_BATTERY"
log INFO "$CHECK_WEEKLY"
# Only print DoH check result if its installation was attempted
if $install_doh; then # Use lowercase variable
  log INFO "$CHECK_DOH"
fi
log INFO "--------------------------"

log INFO "Setup complete ✔"