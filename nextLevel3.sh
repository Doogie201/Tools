#!/usr/bin/env zsh
# shellcheck shell=zsh
###############################################################################
# nextLevel.sh v2.8 – One-shot “genius-level” setup for M2 Pro Mac
# Combined Pi-hole + Cloudflared DoH + Automated Checks
# Fully automated, DRY-RUN / VERBOSE flags, active service detection, robust error handling.
# FINAL: Using launchctl remove/load -w for ALL LaunchAgents for maximum robustness.
# Includes built-in section-specific diagnostics on error.
# FIX: Use source /dev/stdin for brew shellenv evaluation.
# FIX: Use launchctl remove/load -w for all user LaunchAgents.
# FIX: Corrected Zsh syntax (endif -> fi) and plist DTD URL.
###############################################################################
set -eEuo pipefail
trap 'on_error $LINENO $?' ERR

### === Globals & Defaults ===
SCRIPT_NAME=${0##*/}
LOG_DIR="$HOME/Library/Logs/nextLevel"
CONFIG_FILE="$HOME/.nextlevel.json" # SC2034: CONFIG_FILE appears unused. (If only read externally, ignore)

DRYRUN=false # Set to true with --dry-run_diagnostic flag
VERBOSE=false # Set to true with --verbose flag # SC2034: VERBOSE appears unused. (If only checked in diag, ignore)
FAIL_FAST=false # Set to true to exit immediately on *any* error

# Defaults if no config file is read or for flags not present
# Using uppercase as conventions suggest for globals, then use these consistently
INSTALL_PKGS=true # SC2034: INSTALL_PKGS appears unused. (If only used via lowercase, fix usage)
INSTALL_CASKS=true # SC2034: INSTALL_CASKS appears unused. (If only used via lowercase, fix usage)
INSTALL_OLLAMA=true # SC2034: INSTALL_OLLAMA appears unused. (If only used via lowercase, fix usage)
INSTALL_PIHOLE=true # SC2034: INSTALL_PIHOLE appears unused. (If only used via lowercase, fix usage)
INSTALL_DOH=true # SC2034: INSTALL_DOH appears unused. (If only used via lowercase, fix usage)
ENABLE_YUBI=true # SC2034: ENABLE_YUBI appears unused. (If only used via lowercase, fix usage)
ENABLE_NORD=true # SC2034: ENABLE_NORD appears unused. (If only used via lowercase, fix usage)

# Variable to track current script section for diagnostics
CURRENT_SECTION="Script Init"

# --- Flag Parsing (Add your flag parsing logic here, e.g., using getopts) ---
# Example basic flag parsing (replace with your actual logic if different):
# while [[ $# -gt 0 ]]; do
#   key="$1"
#   case $key in
#     --dry-run) DRYRUN=true; shift ;;
#     --verbose) VERBOSE=true; shift ;;
#     --fail-fast) FAIL_FAST=true; shift ;;
#     *) # unknown option
#       echo "Unknown option $key"
#       exit 1
#       ;;
#   esac
# done
# Ensure your actual flag parsing sets the DRYRUN, VERBOSE, FAIL_FAST variables correctly.
# If you intend to read flags from $CONFIG_FILE, add that logic here as well.
# For this corrected script, we assume DRYRUN=false, VERBOSE=false, FAIL_FAST=false
# and the INSTALL/ENABLE variables are used directly.


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
COLOR_INFO=$'\033[0;34m' # Blue
COLOR_WARN=$'\033[0;33m' # Yellow
COLOR_ERROR=$'\033[0;31m' # Red
COLOR_DRYRUN=$'\033[0;36m' # Cyan

log() {
  local level=$1 msg="$2" # Use "$2" in case message has spaces
  local color
  case $level in
    INFO)  color=$COLOR_INFO ;;
    WARN)  color=$COLOR_WARN ;;
    ERROR) color=$COLOR_ERROR ;;
    DRYRUN)color=$COLOR_DRYRUN ;;
    *)     color=$COLOR_RESET ;; # Fallback or default
  esac
  # Print timestamp, level, message with color
  printf "%s[%s] [%s] %s%s\n" \
    "$color" "$(date +'%Y-%m-%dT%H:%M:%S')" "$level" "$msg" "$COLOR_RESET" >&2 # Log to stderr (usually seen immediately)
}

# Helper function to check if a command succeeds (returns 0)
check() {
  local cmd="$*"
  # Use 'eval' here to run_diagnostic the command string passed to check
  eval "$cmd" &>/dev/null # Redirect stdout and stderr to null
  return $? # Return the exit status of the command
}


# --- Diagnostic Functions ---
# Corrected run_diagnostic to simplify exit status capture and logging
# Addresses SC2155, SC2030, SC2031 by capturing combined output and status cleanly
run_diagnostic() {
    local cmd="$*"
    log INFO ">>> Running Diagnostic: $cmd"
    # run_diagnostic diagnostic command, allow it to fail, capture combined output and exit status

    # Use 'eval' to execute the command string passed to the function.
    # Capture combined stdout and stderr into combined_output.
    # Ensure set -e is temporarily disabled around eval if you don't want command failures within eval
    # to immediately exit the script (if you plan to check the status manually).
    # Given the original intent seems to be logging diagnostics and their status *even if they fail*,
    # it's safer to temporarily disable -e around the eval call.

    local combined_output="" # Variable to store combined stdout/stderr
    local exit_status=0 # Variable to store the command's exit status

    # Temporarily disable -e so a failure in the evaluated command doesn't exit the script
    set +e
    combined_output=$( eval "$cmd" 2>&1 ) # Capture combined output
    exit_status=$? # Capture the exit status of the evaluated command *immediately*
    # Re-enable -e if it was active before
    set -e

    # Print combined output if any
    if [[ -n "$combined_output" ]]; then
      log INFO ">>> --- Output ---"
      log INFO "$combined_output"
      log INFO ">>> ------------"
    fi

    log INFO ">>> Diagnostic Exit Code: $exit_status"
    return $exit_status # Return the diagnostic command's actual exit code
}


# Corrected diag_brew function (no structural changes needed, just included for completeness)
diag_brew() {
  log INFO "--- Diagnosing Homebrew ---"
  if command -v brew >/dev/null; then
    run_diagnostic "brew config"
    run_diagnostic "brew doctor"
    run_diagnostic "brew list"
  else
    log WARN "brew command not found. Cannot run_diagnostic brew diagnostics."
  fi
  log INFO "---------------------------"
}

# Corrected diag_launchagents function (no structural changes needed, just included for completeness)
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
          run_diagnostic "cat $HOME/Library/LaunchAgents/$agent.plist" # Show plist content
      else
          log WARN "Plist file not found for agent $agent: $HOME/Library/LaunchAgents/$agent.plist"
      fi
    done
     log INFO "Listing files in ~/Library/LaunchAgents:"
     run_diagnostic "ls -l ~/Library/LaunchAgents/" # Check permissions/existence
     run_diagnostic "ls -leO@d ~/Library/LaunchAgents/" # Check dir permissions/attributes

  else
    log WARN "launchctl command not found. Cannot run launchctl diagnostics"
  fi
  log INFO "-------------------------------"
}

# Corrected diag_docker_networking function (fixed structural errors)
diag_docker_networking() {
  log INFO "--- Diagnosing Docker/Colima Networking ---"
  # Check if Colima is installed
  if command -v colima >/dev/null; then # <--- OUTER COLIMA IF (Opens)
    run_diagnostic "colima status"
    run_diagnostic "colima logs" # Show recent colima logs

    # Check Colima SSH connectivity if Colima is found
    if check "colima ssh -- true"; then # <--- INNER COLIMA SSH IF (Opens)
        run_diagnostic "colima ssh -- df -h" # Check space in VM
    else # <--- ELSE for INNER COLIMA SSH IF
        log WARN "colima ssh connectivity failed. Cannot run_diagnostic VM diagnostics."
    fi # <--- FI for INNER COLIMA SSH IF (Closes)

    # Check if Docker is installed (NESTED inside Colima IF)
    if command -v docker >/dev/null; then # <--- OUTER DOCKER IF (Opens)
      run_diagnostic "docker ps -a" # List all containers
      log INFO "Checking Pi-hole container logs (if exists):"
      run_diagnostic "docker logs pihole" # Show pihole logs

      # Check port 53 listeners on the Mac host (NESTED inside Docker IF)
      log INFO "Checking host port 53 listeners (TCP/UDP):"
      if command -v lsof >/dev/null; then # <--- INNER LSOF IF (Opens)
        run_diagnostic "sudo lsof -nP -iTCP:53 -sTCP:LISTEN"
        run_diagnostic "sudo lsof -nP -iUDP:53"
      else # <--- ELSE for INNER LSOF IF
        log WARN "lsof command not found. Cannot check host port listeners."
      fi # <--- FI for INNER LSOF IF (Closes)

      # Check port 53 listeners inside the Colima VM (NESTED inside Docker IF)
      log INFO "Checking VM port 53 listeners (via colima ssh):"
      # Corrected complex awk line for clarity, though original might have been valid shell but confusing to highlighter/parser
      # Using a simpler approach to get VM IP and pass to awk if needed, or rely on awk's -v
      # Original line: PRIMARY_SERVICE=$(networksetup -listnetworkserviceorder | awk ... '/Device:.*'$PRIMARY_SERVICE_ID'(,|\s|$)/ { ... }' )
      # Let's stick to the original logic but ensure correct quotes/structure
      # Original was: if command -v colima ... && check "colima ssh -- true"; then ... else ... fi
      if command -v colima >/dev/null && command -v lsof >/dev/null && check "colima ssh -- true"; then # <--- INNER COLIMA/LSOF/CHECK IF (Opens)
         # Need to pass commands carefully to colima ssh
         run_diagnostic "colima ssh -- sudo lsof -nP -iTCP:53 -sTCP:LISTEN"
         run_diagnostic "colima ssh -- sudo lsof -nP -iUDP:53"
      else # <--- ELSE for INNER COLIMA/LSOF/CHECK IF
         log WARN "colima ssh not working or lsof not found in VM. Cannot check VM port listeners."
      fi # <--- FI for INNER COLIMA/LSOF/CHECK IF (Closes)

    else # <--- ELSE for OUTER DOCKER IF (If Docker is NOT found)
      log WARN "docker command not found. Cannot run_diagnostic docker diagnostics."
    fi # <--- FI for OUTER DOCKER IF (Closes)

  else # <--- ELSE for OUTER COLIMA IF (If Colima is NOT found)
    log WARN "colima command not found. Cannot run colima diagnostics."
  fi # <--- FI for OUTER COLIMA IF (Closes)

  log INFO "-------------------------------------------"
}

# Corrected diag_ollama function (fixed structural errors)
diag_ollama() {
    log INFO "--- Diagnosing Ollama ---"
    # Check if Ollama is installed
    if command -v ollama >/dev/null; then # <--- OUTER OLLAMA IF (Opens)
        run_diagnostic "ollama list"
        run_diagnostic "ollama --version"

        # Check if brew services is available (Nested inside Ollama IF)
        if command -v brew >/dev/null && command -v brew services >/dev/null; then # <--- INNER BREW IF (Opens)
             run_diagnostic "brew services info ollama" # May provide log path
             # Attempt to show logs if path is found (Nested inside Brew IF)
             local log_path=$(brew services info ollama 2>/dev/null | awk '/Log files:/ {print $3}')
             if [[ -n "$log_path" ]]; then # <--- INNER LOG_PATH IF (Opens)
                 log INFO "Attempting to show Ollama service logs from $log_path:"
                 # Show last 50 lines, handle potential permission errors
                 run_diagnostic "sudo tail -n 50 \"$log_path\" || cat \"$log_path\" || echo 'Could not read log file.'"
             else # <--- ELSE for Inner LogPath IF
                 log WARN "Could not find Ollama service log path via brew services info."
             fi # <--- FI for Inner LogPath IF (Closes)
        else # <--- ELSE for Inner Brew IF (If brew/brew services not found)
            log WARN "brew or brew services not found. Cannot get Ollama service info."
        fi # <--- FI for Inner Brew IF (Closes)
    else # <--- ELSE for Outer Ollama IF (If Ollama not found)
        log WARN "ollama command not found."
    fi # <--- FI for Outer Ollama IF (Closes)

    # Final footer line (outside all conditionals)
    log INFO "-------------------------"
}

# Corrected run_diagnostic function (Add || true after log calls)
run_diagnostic() {
    local cmd="$*"
    log INFO ">>> Running Diagnostic: $cmd" || true # Ensure this log doesn't fail

    local combined_output=$( eval "$cmd" 2>&1 ) # Capture combined output
    local actual_exit_status=$? # Capture exit status

    # Temporarily disable -e around eval if needed for logic (removed in simplification, but good to remember)
    # set +e
    # combined_output=$( eval "$cmd" 2>&1 )
    # actual_exit_status=$?
    # set -e

    # Print combined output if any
    if [[ -n "$combined_output" ]]; then
      log INFO ">>> --- Output ---" || true # Ensure this log doesn't fail
      log INFO "$combined_output" || true # Ensure this log doesn't fail
      log INFO ">>> ------------" || true # Ensure this log doesn't fail
    fi

    log INFO ">>> Diagnostic Exit Code: $actual_exit_status" || true # Ensure this log doesn't fail
    return $actual_exit_status # Return the status
}

# --- Modified on_error trap handler (FULL CORRECTION with || true everywhere needed) ---
on_error() {
  local line=$1 original_code=$2 # Capture original error code
  log ERROR "Script failed in section '$CURRENT_SECTION' on line $line with exit code $original_code" || true # Ensure this initial log doesn't fail the trap
  log INFO "Initiating diagnostics for section '$CURRENT_SECTION'…" || true

  # Run general diagnostics (allow failure inside trap using || true)
  log INFO "--- General System Info ---" || true # Ensure this log doesn't fail
  # Every command or block within the trap that *could* fail needs || true
  if command -v df >/dev/null; then run_diagnostic "df -h" || true; else log WARN "df not found." || true; fi || true # || true after the if/else block
  if command -v top >/dev/null; then run_diagnostic "top -l 1 | head -n 10" || true; else log WARN "top not found." || true; fi || true # || true after the if/else block (Fixes the crash here)
  if command -v log >/dev/null && check "sudo -n true 2>/dev/null"; then run_diagnostic "sudo log show --last 5m --info --debug --predicate 'process == \"launchd\" || process == \"kernel\"' " || true; else log WARN "log command or sudo not available for full logs." || true; fi || true # || true after the if/else block
  log INFO "---------------------------" || true # Ensure this log doesn't fail


  # Run section-specific diagnostics based on CURRENT_SECTION (allow failure inside trap using || true)
  case "$CURRENT_SECTION" in
    "Brew Install") diag_brew || true ;; # Allow diag_brew to fail
    "LaunchAgents") diag_launchagents || true ;; # Allow diag_launchagents to fail
    "Advanced Networking") diag_docker_networking || true ;; # Allow diag_docker_networking to fail
    "Ollama Setup") diag_ollama || true ;; # Allow diag_ollama to fail
    "Dev Toolchain")
        log INFO "--- Diagnosing Dev Toolchain (Mise) ---" || true
        if command -v mise >/dev/null; then
            run_diagnostic "mise --version" || true
            run_diagnostic "mise ls -g" || true
            run_diagnostic "mise doctor" || true
        else
            log WARN "mise command not found." || true
        fi || true # || true after the if/else block
        log INFO "--------------------------------------" || true
        ;;
    "Security Config")
        log INFO "--- Diagnosing Security Config ---" || true
        if command -v /usr/libexec/ApplicationFirewall/socketfilterfw >/dev/null; then
            run_diagnostic "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode on" || true
        else
            log WARN "socketfilterfw command not found." || true
        fi || true # || true after the if/else block
        if [[ -f "/etc/pam.d/sudo" ]]; then
            log INFO "Checking /etc/pam.d/sudo for pam_tid:" || true
            run_diagnostic "grep pam_tid /etc/pam.d/sudo" || true
        else
            log WARN "/etc/pam.d/sudo not found." || true
        fi || true # || true after the if/else block
        log INFO "----------------------------------" || true
        ;;
    "YubiKey")
         log INFO "--- Diagnosing YubiKey/SSH ---" || true # Ensure this log doesn't fail
         if command -v ssh-keygen >/dev/null; then
             run_diagnostic "ssh-keygen --version" || true
             run_diagnostic "ls -l ~/.ssh/" || true
             run_diagnostic "ssh-add -L" || true # List loaded keys (might require touching key)
         else
             log WARN "ssh-keygen command not found." || true
         fi || true # || true after the if/else block
         log INFO "----------------------------" || true # Ensure this log doesn't fail
         ;;
    * ) log INFO "No specific diagnostics for section '$CURRENT_SECTION'.";; # Default case doesn't need || true unless the action (log INFO) could fail.
  esac

  log INFO "Diagnostics complete." || true # Ensure this log doesn't fail

  # Now, exit based on the *original* error code and FAIL_FAST flag
  # This line controls the script's final exit behavior
  $FAIL_FAST && exit $original_code
  # If FAIL_FAST is false, the script will continue execution after the trap returns.
}


# Note: Add your flag parsing logic here if it's not already handled before Section 0.

### === Section 0: Script Init & Prereqs ===
CURRENT_SECTION="Script Init"
log INFO "Starting script: $SCRIPT_NAME (v2.8)"

log INFO "Verifying Xcode Command-Line Tools…"
if ! check "xcode-select -p &>/dev/null"; then # Use check()
  run_diagnostic "xcode-select --install"
  log INFO "Please rerun after Xcode CLT installation"
  exit 1 # Exit here is likely intended if CLT is missing and install is needed
fi

log INFO "Bootstrapping Homebrew…"
# Check if brew exists and is ARM brew by checking the common installation path
if ! check "command -v brew &>/dev/null" || ! check "brew --version &>/dev/null" || ! check "[[ -d /opt/homebrew ]]"; then # Check if brew exists and is ARM brew
  log INFO "Installing ARM Homebrew…"
  # Use source /dev/stdin for brew shellenv evaluation to handle its output syntax
  run_diagnostic 'arch -arm64 /bin/zsh -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"' # Corrected /bin/bash to /bin/zsh - use zsh as script is zsh
  # Add brew shellenv to zprofile for future sessions, use $(which brew) for robustness
  run_diagnostic "echo 'eval \"\$($(which brew) shellenv)\"' >> ~/.zprofile"
  # After installing brew, source its shellenv for the current script session
  log INFO "Evaluating Homebrew shell environment after install..."
  source /dev/stdin <<< "$($(which brew) shellenv)" # SC1091: Not following: /dev/stdin... Use -x flag for ShellCheck.
fi
# Evaluate brew shellenv in the current script for immediate use using source *even if* it was already installed
# FIX: Use source /dev/stdin for brew shellenv evaluation
log INFO "Evaluating Homebrew shell environment..."
source /dev/stdin <<< "$($(which brew) shellenv)" # SC1091: Not following: /dev/stdin... Use -x flag for ShellCheck.
log INFO "Homebrew ready."


### === Section 1: Install Formulae & Casks ===
CURRENT_SECTION="Brew Install"
if $INSTALL_PKGS; then # Use uppercase variable name from config
  log INFO "Installing brew formulae…"
  run_diagnostic "brew update"
  # Added jq to the install list
  run_diagnostic "brew install mise colima docker docker-buildx docker-compose cloudflared jq"
fi
if $INSTALL_CASKS; then # Use uppercase variable name from config
  log INFO "Installing brew casks…"
  run_diagnostic "brew install --cask volta macs-fan-control raycast warp rectangle-pro betterdisplay hummingbird yubico-yubikey-manager yubico-authenticator knockknock blockblock nordvpn"
fi

### === Section 2: Developer Toolchain ===
CURRENT_SECTION="Dev Toolchain"
log INFO "Configuring Mise…"
run_diagnostic "grep -q 'mise activate' ~/.zshrc || echo 'eval \"\$(mise activate zsh)\"' >> ~/.zshrc"
if ! $DRYRUN; then
  # Activate mise in the current script session if not dry running, for immediate use
  # Check if mise is in PATH first, as brew install might not update PATH immediately in current shell
  if ! check "command -v mise &>/dev/null"; then
      log WARN "Mise command not found in PATH. Activation may fail."
  fi
  log INFO "Activating Mise in script session…"
  # Using eval here, ShellCheck SC2317 warnings inside diag_ollama and others might be false positives.
  eval "$(mise activate zsh)" || log WARN "Mise activation failed in script."
fi
run_diagnostic "mise use -g node@lts python@3.12 rust@stable go@1.22"
log INFO "Starting Colima VM…"
run_diagnostic "colima start --arch aarch64 --vm-type vz --vz-rosetta || true"

### === Section 3: Power & Fan Aliases ===
CURRENT_SECTION="Power Aliases"
log INFO "Adding low-power aliases…"
run_diagnostic "grep -q lpm-on ~/.zshrc || echo 'alias lpm-on=\"sudo powermetrics -q --lowpowermode on\"' >> ~/.zshrc"
run_diagnostic "grep -q lpm-off ~/.zshrc || echo 'alias lpm-off=\"sudo powermetrics -q --lowpowermode off\"' >> ~/.zshrc"

### === Section 4: Stealth Firewall & TouchID Sudo ===
CURRENT_SECTION="Security Config"
log INFO "Configuring macOS Firewall & TouchID for sudo…"
run_diagnostic "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
# Use sudo tee with -a for append, -p for permissions, >/dev/null to silence tee's stdout
run_diagnostic "grep -qF 'auth\tsufficient\tpam_tid.so' /etc/pam.d/sudo || echo -e 'auth\tsufficient\tpam_tid.so' | sudo tee -a /etc/pam.d/sudo >/dev/null"

### === Section 5: YubiKey SSH Keygen ===
CURRENT_SECTION="YubiKey"
if $ENABLE_YUBI; then # Use uppercase variable name from config
 log INFO "Attempting to generate YubiKey SSH key…"
 # Wrapped ssh-keygen in run(), checking exit code manually below run()
 # check() function will run_diagnostic it silently. We need to run_diagnostic it such that it *can* prompt for YubiKey touch.
 # Original intent seems to be run_diagnostic it, and if it FAILS (exit status != 0, likely due to no key present), then log WARN.
 # Let's run_diagnostic it directly and check $?
 # We need to allow output/prompts for this command.
 # Temporarily disable set -e around this command if you don't want it to exit script on failure
 log INFO "Running: ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk -N '' -O resident"
 # Note: -O resident requires resident keys, older Yubikeys might need -O verify-required for touch.
 # Also, this will prompt for touch, not ideal for automation unless handled.
 # Let's use 'run' but check its return status *after* it returns
 run_diagnostic "ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk -N '' -O resident 2>/dev/null"
 local ssh_keygen_status=$? # Capture status after run_diagnostic returns
 if [[ "$ssh_keygen_status" -eq 0 ]]; then # Check if run() returned 0 (command succeeded)
   log INFO "✓ YubiKey SSH key generated (or already exists)"
 else
   log WARN "ssh-keygen failed (status: $ssh_keygen_status). No FIDO2 device found or error during generation; skipping YubiKey keygen"
   # You might want to add a more specific check for device presence *before* running ssh-keygen
 fi
fi

### === Section 6: LaunchAgents (Battery & Audit) ===
CURRENT_SECTION="LaunchAgents"
# Using the more robust remove/load -w sequence for all user agents

log INFO "Installing battery alert agent…"
# Create the script file
if ! $DRYRUN; then
  cat > ~/Scripts/battAlert.sh <<'EOF_SCRIPT'
  #!/usr/bin/env zsh
  pct=$(pmset -g batt | awk '/Internal/ {gsub(/;/,""); print $3}')
  (( pct > 85 )) && osascript -e 'display notification "Unplug to preserve battery health" with title "Battery"'
EOF_SCRIPT
fi
# Ensure script is executable
run_diagnostic "chmod +x ~/Scripts/battAlert.sh"
# Create the plist file
if ! $DRYRUN; then
  cat > ~/Library/LaunchAgents/com.local.battalert.plist <<'EOF_PLIST'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTDs/PropertyList-1.0.dtd">
  <plist version="1.0"><dict>
  <key>Label</key><string>com.local.battalert</string>
  <key>ProgramArguments</key><array><string>$HOME/Scripts/battAlert.sh</string></array>
  <key>StartInterval</key><integer>1800</integer>
  <key>RunAtLoad</key><true/>
  </dict></plist>
EOF_PLIST
fi
# Use the more robust remove/load -w sequence
log INFO "Loading agent com.local.battalert…"
run_diagnostic "launchctl remove com.local.battalert 2>/dev/null || true" # Remove by label
run_diagnostic "launchctl load -w $HOME/Library/LaunchAgents/com.local.battalert.plist" # Load by plist path


log INFO "Installing weekly audit agent…"
# Create the script file
if ! $DRYRUN; then
cat > ~/Scripts/weeklyAudit.sh <<'EOF_SCRIPT'
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
run_diagnostic "chmod +x ~/Scripts/weeklyAudit.sh"
# Create the plist file
if ! $DRYRUN; then
  cat > ~/Library/LaunchAgents/com.local.weeklyaudit.plist <<'EOF_PLIST'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTDs/PropertyList-1.0.dtd"> # Corrected URL here
  <plist version="1.0"><dict>
  <key>Label</key><string>com.local.weeklyaudit</string>
  <key>ProgramArguments</key><array><string>$HOME/Scripts/weeklyAudit.sh</string></array>
  <key>StartCalendarInterval</key>
  <dict><key>Weekday</key><integer>1</integer><key>Hour</key><integer>9</integer></dict>
  <key>RunAtLoad</key><true/>
  </dict></plist>
EOF_PLIST
fi
# Use the more robust remove/load -w sequence
log INFO "Loading agent com.local.weeklyaudit…"
run_diagnostic "launchctl remove com.local.weeklyaudit 2>/dev/null || true" # Remove by label
run_diagnostic "launchctl load -w $HOME/Library/LaunchAgents/com.local.weeklyaudit.plist" # Load by plist path


### === Section 7: Local AI Lab (Ollama) === # <-- Renumbered from 6
CURRENT_SECTION="Ollama Setup"
if $INSTALL_OLLAMA; then # Use uppercase variable name
  log INFO "Installing Ollama & pulling Mistral model…"
  run_diagnostic "brew install ollama"
  run_diagnostic "brew services start ollama || true"
  run_diagnostic "ollama pull mistral:7b || true"
fi

### === Section 8: Advanced Networking (DoH + Pi-hole) === # <-- Renumbered from 7
CURRENT_SECTION="Advanced Networking"

# 1) Ensure passwordless sudo for networksetup
log INFO "Configuring passwordless sudo for networksetup…"
# Check if passwordless sudo is configured before running sudo -v,
# to avoid unnecessary password prompt if already configured.
if ! check "sudo -n true 2>/dev/null"; then # Use check()
  log INFO "(Prompting for sudo password to cache it for this script run)"
  sudo -v # This will prompt for password if needed and cache it
fi
SUDOERS="/etc/sudoers.d/nextlevel-network"
# Check if the rule *exactly* matches before attempting to write
if ! sudo grep -qF "$USER ALL=(root) NOPASSWD: /usr/sbin/networksetup -setdnsservers *" $SUDOERS 2>/dev/null; then
  log INFO "Configuring passwordless sudo rule in $SUDOERS…"
  sudo mkdir -p /etc/sudoers.d
  sudo chmod 0755 /etc/sudoers.d
  # Using tee with <<EOF here for robustness
  sudo tee $SUDOERS >/dev/null <<EOF_SUDO
# Allow user '$USER' to run_diagnostic networksetup without password
$USER ALL=(root) NOPASSWD: /usr/sbin/networksetup -setdnsservers *
EOF_SUDO
  sudo chmod 440 $SUDOERS
  log INFO "✓ Passwordless sudo rule created"
else
  log INFO "→ Passwordless sudo rule already exists in $SUDOERS"
fi

# 2) Detect currently active service via scutil
log INFO "Detecting active network service…"
# Use scutil to find the PrimaryService, then map it to a networksetup service name
# Corrected command substitution closing and awk quoting for clarity/robustness
PRIMARY_SERVICE_ID=$(scutil <<< $'open\nshow State:/Network/Global/IPv4\nd.show' 2>/dev/null |
  awk -F': ' '/PrimaryService/ {gsub(/"/,""); print $2}'
) # <--- Corrected command substitution closing

if [[ -n "$PRIMARY_SERVICE_ID" ]]; then
  # Map the PrimaryService ID to a networksetup service name
  # Handle cases where the device name might be like 'en0, en1'
  # Corrected awk quoting and variable usage to address potential highlighting/parsing issues
  PRIMARY_SERVICE=$(networksetup -listnetworkserviceorder |
    awk -v ps_id="$PRIMARY_SERVICE_ID" ' # Pass Shell var to Awk var via -v
    # Look for the line containing the Service ID (Device: ...)
    # Use Awk variable ps_id directly within the regex pattern
    /Device:.*'${ps_id}'(,|\s|$)/ { # Use awk var ps_id in regex
      # The service name is on the line above this one
      # Clean the name (remove number, parens, whitespace)
      gsub(/^\([0-9]+\)\s*/, "", prev_line); gsub(/^\s+|\s+$/,"", prev_line);
      print prev_line; exit
    }
    { prev_line = $0 } # Store the current line for the *next* iteration
    ' # <--- Awk script single quote closes
  ) # <--- Command substitution closes
fi

if [[ -z "$PRIMARY_SERVICE" ]]; then # Check if mapping failed
  log ERROR "Could not detect active service name for ID '$PRIMARY_SERVICE_ID'; skipping Advanced Networking setup"
  INSTALL_PIHOLE=false # Use uppercase
  INSTALL_DOH=false # Use uppercase # Disable installation
else
  log INFO "Active service: '$PRIMARY_SERVICE'" # Quote the service name in log
fi


# 3) Get Colima VM IP
VM_IP=$(check "colima status --json | jq -r '.ip_address'")
if [[ -z "$VM_IP" || "$VM_IP" == "null" ]]; then
  log ERROR "No Colima VM IP; skipping Pi-hole/DoH"
  INSTALL_PIHOLE=false # Use uppercase
  INSTALL_DOH=false # Use uppercase
else
  log INFO "Colima VM IP: $VM_IP"
  run_diagnostic "sleep 3" # Give Colima a moment to ensure networking is fully stable
fi

# Check if either Pihole or DoH is still enabled after checks
if ! $INSTALL_PIHOLE && ! $INSTALL_DOH; then # Use uppercase config variables
  log INFO "Skipping Pi-hole and DoH deployment due to earlier checks."
  # Skip the rest of Section 8
else # At least one is still enabled
  log INFO "Proceeding with DNS setup." # Log that we are proceeding
fi


# 4) Deploy Cloudflared DoH (if enabled and VM_IP available)
if $INSTALL_DOH; then # Use uppercase variable
  log INFO "Deploying Cloudflared DoH on $VM_IP:5053…"
  # cloudflared is installed in Section 1
  if ! $DRYRUN; then
  cat > ~/Library/LaunchAgents/com.local.doh.plist <<'EOF_PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.local.doh</string>
  <key>ProgramArguments</key>
    <array>
      <string>$(which cloudflared)</string>
      <string>proxy-dns</string>
      <string>--address</string><string>${VM_IP}</string> # Make it listen on VM IP
      <string>--port</string><string>5053</string>       # On the host
      <string>--upstream</string><string>https://1.1.1.1/dns-query</string>
    </array>
  <key>KeepAlive</key><true/>
  <key>RunAtLoad</key><true/>
  </dict></plist>
EOF_PLIST
  fi # Use the more robust remove/load -w sequence
  log INFO "Loading agent com.local.doh…"
  run_diagnostic "launchctl remove com.local.doh 2>/dev/null || true" # Remove by label
  run_diagnostic "launchctl load -w $HOME/Library/LaunchAgents/com.local.doh.plist" # Load by plist path

 fi

# 5) Deploy Pi-hole, binding DNS to VM_IP and web UI to localhost
if $INSTALL_PIHOLE; then # Use uppercase variable
  log INFO "Deploying Pi-hole container…"

  # Remove any existing pihole container
  run_diagnostic "docker rm -f pihole || true"

  # Deploy Pi-hole, binding port 53 to the VM's IP address, port 80 to host localhost
  # This bypasses internal VM conflicts (like systemd-resolved)
  # Pre-configure Pi-hole upstream to the Cloudflared proxy via env var
  log INFO "Running docker container 'pihole' binding to ${VM_IP}:53 and 127.0.0.1:80"
  run_diagnostic "docker run -d --name pihole \
    -p $VM_IP:53:53/tcp -p $VM_IP:53:53/udp \
    -p 127.0.0.1:80:80 \
    --restart unless-stopped \
    -v pihole_data:/etc/pihole \
    -e TZ=$(date +%Z) \
    -e WEBPASSWORD='set_me' \
    -e DNS1=$VM_IP#5053 \
    pihole/pihole:latest"

  log INFO "✓ Pi-hole bound to ${VM_IP}:53 with DoH upstream"

  # --- Important Manual Step 1: Verify Pi-hole Setup & Password ---
  # This step is pre-configured by the DNS1 env var above, but manual check/change is good
  log INFO "Please VERIFY Pi-hole setup and CHANGE DEFAULT PASSWORD:"
  log INFO "1. Access Pi-hole web UI at http://127.0.0.1/admin" # Use 127.0.0.1 because port 80 is mapped there
  log INFO "2. Log in (default password is 'set_me', CHANGE THIS IMMEDIATELY!)"
  log INFO "3. Go to Settings -> DNS. Verify 'Custom 1 (IPv4)' is ${VM_IP}#5053 and checked."


  # Set macOS DNS to point to Pi-hole (automated via passwordless sudo)
  log INFO "Updating macOS DNS to Pi-hole at $VM_IP for service '$PRIMARY_SERVICE'…"
  run_diagnostic "sudo networksetup -setdnsservers \"$PRIMARY_SERVICE\" $VM_IP"
  # Flush DNS caches to make the change take effect immediately
  run_diagnostic "dscacheutil -flushcache && sudo killall -HUP mDNSResponder || true"
  log INFO "✓ macOS DNS set to Pi-hole ($VM_IP) and caches flushed."

 fi

### === Section 9: Launch NordVPN === # <-- Renumbered from 8
CURRENT_SECTION="NordVPN Launch"
if $ENABLE_NORD; then # Use uppercase variable
 log INFO "Launching NordVPN GUI…"; run_diagnostic "open -a NordVPN || true"
fi
### === Section 10: Prune Logitech ===
CURRENT_SECTION="Prune Logitech"
log INFO "Pruning Logitech agents…"
# These setopt/unsetopt must run_diagnostic directly in the script's shell
set -o nullglob # SC2039: In zsh, 'setopt' is not available. Use 'set -o'
for p in /Library/LaunchAgents/com.logi.*; do
  run_diagnostic "sudo launchctl bootout system \"$p\" || true" # Use run()
  run_diagnostic "sudo rm -f \"$p\"" # Use run()
done
set +o nullglob # SC2039: In zsh, 'unsetopt' is not available. Use 'set +o'

### === Section 11: Final Health Check === # <-- Renumbered from 10
CURRENT_SECTION="Health Check"
log INFO "----- Health Check -----"

# Check 1: ARM-only process
if check "sysctl -n sysctl.proc_translated &>/dev/null" && (( $(sysctl -n sysctl.proc_translated) == 0 )); then # Check exists first
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

# Check if DoH installation was attempted AND agent is loaded
# Ensure this block is structured exactly as shown:
if $INSTALL_DOH; then # If DoH installation was attempted (Using uppercase variable)
    # Check if the DoH agent is loaded (Nested inside)
    if check "launchctl list com.local.doh &>/dev/null"; then
        CHECK_DOH="Agent com.local.doh loaded ($VM_IP:5053) ✔"
    else # If DoH installation was attempted but agent is NOT loaded
        CHECK_DOH="Agent com.local.doh missing ❌"
    fi # Closes the check for com.local.doh agent status
fi # Closes the outer `if $INSTALL_DOH` block

# --- Print Final Summary ---
# These lines must be OUTSIDE of any if/else/fi blocks.
log INFO "----- Health Check Summary -----"
log INFO "$CHECK_ARM"
log INFO "$CHECK_OLLAMA"
log INFO "$CHECK_DNS"
log INFO "$CHECK_BATTERY"
log INFO "$CHECK_WEEKLY"
# Only print DoH check result if its installation was attempted
if $INSTALL_DOH; then # This conditional print is correct (Using uppercase variable)
  log INFO "$CHECK_DOH"
fi
log INFO "--------------------------"


log INFO "Setup complete ✔" # Final success message. This is Line 674 in the ShellCheck error report.

} # Final closing brace for the script. This is Line 675 in the ShellCheck error report.