#!/bin/bash
# Exit on any error
set -e

# --- Configuration (No changes needed here usually) ---
PLIST_FILE="$HOME/Library/LaunchAgents/com.local.doh.plist"
HOST_IP_FROM_COLIMA="192.168.5.1" # Confirmed via your command output

# --- Step 1: Update Plist ---
echo ">>> Updating $PLIST_FILE to listen on 127.0.0.1..."
if [[ -f "$PLIST_FILE" ]]; then
  sed -i.bak 's/<string>192\.168\.64\.2<\/string>/<string>127.0.0.1<\/string>/' "$PLIST_FILE" \
  && echo "Plist updated." \
  || echo "WARN: Failed to update plist (maybe IP was already 127.0.0.1?)."
else
  echo "WARN: Plist file not found at $PLIST_FILE. Skipping update."
fi

# --- Step 2: Reload cloudflared Agent ---
echo ">>> Reloading com.local.doh LaunchAgent..."
launchctl bootout gui/$(id -u) "$PLIST_FILE" || echo "INFO: Agent not previously loaded or already stopped."
sleep 1
launchctl bootstrap gui/$(id -u) "$PLIST_FILE"
sleep 2
echo ">>> Checking Agent Status (PID should not be 0 or -):"
launchctl list com.local.doh | grep '"PID"' || echo "INFO: Agent might still be starting or failed."
sleep 1

# --- Step 3: Get Current Colima VM IP ---
echo ">>> Getting Colima VM IP..."
VM_IP=$(colima status --json | jq -r '.network.address // .Network.address // .ip_address // .address // .ipAddress // empty' 2>/dev/null)
if [[ -z "$VM_IP" ]]; then
  echo "ERROR: Could not determine Colima VM IP. Aborting."
  exit 1
fi
echo "VM IP found: $VM_IP"

# --- Step 4: Stop/Remove Old Pi-hole ---
echo ">>> Stopping and removing existing Pi-hole container..."
docker stop pihole > /dev/null 2>&1 || echo "INFO: Pi-hole container not running."
docker rm pihole > /dev/null 2>&1 || echo "INFO: Pi-hole container not found."
sleep 1

# --- Step 5: Relaunch Pi-hole with Correct Upstream ---
echo ">>> Relaunching Pi-hole (DNS1 -> ${HOST_IP_FROM_COLIMA}#5053)..."
docker run -d --name pihole \
  -p "${VM_IP}:53:53/tcp" -p "${VM_IP}:53:53/udp" \
  -p 127.0.0.1:80:80 \
  --restart unless-stopped \
  -v pihole_data:/etc/pihole \
  -e TZ=$(date +%Z) \
  -e WEBPASSWORD='set_me' \
  -e DNS1="${HOST_IP_FROM_COLIMA}#5053" \
  pihole/pihole:latest

echo ">>> Waiting ~15 seconds for Pi-hole to start..."
sleep 15

# --- Step 6: Manual Pi-hole UI Step Reminder ---
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "CRITICAL MANUAL STEP REQUIRED:"
echo "1. Open: http://127.0.0.1/admin"
echo "2. Log in (default pass: set_me - CHANGE IT!)"
echo "3. Go to Settings -> DNS -> Interface Settings"
echo "4. Select -> Permit all origins <-"
echo "5. Scroll down and click -> Save <-"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
read -p "Press Enter ONLY after completing the Pi-hole web UI step..."

# --- Step 7: Final Test ---
echo ">>> Testing DNS resolution via Pi-hole ($VM_IP)..."
if dig +short +time=3 +tries=1 apple.com "@${VM_IP}" > /dev/null; then
  echo "✅ SUCCESS: DNS resolution via Pi-hole appears to be working!"
else
  echo "❌ FAILURE: DNS resolution via Pi-hole still seems to be failing."
  echo "   Check Pi-hole logs ('docker logs pihole') and ensure cloudflared ('launchctl list com.local.doh') is running."
fi

echo ">>> Process complete."