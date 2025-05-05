#!/usr/bin/env bash
set -euo pipefail

OUT=network-diagnostics.txt
exec > >(tee "$OUT") 2>&1

echo "=== 1) PrimaryService ID & Name ==="
scutil <<< $'open\nshow State:/Network/Global/IPv4\nd.show'
echo
networksetup -listnetworkserviceorder | sed -n '1,20p'
echo

PRIMARY_ID=$(scutil <<< $'open\nshow State:/Network/Global/IPv4\nd.show' \
              | awk -F': ' '/PrimaryService/ {gsub(/"/,""); print $2}')
echo "PrimaryService ID = $PRIMARY_ID"
SERVICE_NAME=$(networksetup -listnetworkserviceorder \
              | awk -v id="$PRIMARY_ID" '/Device:.*'"$PRIMARY_ID"'/{getline; gsub(/^\([0-9]+\)\s*/,""); print; exit}')
echo "Service name      = $SERVICE_NAME"
echo

echo "=== 2) networksetup DNS & search-domains for $SERVICE_NAME ==="
networksetup -getdnsservers "$SERVICE_NAME" || echo "(empty)"
networksetup -getsearchdomains "$SERVICE_NAME" || echo "(empty)"
echo

echo "=== 3) scutil resolver list ==="
scutil --dns
echo

echo "=== 4) /etc/resolv.conf ==="
cat /etc/resolv.conf
echo

echo "=== 5) Ping tests ==="
echo "→ Ping your router:"
networksetup -getinfo "$SERVICE_NAME" | awk '/Router:/ {print $2}' | xargs -I​{} ping -c3 {}
echo "→ Ping 8.8.8.8"
ping -c3 8.8.8.8
echo

echo "=== 6) Live dig tests ==="
echo "→ dig @8.8.8.8 google.com:"
dig @8.8.8.8 google.com +short
echo
echo "→ dig @127.0.0.1 google.com:"
dig @127.0.0.1 google.com +short
echo
echo "→ dig @127.0.0.1 -p 5053 google.com:"
dig @127.0.0.1 -p 5053 google.com +short
echo

echo "=== 7) cloudflared & Pi-hole status ==="
launchctl list com.local.doh    && echo "cloudflared agent loaded" || echo "cloudflared NOT loaded"
docker ps --filter name=pihole --format '→ pihole container: {{.Names}} {{.Status}}'
echo

echo "=== 8) Ports inside Colima VM ==="
colima ssh -- sudo ss -tulnp | grep -E ':(53|5053)\s'
echo

echo "Diagnostics captured to $OUT"