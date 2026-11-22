#!/bin/sh
# Default-deny WAN egress for the sparkDash container.
#
# sparkDash is a LAN monitor. Everything it collects, and every command it runs
# on a unit, is untrusted: nothing may leave the local network unless the
# operator explicitly sets SPARKDASH_ALLOW_WAN_EGRESS=1.
#
# Enable this guard with SPARKDASH_EGRESS_LOCKDOWN=1. It is deliberately opt-in
# per compose file because it edits the container's network namespace: with
# `network_mode: host` those rules would apply to the whole host, not just the
# dashboard. Bridge deployments (the zettai compose file) enable it.
#
# Allowed: loopback, RFC 1918, link-local, CGNAT / Tailscale, IPv6 ULA and
# link-local, plus replies to inbound connections. Everything else is dropped.
# DNS through Docker's embedded resolver (127.0.0.11) stays inside loopback.
set -eu

if [ "${SPARKDASH_ALLOW_WAN_EGRESS:-0}" = "1" ] || [ "${SPARKDASH_ALLOW_WAN_EGRESS:-0}" = "true" ]; then
  echo "[egress] WAN egress explicitly allowed by the operator"
  exec "$@"
fi

if [ "${SPARKDASH_EGRESS_LOCKDOWN:-0}" != "1" ]; then
  echo "[egress] WAN lockdown not enabled (set SPARKDASH_EGRESS_LOCKDOWN=1 for bridge deployments)"
  exec "$@"
fi

if ! command -v iptables >/dev/null 2>&1; then
  echo "[egress] iptables is missing; refusing to start without egress enforcement" >&2
  exit 1
fi

# IPv4: default drop, then allow only local destinations.
iptables -F OUTPUT 2>/dev/null || true
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16; do
  iptables -A OUTPUT -d "$cidr" -j ACCEPT
done

# IPv6: same policy. Docker Desktop may not enable IPv6; skip cleanly if not.
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -F OUTPUT 2>/dev/null || true
  ip6tables -P OUTPUT DROP 2>/dev/null || true
  ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
  ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  ip6tables -A OUTPUT -d fc00::/7 -j ACCEPT 2>/dev/null || true
  ip6tables -A OUTPUT -d fe80::/10 -j ACCEPT 2>/dev/null || true
fi

echo "[egress] WAN egress blocked; LAN, Tailscale and loopback allowed"
exec "$@"
