#!/bin/bash
# PatriotPot 2026 control: outbound-only, stateful host policy.
#
# The security group supplies the authoritative VPC boundary.  This
# independent host policy is intentionally limited to OUTPUT: it neither
# accepts, rejects, shapes, nor otherwise changes Cowrie's local listener.
set -euo pipefail

readonly CHAIN="PATRIOTPOT_EGRESS"
readonly DENY_CHAIN="PATRIOTPOT_EGRESS_DENY"
readonly IPV6_CHAIN="PATRIOTPOT_EGRESS_V6"
readonly IPV6_DENY_CHAIN="PATRIOTPOT_EGRESS_V6_DENY"
readonly VPC_RESOLVER="10.0.0.2"
readonly INSTANCE_METADATA="169.254.169.254"
readonly AMAZON_TIME="169.254.169.123"
readonly LOG_PREFIX="PATRIOTPOT_EGRESS_DROP "
readonly LOG_RATE="6/minute"
readonly LOG_BURST="10"

iptables_wait() {
  /sbin/iptables -w 5 "$@"
}

ip6tables_wait() {
  /sbin/ip6tables -w 5 "$@"
}

remove_chain() {
  local binary="$1"
  local chain="$2"
  while "$binary" -w 5 -D OUTPUT -j "$chain" 2>/dev/null; do :; done
  "$binary" -w 5 -F "$chain" 2>/dev/null || true
  "$binary" -w 5 -X "$chain" 2>/dev/null || true
}

remove_chain /sbin/iptables "$CHAIN"
remove_chain /sbin/iptables "$DENY_CHAIN"
iptables_wait -N "$DENY_CHAIN"
iptables_wait -A "$DENY_CHAIN" -m limit \
  --limit "$LOG_RATE" --limit-burst "$LOG_BURST" \
  -j LOG --log-prefix "$LOG_PREFIX" --log-level info
iptables_wait -A "$DENY_CHAIN" -j DROP
iptables_wait -N "$CHAIN"

# State is first so reply traffic cannot be mistaken for a new outbound flow.
iptables_wait -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables_wait -A "$CHAIN" -o lo -j ACCEPT

# Objectively required infrastructure exceptions precede reserved-address drops.
iptables_wait -A "$CHAIN" -p udp -d "$VPC_RESOLVER" --dport 53 \
  -m conntrack --ctstate NEW -j ACCEPT
iptables_wait -A "$CHAIN" -p tcp -d "$VPC_RESOLVER" --dport 53 \
  -m conntrack --ctstate NEW -j ACCEPT
iptables_wait -A "$CHAIN" -p tcp -d "$INSTANCE_METADATA" --dport 80 \
  -m conntrack --ctstate NEW -j ACCEPT
iptables_wait -A "$CHAIN" -p udp -d "$AMAZON_TIME" --dport 123 \
  -m conntrack --ctstate NEW -j ACCEPT

# RFC1918, link-local, carrier-grade, documentation, multicast, and reserved
# ranges cannot be reached, including all lateral VPC destinations.
for blocked_cidr in \
  0.0.0.0/8 \
  10.0.0.0/8 \
  100.64.0.0/10 \
  127.0.0.0/8 \
  169.254.0.0/16 \
  172.16.0.0/12 \
  192.0.0.0/24 \
  192.0.2.0/24 \
  192.168.0.0/16 \
  198.18.0.0/15 \
  198.51.100.0/24 \
  203.0.113.0/24 \
  224.0.0.0/4 \
  240.0.0.0/4; do
  iptables_wait -A "$CHAIN" -d "$blocked_cidr" \
    -m conntrack --ctstate NEW -j "$DENY_CHAIN"
done

# The only permitted new public flows are direct TCP HTTP(S).  S3,
# CloudWatch, SSM, package retrieval, and Discord therefore remain direct
# public HTTPS flows; no VPC endpoints or relays are introduced.
iptables_wait -A "$CHAIN" -p tcp -d 0.0.0.0/0 \
  -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT
iptables_wait -A "$CHAIN" -m conntrack --ctstate NEW -j "$DENY_CHAIN"
# Do not alter INVALID, UNTRACKED, or any other non-NEW packet class.
iptables_wait -A "$CHAIN" -j RETURN
iptables_wait -I OUTPUT 1 -j "$CHAIN"

# No IPv6 address is assigned to the ENI.  Keep that boundary explicit without
# changing INPUT, which preserves an unshaped local Cowrie TCP/2222 listener.
remove_chain /sbin/ip6tables "$IPV6_CHAIN"
remove_chain /sbin/ip6tables "$IPV6_DENY_CHAIN"
ip6tables_wait -N "$IPV6_DENY_CHAIN"
ip6tables_wait -A "$IPV6_DENY_CHAIN" -m limit \
  --limit "$LOG_RATE" --limit-burst "$LOG_BURST" \
  -j LOG --log-prefix "$LOG_PREFIX" --log-level info
ip6tables_wait -A "$IPV6_DENY_CHAIN" -j DROP
ip6tables_wait -N "$IPV6_CHAIN"
ip6tables_wait -A "$IPV6_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables_wait -A "$IPV6_CHAIN" -o lo -j ACCEPT
ip6tables_wait -A "$IPV6_CHAIN" -m conntrack --ctstate NEW -j "$IPV6_DENY_CHAIN"
ip6tables_wait -A "$IPV6_CHAIN" -j RETURN
ip6tables_wait -I OUTPUT 1 -j "$IPV6_CHAIN"
