"""Deterministic policy tests for the outbound-only Gate H1 firewall."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIREWALL = ROOT / "native" / "patriotpot-egress-firewall.sh"


class EgressFirewallPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = FIREWALL.read_text(encoding="utf-8")

    def position(self, text):
        position = self.source.find(text)
        self.assertNotEqual(position, -1, f"missing firewall declaration: {text}")
        return position

    def test_denials_are_silent_drop_not_reject(self):
        self.assertNotRegex(self.source, r"(?m)(?:^|\s)-j\s+REJECT(?:\s|$)")
        self.assertIn('iptables_wait -A "$DENY_CHAIN" -j DROP', self.source)
        self.assertIn('ip6tables_wait -A "$IPV6_DENY_CHAIN" -j DROP', self.source)

    def test_denial_logging_is_local_bounded_and_immediately_precedes_drop(self):
        self.assertIn('readonly LOG_PREFIX="PATRIOTPOT_EGRESS_DROP "', self.source)
        self.assertIn('readonly LOG_RATE="6/minute"', self.source)
        self.assertIn('readonly LOG_BURST="10"', self.source)
        for family, chain in (
            ("iptables_wait", "$DENY_CHAIN"),
            ("ip6tables_wait", "$IPV6_DENY_CHAIN"),
        ):
            pattern = re.compile(
                rf'{family} -A "{re.escape(chain)}" -m limit \\\n'
                r'  --limit "\$LOG_RATE" --limit-burst "\$LOG_BURST" \\\n'
                r'  -j LOG --log-prefix "\$LOG_PREFIX" --log-level info\n'
                rf'{family} -A "{re.escape(chain)}" -j DROP'
            )
            self.assertRegex(self.source, pattern)

    def test_only_new_outbound_connections_reach_denial_chains(self):
        for line in self.source.splitlines():
            if '-j "$DENY_CHAIN"' in line or '-j "$IPV6_DENY_CHAIN"' in line:
                # Wrapped CIDR rules carry the NEW selector on the next line.
                continue
            if re.search(r'(?<!DENY_CHAIN)"\s+-j DROP', line):
                self.fail(f"DROP exists outside a dedicated denial chain: {line}")
        self.assertIn(
            'iptables_wait -A "$CHAIN" -m conntrack --ctstate NEW -j "$DENY_CHAIN"',
            self.source,
        )
        self.assertIn(
            'ip6tables_wait -A "$IPV6_CHAIN" -m conntrack --ctstate NEW '
            '-j "$IPV6_DENY_CHAIN"',
            self.source,
        )
        self.assertIn('iptables_wait -A "$CHAIN" -j RETURN', self.source)
        self.assertIn('ip6tables_wait -A "$IPV6_CHAIN" -j RETURN', self.source)
        cidr_jump = re.compile(
            r'iptables_wait -A "\$CHAIN" -d "\$blocked_cidr" \\\n'
            r'    -m conntrack --ctstate NEW -j "\$DENY_CHAIN"'
        )
        self.assertRegex(self.source, cidr_jump)

    def test_established_loopback_infrastructure_and_public_web_precede_denial(self):
        state = self.position(
            'iptables_wait -A "$CHAIN" -m conntrack '
            '--ctstate ESTABLISHED,RELATED -j ACCEPT'
        )
        loopback = self.position('iptables_wait -A "$CHAIN" -o lo -j ACCEPT')
        dns_udp = self.position(
            'iptables_wait -A "$CHAIN" -p udp -d "$VPC_RESOLVER" --dport 53'
        )
        dns_tcp = self.position(
            'iptables_wait -A "$CHAIN" -p tcp -d "$VPC_RESOLVER" --dport 53'
        )
        metadata = self.position(
            'iptables_wait -A "$CHAIN" -p tcp -d "$INSTANCE_METADATA" --dport 80'
        )
        time = self.position(
            'iptables_wait -A "$CHAIN" -p udp -d "$AMAZON_TIME" --dport 123'
        )
        reserved = self.position("for blocked_cidr in")
        public_web = self.position(
            'iptables_wait -A "$CHAIN" -p tcp -d 0.0.0.0/0'
        )
        final_new = self.position(
            'iptables_wait -A "$CHAIN" -m conntrack --ctstate NEW -j "$DENY_CHAIN"'
        )
        returned = self.position('iptables_wait -A "$CHAIN" -j RETURN')
        self.assertEqual(
            [state, loopback, dns_udp, dns_tcp, metadata, time, reserved, public_web, final_new, returned],
            sorted(
                [
                    state,
                    loopback,
                    dns_udp,
                    dns_tcp,
                    metadata,
                    time,
                    reserved,
                    public_web,
                    final_new,
                    returned,
                ]
            ),
        )

    def test_input_forward_and_cowrie_sources_are_not_touched(self):
        self.assertNotRegex(
            self.source,
            r'(?m)^(?:ip6?tables_wait|"\$binary"\s+-w\s+5)\s+.*\b(?:INPUT|FORWARD)\b',
        )
        self.assertNotIn("cowrie.json", self.source)
        self.assertNotIn("/opt/cowrie/var/log", self.source)
        self.assertNotRegex(self.source, r"(?m)^\s*(?:printf|echo|logger)\b.*cowrie")
        self.assertIn('iptables_wait -I OUTPUT 1 -j "$CHAIN"', self.source)
        self.assertIn('ip6tables_wait -I OUTPUT 1 -j "$IPV6_CHAIN"', self.source)

    def test_reapply_removes_main_chain_before_denial_chain(self):
        self.assertLess(
            self.position('remove_chain /sbin/iptables "$CHAIN"'),
            self.position('remove_chain /sbin/iptables "$DENY_CHAIN"'),
        )
        self.assertLess(
            self.position('remove_chain /sbin/ip6tables "$IPV6_CHAIN"'),
            self.position('remove_chain /sbin/ip6tables "$IPV6_DENY_CHAIN"'),
        )


if __name__ == "__main__":
    unittest.main()
