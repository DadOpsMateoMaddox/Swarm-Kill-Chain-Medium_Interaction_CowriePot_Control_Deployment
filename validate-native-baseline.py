#!/usr/bin/env python3
"""Static and self-test validation for the native control baseline (LIVE CONTROL invariants; see Exposure Gate E1)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
NATIVE = ROOT / "native"
TEMPLATE = ROOT / "gmu-honeypot-stack-2026-control.yaml"
BOOTSTRAP = NATIVE / "bootstrap-native.sh"
DEPLOYER = ROOT / "Invoke-PatriotPot.ps1"
CONTAINER_ARTIFACT_NAMES = {
    "dockerfile",
    "containerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}

ASSETS = {
    "archive-requirements.lock": NATIVE / "archive-requirements.lock",
    "cowrie-requirements.lock": NATIVE / "cowrie-requirements.lock",
    "discord-monitor.py": NATIVE / "discord-monitor.py",
    "s3-archive.py": NATIVE / "s3-archive.py",
    "install-host-key.py": NATIVE / "install-host-key.py",
    "cowrie.service": NATIVE / "cowrie.service",
    "patriotpot-discord.service": NATIVE / "patriotpot-discord.service",
    "patriotpot-egress-firewall.service": NATIVE / "patriotpot-egress-firewall.service",
    "patriotpot-archive.service": NATIVE / "patriotpot-archive.service",
    "patriotpot-archive.timer": NATIVE / "patriotpot-archive.timer",
    "cloudwatch-agent.json": NATIVE / "cloudwatch-agent.json",
    "patriotpot-logrotate": NATIVE / "patriotpot-logrotate",
    "cowrie.cfg": ROOT / "cowrie.cfg",
    "userdb.txt": ROOT / "userdb.txt",
    "honeyfs-etc-passwd": ROOT / "honeyfs-etc-passwd",
    "honeyfs-home-admin-passwords.txt": ROOT / "honeyfs-home-admin-passwords.txt",
    "txtcmds-bin-netstat": ROOT / "txtcmds-bin-netstat",
    "txtcmds-bin-ps": ROOT / "txtcmds-bin-ps",
    "patriotpot-egress-firewall.sh": NATIVE / "patriotpot-egress-firewall.sh",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def validate_template() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    for forbidden in (
        "AWS::EC2::SecurityGroupIngress",
        "ContainerImageUri",
        "docker run",
        "containerd",
        "podman",
        "AWS::ECS",
        "PatriotPotSSHEndpoint",
        "PatriotPotTelnetEndpoint",
        "KeyPairName",
    ):
        require(forbidden not in text, f"forbidden template declaration: {forbidden}")
    # Exposure Gate E1 (LIVE CONTROL): the template now declares exactly one
    # inbound rule, TCP/2222 from 0.0.0.0/0, for the Cowrie listener. TCP/22
    # and TCP/2223 remain hard-prohibited everywhere in the template.
    require(text.count("SecurityGroupIngress:") == 1, "template must declare exactly one SecurityGroupIngress block")
    ingress_start = text.find("SecurityGroupIngress:")
    ingress_end = text.find("SecurityGroupEgress:", ingress_start)
    require(ingress_end != -1, "malformed template: SecurityGroupEgress not found after SecurityGroupIngress")
    ingress_block = text[ingress_start:ingress_end]
    require(
        "IpProtocol: tcp" in ingress_block
        and "FromPort: 2222" in ingress_block
        and "ToPort: 2222" in ingress_block
        and "CidrIp: 0.0.0.0/0" in ingress_block,
        "SecurityGroupIngress must expose exactly TCP/2222 from 0.0.0.0/0 (Exposure Gate E1)",
    )
    require(ingress_block.count("IpProtocol:") == 1, "SecurityGroupIngress must declare exactly one rule")
    require("CidrIpv6" not in ingress_block, "SecurityGroupIngress must not declare IPv6 ingress")
    require(
        not re.search(r"(?m)^\s*(FromPort|ToPort):\s*(22|2223)\s*$", text),
        "template declares a prohibited inbound port (22 or 2223)",
    )
    for required in (
        "CreationPolicy:",
        "HttpTokens: required",
        "ImageId: !Ref HostAmiId",
        "EvidenceClaimTable:",
        "DeletionPolicy: Retain",
        "'s3:GetObjectVersion'",
        "control/${Environment}/sensors/control-0/instances/*/segments/*",
        "EVIDENCE_PREFIX='control/${Environment}/sensors/control-0'",
        "DenyUnconditionalControlArchiveWrites",
        "'s3:if-none-match': '*'",
        "NetworkInterfaces:",
        "AssociatePublicIpAddress: true",
        "Description: !Sub 'patriotpot-native-bootstrap-${BootstrapBundleId}'",
        '--reason "$failure_reason"',
        "ExposureState:",
        "LIVE_CONTROL_TCP_2222_ONLY",
        "FirewallBundleId:",
        "FirewallScriptSha256:",
        "FirewallUnitSha256:",
        "DiscordMonitorSha256:",
        "PatriotPotEgressFirewallAssociation:",
        "PatriotPotDiscordMonitorAssociation:",
        "AWS::SSM::Association",
        "WaitForSuccessTimeoutSeconds: 600",
    ):
        require(required in text, f"missing template control: {required}")
    egress = text.split("SecurityGroupEgress:", 1)[1].split("Tags:", 1)[0]
    require("IpProtocol: -1" not in egress, "security-group egress remains unrestricted")
    for declaration in (
        "CidrIp: 10.0.0.2/32",
        "FromPort: 53",
        "ToPort: 53",
        "FromPort: 80",
        "FromPort: 443",
    ):
        require(declaration in egress, f"security-group egress lacks {declaration}")


def validate_no_deployable_container_artifacts() -> None:
    """Reject active deployment mechanisms, without policing historical prose."""
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        relative = path.relative_to(ROOT)
        lower_name = path.name.lower()
        require(
            lower_name not in CONTAINER_ARTIFACT_NAMES,
            f"deployable container artifact present: {relative}",
        )
        if path.suffix.lower() in {".sh", ".ps1", ".yaml", ".yml", ".service"}:
            text = path.read_text(encoding="utf-8", errors="ignore")
            require(
                re.search(
                    r"(?im)^\s*(?:docker|podman|containerd|nerdctl)\s+"
                    r"(?:run|build|pull|compose|start)\b",
                    text,
                )
                is None,
                f"deployable container command present: {relative}",
            )
            require(
                re.search(
                    r"(?im)^\s*(?:EXPOSE\s+2223\b|(?:FromPort|ToPort)\s*:\s*2223\s*$)",
                    text,
                )
                is None,
                f"deployable TCP/2223 alternative present: {relative}",
            )


def validate_assets() -> None:
    bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
    for name, path in ASSETS.items():
        require(path.is_file(), f"missing asset: {name}")
        require(
            b"\r" not in path.read_bytes(),
            f"deployment asset is not persistently LF-normalized: {name}",
        )
        expected = sha256(path)
        require(
            re.search(rf"(?m)^{expected}  {re.escape(name)}$", bootstrap) is not None,
            f"stale bootstrap SHA-256 pin: {name}",
        )
    require(
        'COWRIE_COMMIT="000116838246ce522b1f6953c6f108a3a4f0611c"' in bootstrap,
        "Cowrie commit is not pinned",
    )
    require(
        'COWRIE_FS_SHA256="06f0ed527bdc133b3fabca5def3db084b120bdf6b8e47736a85cd12e98b36da9"'
        in bootstrap,
        "stock v2.5.0 fs.pickle is not pinned",
    )
    require(
        'COWRIE_JSONLOG_UPSTREAM_SHA256="ebfabe105b8c680abf61b0e2e373ddeea3ad2918333441ec15fa0b76120820da"'
        in bootstrap
        and 'COWRIE_JSONLOG_PATCHED_SHA256="c3a17e95795683ac3cf0dfb1593051c989875974499447cab98ec2c4902a813c"'
        in bootstrap,
        "Cowrie JSON logger permission patch is not provenance-pinned",
    )
    require(
        "sed -i 's/defaultMode=0o664/defaultMode=0o640/'" in bootstrap,
        "Cowrie JSON logger does not enforce mode 0640 across rotation",
    )
    require(
        'PYTHON_VERSION="3.8.20"' in bootstrap
        and 'PYTHON_SHA256="9f2d5962c2583e67ef75924cd56d0c1af78bf45ec57035cf8a2cc09f74f4bf78"'
        in bootstrap,
        "side-by-side Python source is not pinned",
    )
    require("systemctl disable --now sshd" in bootstrap, "host sshd is not disabled")
    require("enabled = false" in bootstrap, "Telnet safety override is absent")
    require(
        not re.search(
            r"(?:truncate|/dev/null\s+/opt/cowrie/var/log|>\s*/opt/cowrie/var/log)",
            bootstrap,
        ),
        "bootstrap can truncate authoritative Cowrie logs",
    )
    archive = (NATIVE / "s3-archive.py").read_text(encoding="utf-8")
    for required in (
        '"version": 3',
        "def open_source",
        "os.fstat(fd)",
        "def descriptor_anchor",
        "def snapshot_anchor",
        "def complete_records",
        '"IfNoneMatch": "*"',
        '"ChecksumSHA256": checksum_b64(digest)',
        "s3_client().get_object",
        "hasher.hexdigest() != digest",
        "changed_during_descriptor_read",
    ):
        require(
            required in archive,
            f"archive descriptor/immutable-segment control is absent: {required}",
        )
    for forbidden in (
        "path.lstat()",
        "path.read_bytes()",
        "splitlines(keepends=True)",
        '"--if-none-match"',
        "head_object",
        "list_objects",
        "dynamodb",
        "acquire_claim",
        "release_claim",
    ):
        require(
            forbidden not in archive,
            f"archive source TOCTOU or non-LF record split remains: {forbidden}",
        )
    for forbidden in ("'s3:ListBucket'", "'dynamodb:PutItem'", "'dynamodb:DeleteItem'"):
        require(
            forbidden not in TEMPLATE.read_text(encoding="utf-8"),
            f"obsolete archive permission remains: {forbidden}",
        )
    archive_requirements = (NATIVE / "archive-requirements.lock").read_text(
        encoding="utf-8"
    )
    require(
        "boto3==1.35.99" in archive_requirements
        and "botocore==1.35.99" in archive_requirements,
        "archive boto3/botocore versions are not pinned",
    )
    archive_unit = (NATIVE / "patriotpot-archive.service").read_text(encoding="utf-8")
    require(
        "ExecStart=/opt/patriotpot-archive/venv/bin/python " in archive_unit,
        "archive service does not use the pinned SDK environment",
    )
    for required in ("FAILURE_PHASE_PATH", "record_failure_phase", "set_phase"):
        require(
            required in bootstrap,
            f"bootstrap failure signal is not safely phase-qualified: {required}",
        )

    unit = (NATIVE / "cowrie.service").read_text(encoding="utf-8")
    require("User=cowrie" in unit, "Cowrie unit is not unprivileged")
    require("/opt/cowrie/venv/bin/twistd" in unit, "Cowrie unit is not native")
    require("CapabilityBoundingSet=" in unit, "Cowrie unit retains Linux capabilities")
    require("UMask=0027" in unit, "Cowrie unit does not enforce umask 0027")
    require(
        "ExecStartPre=/usr/bin/touch /opt/cowrie/var/log/cowrie/cowrie.log "
        "/opt/cowrie/var/log/cowrie/cowrie.json" in unit,
        "Cowrie unit does not safely create missing authoritative logs",
    )
    require(
        "ExecStartPre=/usr/bin/chmod 0640 /opt/cowrie/var/log/cowrie/cowrie.log "
        "/opt/cowrie/var/log/cowrie/cowrie.json" in unit,
        "Cowrie unit does not correct authoritative log modes before start",
    )

    firewall = (NATIVE / "patriotpot-egress-firewall.sh").read_text(encoding="utf-8")
    for required in (
        'readonly VPC_RESOLVER="10.0.0.2"',
        'readonly INSTANCE_METADATA="169.254.169.254"',
        'readonly AMAZON_TIME="169.254.169.123"',
        'readonly LOG_PREFIX="PATRIOTPOT_EGRESS_DROP "',
        'readonly LOG_RATE="6/minute"',
        'readonly LOG_BURST="10"',
        '-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
        '--dport 53',
        '--dport 80',
        '--dport 123',
        '--dports 80,443',
        'iptables_wait -A "$DENY_CHAIN" -j DROP',
        'ip6tables_wait -A "$IPV6_DENY_CHAIN" -j DROP',
        'iptables_wait -A "$CHAIN" -m conntrack --ctstate NEW -j "$DENY_CHAIN"',
        'ip6tables_wait -A "$IPV6_CHAIN" -m conntrack --ctstate NEW -j "$IPV6_DENY_CHAIN"',
        'iptables_wait -A "$CHAIN" -j RETURN',
        'ip6tables_wait -A "$IPV6_CHAIN" -j RETURN',
    ):
        require(required in firewall, f"firewall control missing: {required}")
    require(
        re.search(r"(?m)^(?:ip6?tables_wait).*\b(?:INPUT|FORWARD)\b", firewall)
        is None,
        "firewall must not shape Cowrie inbound or forwarding behavior",
    )
    require(
        re.search(r"(?m)(?:^|\s)-j\s+REJECT(?:\s|$)", firewall) is None,
        "firewall must silently DROP rather than actively REJECT",
    )
    require(
        re.search(
            r'-m limit \\\n'
            r'  --limit "\$LOG_RATE" --limit-burst "\$LOG_BURST" \\\n'
            r'  -j LOG --log-prefix "\$LOG_PREFIX" --log-level info\n'
            r'iptables_wait -A "\$DENY_CHAIN" -j DROP',
            firewall,
        )
        is not None
        and re.search(
            r'-m limit \\\n'
            r'  --limit "\$LOG_RATE" --limit-burst "\$LOG_BURST" \\\n'
            r'  -j LOG --log-prefix "\$LOG_PREFIX" --log-level info\n'
            r'ip6tables_wait -A "\$IPV6_DENY_CHAIN" -j DROP',
            firewall,
        )
        is not None,
        "bounded local LOG must immediately precede each silent DROP",
    )
    require(
        "cowrie.json" not in firewall and "/opt/cowrie/var/log" not in firewall,
        "firewall logging must not write to an authoritative Cowrie source",
    )
    firewall_unit = (NATIVE / "patriotpot-egress-firewall.service").read_text(
        encoding="utf-8"
    )
    for required in (
        "Before=amazon-ssm-agent.service cowrie.service",
        "ExecStart=/usr/local/libexec/patriotpot-egress-firewall",
        "RemainAfterExit=yes",
        "WantedBy=multi-user.target",
    ):
        require(required in firewall_unit, f"firewall unit control missing: {required}")

    for service in ("patriotpot-discord.service", "patriotpot-archive.service"):
        reader_unit = (NATIVE / service).read_text(encoding="utf-8")
        require(
            "SupplementaryGroups=cowrie" in reader_unit,
            f"{service} lacks deliberate Cowrie group read access",
        )
        require(
            "Requires=cowrie.service" not in reader_unit,
            f"{service} is fatally coupled to Cowrie lifecycle",
        )
        require(
            "After=network-online.target cowrie.service" in reader_unit,
            f"{service} lacks non-fatal Cowrie ordering",
        )

    discord = (NATIVE / "discord-monitor.py").read_text(encoding="utf-8")
    for eventid in (
        "cowrie.login.success",
        "cowrie.login.failed",
        "cowrie.command.input",
        "cowrie.session.file_download",
    ):
        require(eventid in discord, f"Discord supported event is absent: {eventid}")
    require('"Country"' not in discord, "Discord monitor enriches alert payloads")
    require(
        "restart_replay_suppressed" in discord
        and "delivery_uncertain_no_replay" in discord,
        "Discord monitor does not document durable no-replay behavior",
    )

    cloudwatch = json.loads((NATIVE / "cloudwatch-agent.json").read_text())
    require(
        cloudwatch["agent"]["run_as_user"] == "root",
        "CloudWatch agent no longer has deliberate root read access",
    )
    paths = {
        item["file_path"]
        for item in cloudwatch["logs"]["logs_collected"]["files"]["collect_list"]
    }
    require(
        "/opt/cowrie/var/log/cowrie/cowrie.json" in paths,
        "CloudWatch does not collect local cowrie.json",
    )
    operation_entries = [
        item
        for item in cloudwatch["logs"]["logs_collected"]["files"]["collect_list"]
        if item["log_group_name"] == "/patriotpot/operations"
    ]
    require(operation_entries, "CloudWatch operations collection is absent")
    require(
        all("{file_name}" not in item["log_stream_name"] for item in operation_entries),
        "CloudWatch operations stream contains unsupported literal {file_name}",
    )
    require(
        len({item["log_stream_name"] for item in operation_entries})
        == len(operation_entries),
        "CloudWatch operations streams are not explicitly distinct",
    )


def validate_behavioral_contract() -> None:
    cfg = (ROOT / "cowrie.cfg").read_text(encoding="utf-8")
    for declaration in (
        "hostname = gmu-server",
        "backend = shell",
        "version = SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
        "listen_endpoints = tcp:2222:interface=0.0.0.0",
        "filesystem = /opt/cowrie/share/cowrie/fs.pickle",
    ):
        require(declaration in cfg, f"behavioral declaration missing: {declaration}")
    require("2223" not in cfg, "recovered candidate cfg unexpectedly enables TCP/2223")

    users = (ROOT / "userdb.txt").read_text(encoding="utf-8").splitlines()
    require(len(users) == 10, "userdb account count changed")
    require(all(line.endswith(":x:*:") for line in users), "userdb wildcard policy changed")


def validate_bundle_replacement_control() -> None:
    deployer = DEPLOYER.read_text(encoding="utf-8")
    for required in (
        "$currentBundleId",
        "$desiredBundleId",
        "$currentBundleId -ne $desiredBundleId",
        "Change set does not contain the required EC2 instance replacement.",
    ):
        require(
            required in deployer,
            f"bundle revision does not require reviewed instance replacement: {required}",
        )


def validate_secret_absence() -> None:
    patterns = {
        "Discord webhook": re.compile(
            r"https://(?:discord(?:app)?\.com)/api/webhooks/[0-9]+/[A-Za-z0-9._-]+",
            re.I,
        ),
        "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "private key material": re.compile(
            rb"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----\s*\r?\n[A-Za-z0-9+/]{40}"
        ),
    }
    for name, path in ASSETS.items():
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="ignore")
        require(not patterns["Discord webhook"].search(text), f"webhook in {name}")
        require(not patterns["AWS access key"].search(text), f"AWS key in {name}")
        require(not patterns["private key material"].search(raw), f"private key in {name}")


def run_self_tests() -> None:
    for script in ("discord-monitor.py", "s3-archive.py"):
        result = subprocess.run(
            [sys.executable, str(NATIVE / script), "--self-test"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        require(result.returncode == 0, f"{script} self-test failed: {result.stderr}")


def main() -> None:
    validate_template()
    validate_no_deployable_container_artifacts()
    validate_assets()
    validate_behavioral_contract()
    validate_bundle_replacement_control()
    validate_secret_absence()
    run_self_tests()
    print("native baseline validation: PASS")


if __name__ == "__main__":
    main()
