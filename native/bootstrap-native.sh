#!/bin/bash
# Repository text is LF-normalized so this entry point executes unchanged on AL2.
set -euo pipefail
umask 027

readonly PYTHON_VERSION="3.8.20"
readonly PYTHON_SHA256="9f2d5962c2583e67ef75924cd56d0c1af78bf45ec57035cf8a2cc09f74f4bf78"
readonly COWRIE_VERSION="v2.5.0"
readonly COWRIE_COMMIT="000116838246ce522b1f6953c6f108a3a4f0611c"
readonly COWRIE_FS_SHA256="06f0ed527bdc133b3fabca5def3db084b120bdf6b8e47736a85cd12e98b36da9"
readonly COWRIE_JSONLOG_UPSTREAM_SHA256="ebfabe105b8c680abf61b0e2e373ddeea3ad2918333441ec15fa0b76120820da"
readonly COWRIE_JSONLOG_PATCHED_SHA256="c3a17e95795683ac3cf0dfb1593051c989875974499447cab98ec2c4902a813c"
readonly ASSET_DIR="/opt/patriotpot-bootstrap"
readonly AWS_PROFILE_EXPECTED="patriotpot"
readonly AWS_REGION_EXPECTED="us-east-1"
readonly FAILURE_PHASE_PATH="/var/log/patriotpot/bootstrap-failure-phase"
CURRENT_PHASE="bootstrap_preflight"

record_failure_phase() {
  local exit_code="$1"
  trap - EXIT
  if [[ "$exit_code" -ne 0 ]]; then
    # This value is intentionally limited to a fixed internal phase and exit
    # code. It is safe to attach to cfn-signal without exposing credentials.
    printf '%s:%s\n' "$CURRENT_PHASE" "$exit_code" >"$FAILURE_PHASE_PATH" || true
  fi
  exit "$exit_code"
}

set_phase() {
  CURRENT_PHASE="$1"
}

trap 'record_failure_phase $?' EXIT

# This list is completed by the deployment preparation step. The bootstrap
# script itself is independently pinned by BootstrapScriptSha256 in CFN.
read -r -d '' ASSET_HASHES <<'EOF' || true
65ba7f77c4fa17e77f7fee3ad0510b510f862b88e46f53a6b266c23dfb7afb3a  archive-requirements.lock
4dcc0dfe4b652ab4647f6d2fe992de0bebaedbd09f64dbe284b157545fb232b5  cowrie-requirements.lock
6c4e7bc3e4516d4df828e37d4abee579b2082648857312be883a4bbb1aebb79c  discord-monitor.py
1b8089d405e1766e3e1182c1d26cd0de66d35bd0205965b62979b9699a2d2b54  s3-archive.py
ee2d62fe0cc0ed88d6180b30c5cf19611d481432aea058977ea88fe07ee918b9  install-host-key.py
77057b6c86189dcc153ddfeb50c00e6fd3165711e7a6ddff121241a73c6fb7de  cowrie.service
2b1d2ab3769602c4f1f3c008f6fab8b2dd063b5afb9091d1813a0daed28bcad4  patriotpot-discord.service
11d9124d1390bd44985cb6884e032b80979ac0f8029b541230732f7cdcd026e8  patriotpot-egress-firewall.service
295335375980bc3d1981c4fb3f4a2a2d66c2ae36a439b99a2e7b65526c83e281  patriotpot-archive.service
a407c90e568d357a7c937fc08306a412f1607d64076b3dac01c954a1a5e66129  patriotpot-archive.timer
d793095dd9fa5a499029034c0a77f1dce91a68574694a36c74e4ac6a257de857  cloudwatch-agent.json
e683e452cc9e461c61fa8ab76f454a95bd9920198406693aad6f713cd7a2ee30  patriotpot-logrotate
33ff40ef21dc66021e31c22be94b896d2717d7a4e8cdbd2078e2ef2f26f00a3d  cowrie.cfg
8f4f8645f05f25392adc9cb0963f7a60adaf677d2195dfd588a83c433c6365a6  userdb.txt
aabdb61b03b6486e778561fd624ff143d111bd1d218ec5672b81c633b46d2c4c  honeyfs-etc-passwd
9e0c02bd77c06deccb6b028ae21dd48e451d9d90c1d3e2d5b36daf1fcfcda4f4  honeyfs-home-admin-passwords.txt
12ab3fc30374985bbc73015ca0359f0b3a4dcb6dd209bcc182d3a9d0075d1685  txtcmds-bin-netstat
84072fad2ecf8939f1fda1a38ee8433e4555682be82210ff6ec5f180452ed3b3  txtcmds-bin-ps
0e1167ceb9f2c546ba5ba3a0c1e98b78e6b8625eee6d963d16de5692b757e839  patriotpot-egress-firewall.sh
b0ae7a61f5ed3ca0055b7f3306be22127ef4a796b4e1562f06dff310b13e475c  session_cluster.py
e273bb8f3e7876f58ae2d1bb10220bc1eaf5560ba0cf2f60ab34c82d77026f42  discord_rate_governor.py
d5986e22011704756d751f43dc9333a547271cee81052c347d411e9e5e1b880a  threat_intel__init__.py
3cf659977250161e413d6047a29a43b35b3919fbfa2e6f119e08aac89b047cff  threat_intel_observables.py
e0d4b34a76eab34db939b18f37b1d1d987aad757827089494b32f17e27bda9fe  threat_intel_parameter_store.py
cd429e9d8c787084d52133f1e4b04925fb38f2458f8e1bc5b0f7fc386febf92a  threat_intel_cache.py
2bf42c481b14ca2dddbcb3fbe11bea7861cc9ca68a64ef078065fafc82c9c0b4  threat_intel_provider_result.py
4aca1fa502cd234d832b5cf012909cc8a886bf5f6aa29e1ff7ee1e79470d6e7e  threat_intel_http_client.py
200ff0abfbfb7a7197a0187139ee8e634ab7e9f1fa92f38400c6278701a3eefd  threat_intel_greynoise.py
2a2a5c43f27405f7ca2f7c6c4686de7872632c7737fd9ee02bac333833dd91d2  threat_intel_virustotal.py
4cb7a9d25631240c3e600be7c235d38029b06fd1390fb97768aafdd232f1da1d  threat_intel_shodan.py
7c4934aa7d28a2ae258254f39af5cdf67fcd8655dd57615b9f7c7f39985b34a4  threat_intel_broker.py
0a4b1ce978506c263e9c1c164dad3c0a1dc0fe944021e208f795606da742539e  threat_intel_rate_governor.py
68d5cf8d6d2cab24e25a83d6ccc987d38cbf61784fa8be75909eb31a0a65e6e1  threat_intel_worker.py
EOF

required_environment=(
  ASSET_BUCKET
  ASSET_PREFIX
  COWRIE_HOST_KEY_SECRET
  COWRIE_HOST_KEY_VERSION_ID
  DISCORD_PARAMETER_NAME
  EVIDENCE_BUCKET
  EVIDENCE_PREFIX
  AWS_PROFILE
  AWS_REGION
)
for variable in "${required_environment[@]}"; do
  if [[ -z "${!variable:-}" ]]; then
    echo "bootstrap error: required environment variable $variable is empty" >&2
    exit 1
  fi
done
if [[ "$AWS_PROFILE" != "$AWS_PROFILE_EXPECTED" || "$AWS_REGION" != "$AWS_REGION_EXPECTED" ]]; then
  echo "bootstrap error: AWS profile or region violates the control boundary" >&2
  exit 1
fi
if [[ ! "$ASSET_BUCKET" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]]; then
  echo "bootstrap error: invalid asset bucket" >&2
  exit 1
fi
if [[ ! "$ASSET_PREFIX" =~ ^bootstrap/[0-9a-f]{64}$ ]]; then
  echo "bootstrap error: invalid content-addressed asset prefix" >&2
  exit 1
fi
if [[ ! "$EVIDENCE_PREFIX" =~ ^control/[a-z0-9-]+/sensors/control-0$ ]]; then
  echo "bootstrap error: invalid evidence prefix" >&2
  exit 1
fi
if [[ ! "$DISCORD_PARAMETER_NAME" =~ ^/[A-Za-z0-9_.:/-]+$ ]]; then
  echo "bootstrap error: invalid Discord parameter name" >&2
  exit 1
fi

set_phase "asset_fetch"
mkdir -p "$ASSET_DIR"
chmod 0750 "$ASSET_DIR"

fetch_asset() {
  local expected="$1"
  local name="$2"
  local destination="$ASSET_DIR/$name"
  local candidate="$destination.new"
  rm -f "$candidate"
  aws s3api get-object \
    --bucket "$ASSET_BUCKET" \
    --key "$ASSET_PREFIX/$name" \
    "$candidate" \
    --output json \
    --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" >/dev/null
  printf '%s  %s\n' "$expected" "$candidate" | sha256sum --check --status
  mv -f "$candidate" "$destination"
  chmod 0640 "$destination"
}

while read -r expected name; do
  [[ -z "$expected" ]] && continue
  fetch_asset "$expected" "$name"
done <<<"$ASSET_HASHES"
while read -r _ name; do
  [[ -z "$name" ]] && continue
  sed -i 's/\r$//' "$ASSET_DIR/$name"
done <<<"$ASSET_HASHES"

set_phase "package_preparation"
echo "native bootstrap: package preparation"
yum update -y
yum install -y \
  amazon-cloudwatch-agent \
  aws-cfn-bootstrap \
  awscli \
  bzip2-devel \
  curl \
  findutils \
  gcc \
  gcc-c++ \
  gdbm-devel \
  git \
  gzip \
  iproute \
  libffi-devel \
  libuuid-devel \
  make \
  ncurses-devel \
  openssh-clients \
  openssl-devel \
  iptables-services \
  readline-devel \
  shadow-utils \
  sqlite-devel \
  tar \
  xz-devel \
  zlib-devel

for runtime in docker containerd podman; do
  if command -v "$runtime" >/dev/null 2>&1; then
    echo "bootstrap error: prohibited container runtime present: $runtime" >&2
    exit 1
  fi
done

set_phase "service_identities"
echo "native bootstrap: service identities"
getent group cowrie >/dev/null || groupadd --system cowrie
if ! id cowrie >/dev/null 2>&1; then
  useradd --system --gid cowrie --home-dir /opt/cowrie --no-create-home --shell /sbin/nologin cowrie
fi
usermod --lock --shell /sbin/nologin cowrie

getent group patriot-discord >/dev/null || groupadd --system patriot-discord
if ! id patriot-discord >/dev/null 2>&1; then
  useradd --system --gid patriot-discord --home-dir /var/lib/patriotpot-discord \
    --no-create-home --shell /sbin/nologin patriot-discord
fi
usermod --lock --shell /sbin/nologin --append --groups cowrie patriot-discord

getent group patriot-archive >/dev/null || groupadd --system patriot-archive
if ! id patriot-archive >/dev/null 2>&1; then
  useradd --system --gid patriot-archive --home-dir /var/lib/patriotpot-archive \
    --no-create-home --shell /sbin/nologin patriot-archive
fi
usermod --lock --shell /sbin/nologin --append --groups cowrie patriot-archive

install -d -m 0700 -o patriot-discord -g patriot-discord /var/lib/patriotpot-discord
install -d -m 0700 -o patriot-archive -g patriot-archive /var/lib/patriotpot-archive
install -d -m 0700 -o patriot-archive -g patriot-archive /var/lib/patriotpot-archive/spool
install -d -m 0755 -o root -g root /var/log/patriotpot /etc/patriotpot /usr/local/libexec
touch /var/log/patriotpot/discord.log /var/log/patriotpot/archive.log
chown patriot-discord:patriot-discord /var/log/patriotpot/discord.log
chown patriot-archive:patriot-archive /var/log/patriotpot/archive.log
chmod 0600 /var/log/patriotpot/discord.log /var/log/patriotpot/archive.log

set_phase "side_by_side_python"
echo "native bootstrap: CPython $PYTHON_VERSION side-by-side"
python_prefix="/opt/python/$PYTHON_VERSION"
python_binary="$python_prefix/bin/python3.8"
if [[ ! -x "$python_binary" ]] || [[ "$("$python_binary" --version 2>&1)" != "Python $PYTHON_VERSION" ]]; then
  install -d -m 0755 /var/cache/patriotpot /usr/local/src
  python_archive="/var/cache/patriotpot/Python-$PYTHON_VERSION.tgz"
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 \
    "https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tgz" \
    --output "$python_archive"
  printf '%s  %s\n' "$PYTHON_SHA256" "$python_archive" | sha256sum --check --status
  rm -rf "/usr/local/src/Python-$PYTHON_VERSION"
  tar -xzf "$python_archive" -C /usr/local/src
  pushd "/usr/local/src/Python-$PYTHON_VERSION" >/dev/null
  ./configure --prefix="$python_prefix" --with-ensurepip=install
  make -j"$(getconf _NPROCESSORS_ONLN)"
  make altinstall
  popd >/dev/null
fi
if [[ "$("$python_binary" --version 2>&1)" != "Python $PYTHON_VERSION" ]]; then
  echo "bootstrap error: side-by-side Python validation failed" >&2
  exit 1
fi

set_phase "archive_dependencies"
echo "native bootstrap: pinned boto3 archive environment"
install -d -m 0755 -o root -g root /opt/patriotpot-archive
"$python_binary" -m venv /opt/patriotpot-archive/venv
/opt/patriotpot-archive/venv/bin/python -m pip install --disable-pip-version-check \
  pip==23.0.1 setuptools==60.10.0 wheel==0.38.4
/opt/patriotpot-archive/venv/bin/python -m pip install --disable-pip-version-check \
  --requirement "$ASSET_DIR/archive-requirements.lock"
/opt/patriotpot-archive/venv/bin/python -m pip check
/opt/patriotpot-archive/venv/bin/python -c \
  'import boto3, botocore; assert boto3.__version__ == "1.35.99"; assert botocore.__version__ == "1.35.99"'
chown -R root:patriot-archive /opt/patriotpot-archive
chmod -R o-rwx,g+rX /opt/patriotpot-archive

set_phase "cowrie_source"
echo "native bootstrap: Cowrie $COWRIE_VERSION at pinned commit"
if [[ ! -d /opt/cowrie/.git ]]; then
  rm -rf /opt/cowrie
  git clone --depth 1 --branch "$COWRIE_VERSION" https://github.com/cowrie/cowrie.git /opt/cowrie
fi
actual_commit="$(git -C /opt/cowrie rev-parse HEAD)"
if [[ "$actual_commit" != "$COWRIE_COMMIT" ]]; then
  echo "bootstrap error: Cowrie commit mismatch" >&2
  exit 1
fi
set_phase "cowrie_dependencies"
rm -f /opt/cowrie/pyproject.toml
"$python_binary" -m venv /opt/cowrie/venv
/opt/cowrie/venv/bin/python -m pip install --disable-pip-version-check \
  pip==23.0.1 setuptools==60.10.0 wheel==0.38.4
/opt/cowrie/venv/bin/python -m pip install --disable-pip-version-check \
  --requirement "$ASSET_DIR/cowrie-requirements.lock"
/opt/cowrie/venv/bin/python -m pip install --disable-pip-version-check \
  --no-deps --no-build-isolation --editable /opt/cowrie
/opt/cowrie/venv/bin/python -m pip check
/opt/cowrie/venv/bin/python -c 'import bcrypt, cowrie, cryptography, tftpy, treq, twisted'
(
  cd /opt/cowrie
  PYTHONPATH=/opt/cowrie/src /opt/cowrie/venv/bin/twistd --help >/dev/null 2>&1
)
find \
  /opt/cowrie/venv/lib/python3.8/site-packages/twisted/plugins \
  /opt/cowrie/src/twisted/plugins \
  -maxdepth 1 -name dropin.cache -exec chmod 0644 {} \;
chgrp -R cowrie /opt/cowrie
chmod -R g+rX /opt/cowrie

actual_fs_hash="$(sha256sum /opt/cowrie/share/cowrie/fs.pickle | awk '{print $1}')"
if [[ "$actual_fs_hash" != "$COWRIE_FS_SHA256" ]]; then
  echo "bootstrap error: stock Cowrie v2.5.0 fs.pickle hash mismatch" >&2
  exit 1
fi

set_phase "cowrie_json_logging"
echo "native bootstrap: enforce private group-readable Cowrie JSON logging"
jsonlog_module="/opt/cowrie/src/cowrie/output/jsonlog.py"
actual_jsonlog_hash="$(sha256sum "$jsonlog_module" | awk '{print $1}')"
if [[ "$actual_jsonlog_hash" == "$COWRIE_JSONLOG_UPSTREAM_SHA256" ]]; then
  if [[ "$(grep -Fc 'defaultMode=0o664' "$jsonlog_module")" -ne 1 ]]; then
    echo "bootstrap error: Cowrie JSON log mode patch target is ambiguous" >&2
    exit 1
  fi
  sed -i 's/defaultMode=0o664/defaultMode=0o640/' "$jsonlog_module"
elif [[ "$actual_jsonlog_hash" != "$COWRIE_JSONLOG_PATCHED_SHA256" ]]; then
  echo "bootstrap error: Cowrie JSON logger provenance mismatch" >&2
  exit 1
fi
actual_jsonlog_hash="$(sha256sum "$jsonlog_module" | awk '{print $1}')"
if [[ "$actual_jsonlog_hash" != "$COWRIE_JSONLOG_PATCHED_SHA256" ]] ||
   [[ "$(grep -Fc 'defaultMode=0o640' "$jsonlog_module")" -ne 1 ]]; then
  echo "bootstrap error: Cowrie JSON log mode patch validation failed" >&2
  exit 1
fi

set_phase "recovered_control_assets"
echo "native bootstrap: recovered control assets"
install -d -m 0755 -o root -g root \
  /opt/cowrie/etc \
  /opt/cowrie/honeyfs/etc \
  /opt/cowrie/honeyfs/home/admin \
  /opt/cowrie/honeyfs/var/www \
  /opt/cowrie/honeyfs/opt \
  /opt/cowrie/share/cowrie/txtcmds/bin
install -d -m 0750 -o cowrie -g cowrie \
  /opt/cowrie/var \
  /opt/cowrie/var/lib \
  /opt/cowrie/var/lib/cowrie \
  /opt/cowrie/var/lib/cowrie/downloads \
  /opt/cowrie/var/log \
  /opt/cowrie/var/log/cowrie
install -m 0644 -o root -g root "$ASSET_DIR/cowrie.cfg" /opt/cowrie/etc/cowrie.cfg
cat >>/opt/cowrie/etc/cowrie.cfg <<'EOF'

; 2026 pre-exposure safety override: TCP/2223 is deliberately disabled.
[telnet]
enabled = false
EOF
install -m 0644 -o root -g root "$ASSET_DIR/userdb.txt" /opt/cowrie/etc/userdb.txt
install -m 0644 -o root -g root "$ASSET_DIR/honeyfs-etc-passwd" /opt/cowrie/honeyfs/etc/passwd
install -m 0644 -o root -g root \
  "$ASSET_DIR/honeyfs-home-admin-passwords.txt" \
  /opt/cowrie/honeyfs/home/admin/passwords.txt
install -m 0644 -o root -g root "$ASSET_DIR/txtcmds-bin-netstat" /opt/cowrie/share/cowrie/txtcmds/bin/netstat
install -m 0644 -o root -g root "$ASSET_DIR/txtcmds-bin-ps" /opt/cowrie/share/cowrie/txtcmds/bin/ps
touch /opt/cowrie/var/log/cowrie/cowrie.log /opt/cowrie/var/log/cowrie/cowrie.json
chown cowrie:cowrie /opt/cowrie/var/log/cowrie/cowrie.log /opt/cowrie/var/log/cowrie/cowrie.json
chmod 0640 /opt/cowrie/var/log/cowrie/cowrie.log /opt/cowrie/var/log/cowrie/cowrie.json

set_phase "host_key_install"
echo "native bootstrap: rotated service-only Cowrie host key"
install -m 0755 -o root -g root "$ASSET_DIR/install-host-key.py" /usr/local/libexec/install-cowrie-host-key.py
aws secretsmanager get-secret-value \
  --secret-id "$COWRIE_HOST_KEY_SECRET" \
  --version-id "$COWRIE_HOST_KEY_VERSION_ID" \
  --query SecretString \
  --output text \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" |
  "$python_binary" /usr/local/libexec/install-cowrie-host-key.py
test "$(stat -c '%U:%G:%a' /opt/cowrie/etc/ssh_host_rsa_key)" = "cowrie:cowrie:600"
ssh-keygen -lf /opt/cowrie/etc/ssh_host_rsa_key.pub

set_phase "monitoring_archive_services"
echo "native bootstrap: monitoring and archive services"
install -m 0755 -o root -g root "$ASSET_DIR/discord-monitor.py" /usr/local/libexec/patriotpot-discord-monitor.py
install -m 0644 -o root -g root "$ASSET_DIR/session_cluster.py" /usr/local/libexec/session_cluster.py
install -m 0644 -o root -g root "$ASSET_DIR/discord_rate_governor.py" /usr/local/libexec/discord_rate_governor.py
install -d -m 0755 -o root -g root /usr/local/libexec/threat_intel
install -m 0644 -o root -g root "$ASSET_DIR/threat_intel__init__.py" /usr/local/libexec/threat_intel/__init__.py
install -m 0644 -o root -g root "$ASSET_DIR/threat_intel_observables.py" /usr/local/libexec/threat_intel/observables.py
install -m 0644 -o root -g root "$ASSET_DIR/threat_intel_parameter_store.py" /usr/local/libexec/threat_intel/parameter_store.py
install -m 0644 -o root -g root "$ASSET_DIR/threat_intel_cache.py" /usr/local/libexec/threat_intel/cache.py
install -m 0644 -o root -g root "$ASSET_DIR/threat_intel_provider_result.py" /usr/local/libexec/threat_intel/provider_result.py
install -m 0644 -o root -g root "$ASSET_DIR/threat_intel_http_client.py" /usr/local/libexec/threat_intel/http_client.py
install -m 0644 -o root -g root "$ASSET_DIR/threat_intel_greynoise.py" /usr/local/libexec/threat_intel/greynoise.py
install -m 0644 -o root -g root "$ASSET_DIR/threat_intel_virustotal.py" /usr/local/libexec/threat_intel/virustotal.py
install -m 0644 -o root -g root "$ASSET_DIR/threat_intel_shodan.py" /usr/local/libexec/threat_intel/shodan.py
install -m 0644 -o root -g root "$ASSET_DIR/threat_intel_broker.py" /usr/local/libexec/threat_intel/broker.py
install -m 0644 -o root -g root "$ASSET_DIR/threat_intel_rate_governor.py" /usr/local/libexec/threat_intel/rate_governor.py
install -m 0644 -o root -g root "$ASSET_DIR/threat_intel_worker.py" /usr/local/libexec/threat_intel/worker.py
install -d -m 0700 -o patriot-discord -g patriot-discord /var/lib/patriotpot-discord/threat-intel
install -m 0755 -o root -g root "$ASSET_DIR/s3-archive.py" /usr/local/libexec/patriotpot-s3-archive.py
install -m 0644 -o root -g root "$ASSET_DIR/cowrie.service" /etc/systemd/system/cowrie.service
install -m 0644 -o root -g root "$ASSET_DIR/patriotpot-discord.service" /etc/systemd/system/patriotpot-discord.service
install -m 0755 -o root -g root \
  "$ASSET_DIR/patriotpot-egress-firewall.sh" \
  /usr/local/libexec/patriotpot-egress-firewall
install -m 0644 -o root -g root \
  "$ASSET_DIR/patriotpot-egress-firewall.service" \
  /etc/systemd/system/patriotpot-egress-firewall.service
install -m 0644 -o root -g root "$ASSET_DIR/patriotpot-archive.service" /etc/systemd/system/patriotpot-archive.service
install -m 0644 -o root -g root "$ASSET_DIR/patriotpot-archive.timer" /etc/systemd/system/patriotpot-archive.timer
install -m 0644 -o root -g root "$ASSET_DIR/patriotpot-logrotate" /etc/logrotate.d/patriotpot
install -d -m 0755 -o root -g root /opt/aws/amazon-cloudwatch-agent/etc
install -m 0644 -o root -g root "$ASSET_DIR/cloudwatch-agent.json" \
  /opt/aws/amazon-cloudwatch-agent/etc/patriotpot.json

cat >/etc/patriotpot/discord.env <<EOF
AWS_CONFIG_FILE=/etc/aws/config
AWS_PROFILE=$AWS_PROFILE
AWS_REGION=$AWS_REGION
DISCORD_PARAMETER_NAME=$DISCORD_PARAMETER_NAME
COWRIE_JSON_PATH=/opt/cowrie/var/log/cowrie/cowrie.json
DISCORD_STATE_PATH=/var/lib/patriotpot-discord/state.json
DISCORD_OPS_LOG=/var/log/patriotpot/discord.log
GREYNOISE_PARAMETER_NAME=/patriotpot/2026-control/greynoise-api-key
VIRUSTOTAL_PARAMETER_NAME=/patriotpot/2026-control/virustotal-api-key
SHODAN_PARAMETER_NAME=/patriotpot/2026-control/shodan-api-key
THREAT_INTEL_CACHE_DIR=/var/lib/patriotpot-discord/threat-intel
EOF
chmod 0640 /etc/patriotpot/discord.env
chown root:patriot-discord /etc/patriotpot/discord.env

cat >/etc/patriotpot/archive.env <<EOF
AWS_CONFIG_FILE=/etc/aws/config
AWS_PROFILE=$AWS_PROFILE
AWS_REGION=$AWS_REGION
EVIDENCE_BUCKET=$EVIDENCE_BUCKET
EVIDENCE_PREFIX=$EVIDENCE_PREFIX
COWRIE_JSON_PATH=/opt/cowrie/var/log/cowrie/cowrie.json
ARCHIVE_STATE_PATH=/var/lib/patriotpot-archive/state.json
ARCHIVE_SPOOL_DIR=/var/lib/patriotpot-archive/spool
ARCHIVE_OPS_LOG=/var/log/patriotpot/archive.log
EOF
chmod 0640 /etc/patriotpot/archive.env
chown root:patriot-archive /etc/patriotpot/archive.env

set_phase "sidecar_self_tests"
runuser -u patriot-discord -- env \
  DISCORD_OPS_LOG=/var/log/patriotpot/discord.log \
  "$python_binary" /usr/local/libexec/patriotpot-discord-monitor.py --self-test
runuser -u patriot-archive -- env \
  EVIDENCE_BUCKET="$EVIDENCE_BUCKET" \
  EVIDENCE_PREFIX="$EVIDENCE_PREFIX" \
  ARCHIVE_OPS_LOG=/var/log/patriotpot/archive.log \
  /opt/patriotpot-archive/venv/bin/python \
    /usr/local/libexec/patriotpot-s3-archive.py --self-test

set_phase "native_service_start"
systemctl daemon-reload
systemctl enable --now patriotpot-egress-firewall.service
systemctl is-active --quiet patriotpot-egress-firewall.service
systemctl enable amazon-ssm-agent
systemctl restart amazon-ssm-agent
systemctl disable --now sshd
systemctl mask sshd
systemctl enable --now cowrie.service

set_phase "cowrie_listener_check"
for attempt in $(seq 1 60); do
  if (exec 3<>/dev/tcp/127.0.0.1/2222) 2>/dev/null; then
    exec 3>&-
    break
  fi
  if [[ "$attempt" -eq 60 ]]; then
    echo "bootstrap error: Cowrie did not listen on TCP/2222" >&2
    exit 1
  fi
  sleep 2
done
if ss -lntH | awk '{print $4}' | grep -Eq '(^|:)2223$'; then
  echo "bootstrap error: prohibited TCP/2223 listener detected" >&2
  exit 1
fi

set_phase "discord_service_enablement"
systemctl enable --now patriotpot-discord.service
set_phase "archive_timer_enablement"
systemctl enable --now patriotpot-archive.timer
set_phase "archive_initial_run"
systemctl start patriotpot-archive.service

set_phase "cloudwatch_setup"
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config \
  -m ec2 \
  -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/patriotpot.json
systemctl enable amazon-cloudwatch-agent

set_phase "baseline_declaration"
cat >/opt/cowrie/PATRIOTPOT-BASELINE <<EOF
baseline=patriotpot-2026-control-native
host_os=Amazon Linux 2
python=$PYTHON_VERSION
cowrie_tag=$COWRIE_VERSION
cowrie_commit=$COWRIE_COMMIT
fs_pickle_sha256=$COWRIE_FS_SHA256
fs_pickle_provenance=stock Cowrie v2.5.0 substitution
cfg_provenance=recovered candidate; exact live 2025 provenance unverified
telnet_2223=disabled
EOF
chmod 0444 /opt/cowrie/PATRIOTPOT-BASELINE
chown root:root /opt/cowrie/PATRIOTPOT-BASELINE

set_phase "final_runtime_validation"
systemctl is-active --quiet cowrie.service
systemctl is-active --quiet patriotpot-egress-firewall.service
systemctl is-active --quiet patriotpot-discord.service
systemctl is-enabled --quiet patriotpot-archive.timer
systemctl is-active --quiet amazon-ssm-agent
if systemctl is-active --quiet sshd; then
  echo "bootstrap error: sshd remains active" >&2
  exit 1
fi

echo "native bootstrap complete"
echo "cowrie_commit=$actual_commit"
echo "stock_fs_pickle_sha256=$actual_fs_hash"
echo "python_version=$("$python_binary" --version 2>&1)"
