#!/bin/bash
# =============================================================================
# deploy-forwarder.sh - Provision the TCP pass-through forwarder in cn-hongkong.
#
# A byte-level hop for one target: the notary pins
#     "api-m.paypal.com@<this IP>"
# and dials it on 443; haproxy forwards the TLS stream untouched to api-m's own
# edges, so the certificate, the transcript and every audit digest are PayPal's
# and the notary's, not ours. See docs/tls-proxy.md ("Egress, and what
# compensates for it") for why it exists and when the alternative (moving the
# notary's egress) is the better trade.
#
# Hong Kong, not the notary's own region: the whole point is a different source
# address, and cn-hongkong is the closest region this account already uses (the
# staging OSS bucket lives there). The refusal is aimed at the notary's address,
# not at Alibaba as a whole, so any egress PayPal does not refuse will do.
#
# Idempotent: re-running reuses the VPC, vswitch, security group, EIP and
# instance it created (by name), so it is safe after a failed half-run.
#
# Usage:
#   bash deploy-forwarder.sh              # full: image import + infra + boot
#   IMAGE_ID=m-xxx bash deploy-forwarder.sh    # reuse an already imported image
#   VERIFY_ONLY=1 bash deploy-forwarder.sh     # just re-run the TLS check
#   DESTROY=1 bash deploy-forwarder.sh         # tear everything down
#
# Costs (cn-hongkong, pay-as-you-go): one small instance + one pay-by-traffic
# EIP. The forwarder carries only TLS binary; a 10 Mbps cap is generous.
# =============================================================================
set -eo pipefail

REGION="${ALI_REGION:-cn-hongkong}"
OSS_BUCKET="${ALI_OSS_BUCKET:-paypal-tdx-relay-1792227992}"
OSS_OBJECT="${OSS_OBJECT:-forwarder/disk-forwarder.raw}"
DISK_FILE="${DISK_FILE:-output-forwarder/disk-forwarder.raw}"
VPC_CIDR="${VPC_CIDR:-172.16.0.0/16}"
VSW_CIDR="${VSW_CIDR:-172.16.1.0/24}"
INSTANCE_TYPE="${INSTANCE_TYPE:-ecs.e-c1m1.large}"
INSTANCE_NAME="${INSTANCE_NAME:-paypal-tcp-forwarder}"
BANDWIDTH="${BANDWIDTH:-10}"
TARGET_HOST="${TARGET_HOST:-api-m.paypal.com}"
SECONDS_WAIT="${SECONDS_WAIT:-240}"

need() { command -v "$1" >/dev/null || { echo "❌ $1 not found"; exit 1; }; }
need aliyun; need jq

say() { printf '%s\n' "$*"; }
die() { echo "❌ $*"; exit 1; }

ALIYUN_REGION=(--RegionId "$REGION")

# ---------------------------------------------------------------- helpers ----
# One instance by name (empty if none). DescribeInstances takes a name filter.
instance_by_name() {
    aliyun ecs DescribeInstances "${ALIYUN_REGION[@]}" \
        --InstanceName "$1" 2>/dev/null \
        | jq -r '.Instances.Instance[0].InstanceId // empty'
}

instance_status() {
    aliyun ecs DescribeInstances "${ALIYUN_REGION[@]}" \
        | jq -r --arg id "$1" '.Instances.Instance[]? | select(.InstanceId==$id) | .Status'
}

instance_private_ip() {
    aliyun ecs DescribeInstances "${ALIYUN_REGION[@]}" \
        | jq -r --arg id "$1" \
            '.Instances.Instance[]? | select(.InstanceId==$id) | .VpcAttributes.PrivateIpAddress.IpAddress[0] // empty'
}

eip_by_name() {
    aliyun vpc DescribeEipAddresses "${ALIYUN_REGION[@]}" --EipName "paypal-forwarder" 2>/dev/null \
        | jq -r '.EipAddresses.EipAddress[0].AllocationId // empty'
}

eip_address() {
    aliyun vpc DescribeEipAddresses "${ALIYUN_REGION[@]}" --AllocationId "$1" 2>/dev/null \
        | jq -r '.EipAddresses.EipAddress[0].IpAddress // empty'
}

eip_binding() {
    aliyun vpc DescribeEipAddresses "${ALIYUN_REGION[@]}" --AllocationId "$1" 2>/dev/null \
        | jq -r '.EipAddresses.EipAddress[0].InstanceId // empty'
}

# Does the relay actually hand back api-m's certificate, byte for byte?
verify_passthrough() {
    local ip="$1"
    say ""
    say "🔎 Verifying raw TLS passthrough to $ip (SNI $TARGET_HOST)"
    local out
    out=$(timeout 20 openssl s_client -connect "$ip:443" -servername "$TARGET_HOST" \
            -showcerts </dev/null 2>&1) || {
        say "❌ no TLS handshake through $ip:443"
        say "$out" | tail -5
        return 1
    }
    local subj san issuer
    subj=$(printf '%s' "$out" | openssl x509 -noout -subject 2>/dev/null)
    san=$(printf '%s' "$out" | openssl x509 -noout -ext subjectAltName 2>/dev/null | tr -d '\n' | sed 's/  */ /g')
    issuer=$(printf '%s' "$out" | openssl x509 -noout -issuer 2>/dev/null)
    say "   $subj"
    say "   $issuer"
    say "   $san"
    # The whole point: the certificate is PayPal's, so the notary's pinning and
    # the auditor's chain check are unchanged. A forwarder with its own cert
    # would be a completely different (and much worse) design.
    if ! printf '%s' "$subj$san" | grep -qi "$TARGET_HOST"; then
        say "❌ the certificate does not name $TARGET_HOST — this is not a transparent hop"
        return 1
    fi
    # `-brief` style timing: a real HTTP round trip through the hop, not just a
    # handshake, because a forwarder that accepts and then idles looks fine on
    # a handshake alone (the same failure mode the notary's probes catch).
    local t0 t1
    t0=$(date +%s%N)
    printf 'GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n' "$TARGET_HOST" \
        | timeout 25 openssl s_client -quiet -connect "$ip:443" -servername "$TARGET_HOST" \
            2>/dev/null | head -1 | grep -q "HTTP/" || {
        say "❌ handshake works but no HTTP response through the hop"
        return 1
    }
    t1=$(date +%s%N)
    say "✅ passthrough OK — $TARGET_HOST certificate, HTTP answered in $(( (t1-t0)/1000000 )) ms"
}

# ---------------------------------------------------------------- destroy ----
if [[ "${DESTROY:-0}" == "1" ]]; then
    ID=$(instance_by_name "$INSTANCE_NAME")
    if [[ -n "$ID" ]]; then
        say "🗑  stopping/deleting $ID"
        aliyun ecs StopInstance "${ALIYUN_REGION[@]}" --InstanceId "$ID" --ForceStop true >/dev/null 2>&1 || true
        sleep 15
        aliyun ecs DeleteInstance "${ALIYUN_REGION[@]}" --InstanceId "$ID" --Force true >/dev/null 2>&1 \
            || say "⚠️  delete failed — remove $ID by hand"
    fi
    EIP=$(eip_by_name)
    if [[ -n "$EIP" ]]; then
        say "🗑  releasing EIP $EIP"
        aliyun vpc UnassociateEipAddress "${ALIYUN_REGION[@]}" --AllocationId "$EIP" >/dev/null 2>&1 || true
        aliyun vpc ReleaseEipAddress "${ALIYUN_REGION[@]}" --AllocationId "$EIP" >/dev/null 2>&1 \
            || say "⚠️  release failed — release $EIP by hand"
    fi
    say "⚠️  VPC/vswitch/security group left in place (they are free and reusable):"
    say "    delete them by hand if this forwarder is gone for good."
    exit 0
fi

# ---------------------------------------------------------------- image ------
if [[ -z "${IMAGE_ID:-}" ]]; then
    [[ -f "$DISK_FILE" ]] || die "$DISK_FILE missing — run: bash build-forwarder-image.sh"
    SHA=$(sha256sum "$DISK_FILE" | cut -d' ' -f1)
    say "📦 [1/5] staging $(basename "$DISK_FILE") ($(du -h "$DISK_FILE" | cut -f1), sha256=$SHA) in oss://$OSS_BUCKET"
    # The HK bucket is the one OSS endpoint reachable from outside mainland, and
    # ImportImage requires the object to be in the image's region.
    aliyun oss stat "oss://$OSS_BUCKET/$OSS_OBJECT" -e oss-cn-hongkong.aliyuncs.com >/dev/null 2>&1 || {
        aliyun oss cp "$DISK_FILE" "oss://$OSS_BUCKET/$OSS_OBJECT" \
            -e oss-cn-hongkong.aliyuncs.com --force >/dev/null \
            || die "upload to oss://$OSS_BUCKET/$OSS_OBJECT failed"
    }
    say "✅ object present"

    IMAGE_NAME="paypal-tcp-forwarder-$(date +%Y%m%d%H%M)"
    say "🖼  [2/5] ImportImage $IMAGE_NAME ($REGION)"
    aliyun ecs ImportImage "${ALIYUN_REGION[@]}" \
        --ImageName "$IMAGE_NAME" \
        --Description "TCP passthrough forwarder (haproxy, mode tcp) sha256=$SHA" \
        --DiskDeviceMapping.1.OSSBucket "$OSS_BUCKET" \
        --DiskDeviceMapping.1.OSSObject "$OSS_OBJECT" \
        --DiskDeviceMapping.1.Format RAW \
        --DiskDeviceMapping.1.DiskImageSize 1 \
        --Architecture x86_64 --OSType linux --Platform Debian \
        --BootMode BIOS >/dev/null || die "ImportImage failed"
    for _ in $(seq 1 60); do
        IMAGE_ID=$(aliyun ecs DescribeImages "${ALIYUN_REGION[@]}" --ImageName "$IMAGE_NAME" 2>/dev/null \
            | jq -r '.Images.Image[0].ImageId // empty')
        [[ -n "$IMAGE_ID" ]] || { sleep 5; continue; }
        ST=$(aliyun ecs DescribeImages "${ALIYUN_REGION[@]}" --ImageId "$IMAGE_ID" 2>/dev/null \
            | jq -r '.Images.Image[0].Status // empty')
        [[ "$ST" == "Available" || "$ST" == "AVAILABLE" ]] && break
        [[ "$ST" == "Unavailable" || "$ST" == "UNAVAILABLE" ]] && die "image import failed"
        sleep 10
    done
    [[ -n "${IMAGE_ID:-}" ]] || die "image never appeared"
    say "✅ image $IMAGE_ID"
else
    say "⏭  [1-2/5] reusing IMAGE_ID=$IMAGE_ID"
fi

# ---------------------------------------------------------------- network ----
say "🌐 [3/5] network ($REGION)"
VPC_ID=$(aliyun vpc DescribeVpcs "${ALIYUN_REGION[@]}" --PageSize 50 2>/dev/null \
    | jq -r '.Vpcs.Vpc[]? | select(.VpcName=="paypal-forwarder") | .VpcId' | head -1)
if [[ -z "$VPC_ID" ]]; then
    VPC_ID=$(aliyun vpc CreateVpc "${ALIYUN_REGION[@]}" --CidrBlock "$VPC_CIDR" \
        --VpcName paypal-forwarder --Description "TCP passthrough forwarder for api-m" 2>/dev/null \
        | jq -r '.VpcId // empty')
    [[ -n "$VPC_ID" ]] || die "CreateVpc failed"
    sleep 6
    say "   vpc $VPC_ID created"
else
    say "   vpc $VPC_ID reused"
fi

VSW_ID=$(aliyun vpc DescribeVSwitches "${ALIYUN_REGION[@]}" --VpcId "$VPC_ID" 2>/dev/null \
    | jq -r '.VSwitches.VSwitch[]? | select(.VSwitchName=="paypal-forwarder") | .VSwitchId' | head -1)
if [[ -z "$VSW_ID" ]]; then
    ZONE_ID=$(aliyun ecs DescribeZones "${ALIYUN_REGION[@]}" 2>/dev/null \
        | jq -r '.Zones.Zone[0].ZoneId // empty')
    [[ -n "$ZONE_ID" ]] || die "no zone in $REGION"
    VSW_ID=$(aliyun vpc CreateVSwitch "${ALIYUN_REGION[@]}" --VpcId "$VPC_ID" \
        --CidrBlock "$VSW_CIDR" --ZoneId "$ZONE_ID" --VSwitchName paypal-forwarder 2>/dev/null \
        | jq -r '.VSwitchId // empty')
    [[ -n "$VSW_ID" ]] || die "CreateVSwitch failed"
    say "   vswitch $VSW_ID in $ZONE_ID created"
else
    ZONE_ID=$(aliyun vpc DescribeVSwitches "${ALIYUN_REGION[@]}" --VpcId "$VPC_ID" 2>/dev/null \
        | jq -r --arg v "$VSW_ID" '.VSwitches.VSwitch[]? | select(.VSwitchId==$v) | .ZoneId')
    say "   vswitch $VSW_ID in $ZONE_ID reused"
fi

SG_ID=$(aliyun ecs DescribeSecurityGroups "${ALIYUN_REGION[@]}" --VpcId "$VPC_ID" 2>/dev/null \
    | jq -r '.SecurityGroups.SecurityGroup[]? | select(.SecurityGroupName=="paypal-forwarder") | .SecurityGroupId' | head -1)
if [[ -z "$SG_ID" ]]; then
    SG_ID=$(aliyun ecs CreateSecurityGroup "${ALIYUN_REGION[@]}" --VpcId "$VPC_ID" \
        --SecurityGroupName paypal-forwarder \
        --Description "admit 443 only" 2>/dev/null | jq -r '.SecurityGroupId // empty')
    [[ -n "$SG_ID" ]] || die "CreateSecurityGroup failed"
    say "   security group $SG_ID created"
else
    say "   security group $SG_ID reused"
fi
# 443/tcp in; SSH deliberately absent (the image has no sshd and no agent).
aliyun ecs AuthorizeSecurityGroup "${ALIYUN_REGION[@]}" --SecurityGroupId "$SG_ID" \
    --IpProtocol tcp --PortRange 443/443 --SourceCidrIp 0.0.0.0/0 \
    --Description "TLS passthrough for the notary" >/dev/null 2>&1 \
    || say "   (443 rule already present)"

# ---------------------------------------------------------------- instance ---
ID=$(instance_by_name "$INSTANCE_NAME")
if [[ -z "$ID" ]]; then
    say "🚀 [4/5] RunInstances $INSTANCE_TYPE"
    # No public IP at launch: the address has to be a STABLE EIP, because it is
    # written into a boot-time pin - a stop/start must not move it.
    OUT=$(aliyun ecs RunInstances "${ALIYUN_REGION[@]}" \
        --InstanceName "$INSTANCE_NAME" \
        --ImageId "$IMAGE_ID" --InstanceType "$INSTANCE_TYPE" \
        --SecurityGroupId "$SG_ID" --VSwitchId "$VSW_ID" \
        --SystemDisk.Category cloud_essd --SystemDisk.Size 20 \
        --InternetMaxBandwidthOut 0 \
        --HostName paypal-forwarder --Amount 1 2>&1) || true
    ID=$(echo "$OUT" | jq -r '.InstanceIdSets.InstanceIdSet[0] // empty' 2>/dev/null)
    [[ -n "$ID" ]] || { say "$OUT"; die "RunInstances failed"; }
    say "   instance $ID created (waiting for Running)"
else
    say "🚀 [4/5] instance $ID reused"
    if [[ "$(instance_status "$ID")" != "Running" ]]; then
        aliyun ecs StartInstance "${ALIYUN_REGION[@]}" --InstanceId "$ID" >/dev/null 2>&1 || true
    fi
fi
for _ in $(seq 1 60); do
    [[ "$(instance_status "$ID")" == "Running" ]] && break
    sleep 5
done
[[ "$(instance_status "$ID")" == "Running" ]] || die "instance $ID never reached Running"
PRIVATE_IP=$(instance_private_ip "$ID")
say "   running, private $PRIVATE_IP"

# ---------------------------------------------------------------- EIP --------
EIP_ID=$(eip_by_name)
if [[ -z "$EIP_ID" ]]; then
    say "📌 Allocating EIP (pay-by-traffic, ${BANDWIDTH} Mbps)"
    EIP_ID=$(aliyun vpc AllocateEipAddress "${ALIYUN_REGION[@]}" \
        --InternetChargeType PayByTraffic --Bandwidth "$BANDWIDTH" \
        --Name paypal-forwarder 2>/dev/null | jq -r '.AllocationId // empty')
    [[ -n "$EIP_ID" ]] || die "AllocateEipAddress failed"
fi
if [[ "$(eip_binding "$EIP_ID")" != "$ID" ]]; then
    aliyun vpc AssociateEipAddress "${ALIYUN_REGION[@]}" --AllocationId "$EIP_ID" \
        --InstanceId "$ID" --InstanceType EcsInstance >/dev/null \
        || die "AssociateEipAddress failed"
fi
IP=$(eip_address "$EIP_ID")
[[ -n "$IP" ]] || die "could not read the EIP address"
say "✅ forwarder up: $IP (allocation $EIP_ID, instance $ID)"

# ---------------------------------------------------------------- verify -----
say "🧪 [5/5] verify"
# haproxy needs a moment to bind after boot; poll rather than sleep blindly.
for _ in $(seq 1 30); do
    timeout 5 bash -c "echo > /dev/tcp/$IP/443" 2>/dev/null && break
    sleep 5
done
verify_passthrough "$IP" || die "the hop is up but not transparent — check the instance console"

cat <<EOF

==============================================================
Pin it in the deployment config (services.tls_proxy.relay_targets):

  "api-m.paypal.com@$IP"

Nothing else changes: the address is admitted on 443 by the same
rule that admitted the old pins, and /etc/hosts gets
"$IP api-m.paypal.com". The certificate the notary verifies is
still PayPal's, so no audit digest moves.

Apply with a config-only redeploy (stop -> ModifyInstanceAttribute
--UserData -> start; no image rebuild, no pin rotation).
==============================================================
EOF
