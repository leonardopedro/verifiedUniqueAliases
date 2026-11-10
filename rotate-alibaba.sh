#!/bin/bash
# =============================================================================
# rotate-alibaba.sh - One pass from source to a rotated prod enclave:
#   preflight -> build -> stage -> import -> rotate -> verify
#
# Why this exists: every hop in the rotation has a failure mode that silently
# boots the WRONG bytes — a truncated OSS upload, an image imported from a
# stale object, a disk swapped while user_data still carries the previous
# config. Each phase below ends in a digest assertion, and the next phase is
# not allowed to start until it passes. That is the whole point of the script:
# not to be shorter than the manual run, but to refuse to continue.
#
# Gates:
#   1 preflight  tools present, config JSON parses, instance exists,
#                verify.html == index.html (byte-identical repo invariant),
#                tree clean (the disk digest must map to a commit)
#   2 build      build-alibaba-docker.sh -> disk sha256/md5/size + binary sha
#   3 stage      bytes to OSS, then Content-Length == local size and
#                ETag == local md5. Relay legs default to the proven path:
#                operator -> HK bucket (presigned PUT) -> relay ECS intranet
#                PUT -> Beijing bucket, ETag checked on both hops.
#                RELAY_MODE=direct uses `aliyun oss cp` (mainland host only).
#   4 import     ImportImage, then Features.NvmeSupport=supported through the
#                flat-wire RPC (the CLI rejects the flag), poll by ImageName
#                until Available, read the Description back and compare its
#                sha256= to the local disk.
#   5 rotate     StopInstance --ForceStop -> ReplaceSystemDisk --SystemDisk.Size
#                1 -> ModifyInstanceAttribute --UserData (readback
#                byte-identical) -> StartInstance. Order matters: a user_data
#                push BEFORE the swap is discarded.
#   6 verify     HTTPS 200, /debug/envelope binary_sha256 == the binary just
#                built, check-manifest-parity.mjs -> PARITY OK against the
#                local disk (proves the deployed ESP is this file), then the
#                three live behaviour checks: TLS certificate binding, sealed
#                callback refusals, the notary answering — plus (v234) a real
#                notary restart through POST /proxy/restart proving the
#                envelope cache re-mints with the NEW key.
#
# Usage:
#   export ALI_INSTANCE_ID=i-xxxxxxxx          # prod instance to rotate
#   export ALI_OSS_BUCKET=paypal-tdx-image-xxxxxxxx   # Beijing bucket
#   export ALI_CONFIG_FILE_PATH=/path/prod-config.json
#   export PROD_URL=https://login.airma.de
#   bash rotate-alibaba.sh                     # every phase
#   bash rotate-alibaba.sh --dry-run           # plan + local digests, no cloud
#   bash rotate-alibaba.sh --from import       # resume (needs ALI_IMAGE_ID or
#                                              #   ALI_IMAGE_ID set for rotate)
#
# Relay env (unless RELAY_MODE=direct):
#   ALI_STAGE_BUCKET=paypal-tdx-relay-xxxxxxxx       # HK bucket, operator-writable
#   ALI_RELAY_INSTANCE_ID=i-xxxxxxxx                 # stopped cn-beijing relay
#   ALI_STAGE_ENDPOINT / ALI_OSS_ENDPOINT            # optional endpoint overrides
#
# Notes learned the hard way (see HANDOVER §0.40):
#   - RunCommand needs --InstanceId.1, not --InstanceIds
#   - a 49 MB transfer outlives a RunCommand invocation -> the relay leg is
#     detached (setsid) and polled through a status file
#   - StartInstance right after ReplaceSystemDisk is dropped -> poll for Running
#   - DescribeImages by ImageId returns TotalCount 0 in cn-beijing-i -> query
#     by ImageName
# =============================================================================
set -eo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

REGION="${ALI_REGION:-cn-beijing}"
DISK_FILE="${DISK_FILE:-output-alibaba/disk-alibaba.raw}"
INSTANCE_ID="${ALI_INSTANCE_ID:-}"
CONFIG_FILE="${ALI_CONFIG_FILE_PATH:-}"
BUCKET="${ALI_OSS_BUCKET:-}"
STAGE_BUCKET="${ALI_STAGE_BUCKET:-}"
RELAY_INSTANCE_ID="${ALI_RELAY_INSTANCE_ID:-}"
RELAY_MODE="${RELAY_MODE:-relay}"
PROD_URL="${PROD_URL:-https://login.airma.de}"
SYSTEM_DISK_SIZE="${ALI_SYSTEM_DISK_SIZE:-1}"
IMAGE_NAME="${ALI_IMAGE_NAME:-paypal-tdx-esp-$(date +%Y%m%d%H%M)}"

DRY_RUN=0
ALLOW_DIRTY=0
FROM_PHASE=preflight

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --allow-dirty) ALLOW_DIRTY=1; shift ;;
        --from) FROM_PHASE="$2"; shift 2 ;;
        -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

say()  { echo "$*"; }
step() { echo ""; echo "── $* ─────────────────────────────────────────────"; }
ok()   { echo "✅ $*"; }
warn() { echo "⚠️  $*"; }
die()  { echo "❌ $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }
sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
md5_of() { md5sum "$1" | cut -d' ' -f1; }

# Alibaba's flat-wire RPC, for the calls the CLI rejects or misreports.
rpc() {
    local payload="$1"
    if [[ $DRY_RUN == 1 ]]; then say "   [dry-run] rpc $payload"; return 0; fi
    node scripts/ecs-rpc.mjs "$payload"
}
presign() { # METHOD BUCKET KEY HOST TTL
    node scripts/oss-presign.mjs "$1" "$2" "$3" "$4" "${5:-10800}"
}

# Relay command execution: start detached, then poll a status file.
relay_start() { # SCRIPT
    local b64; b64=$(printf '%s' "$1" | base64 -w0)
    aliyun ecs RunCommand --RegionId "$REGION" \
        --InstanceId.1 "$RELAY_INSTANCE_ID" \
        --Type RunShellScript --ContentEncoding Base64 \
        --CommandContent "$b64" --Timeout 3600 >/dev/null
}
relay_ensure_running() { # the relay is stopped between rotations (StopCharging)
    local st
    st=$(aliyun ecs DescribeInstances --RegionId "$REGION" --InstanceIds "[\"$RELAY_INSTANCE_ID\"]" 2>/dev/null \
        | jq -r '.Instances.Instance[0].Status // empty')
    if [[ "$st" != "Running" ]]; then
        say "   relay $RELAY_INSTANCE_ID is ${st:-unknown} — starting it"
        aliyun ecs StartInstance --RegionId "$REGION" --InstanceId "$RELAY_INSTANCE_ID" >/dev/null 2>&1 || true
        for _ in $(seq 1 48); do
            st=$(aliyun ecs DescribeInstances --RegionId "$REGION" --InstanceIds "[\"$RELAY_INSTANCE_ID\"]" 2>/dev/null \
                | jq -r '.Instances.Instance[0].Status // empty')
            [[ "$st" == "Running" ]] && break
            sleep 5
        done
        [[ "$st" == "Running" ]] || die "relay $RELAY_INSTANCE_ID did not reach Running (status: ${st:-unknown})"
        # RunCommand can land before the cloud agent is listening on a fresh boot.
        sleep 15
    fi
    ok "relay $RELAY_INSTANCE_ID is Running"
}

relay_poll() { # STATUSFILE TIMEOUT_S -> prints file content
    local f="$1" limit="${2:-1800}" b64
    b64=$(printf 'cat %s 2>/dev/null || echo PENDING' "$f" | base64 -w0)
    for _ in $(seq 1 $((limit / 15))); do
        local out
        out=$(aliyun ecs RunCommand --RegionId "$REGION" --InstanceId.1 "$RELAY_INSTANCE_ID" \
            --Type RunShellScript --ContentEncoding Base64 \
            --CommandContent "$b64" --Timeout 60 2>/dev/null \
            | jq -r '.InvokeId // empty' 2>/dev/null || true)
        if [[ -n "$out" ]]; then
            local text
            text=$(aliyun ecs DescribeInvocationResults --RegionId "$REGION" \
                --InstanceId "$RELAY_INSTANCE_ID" --InvokeId "$out" 2>/dev/null \
                | jq -r '.Invocation.InvocationResults.InvocationResult[0].Output // empty' 2>/dev/null || true)
            text=$(printf '%s' "$text" | base64 -d 2>/dev/null || printf '%s' "$text")
            case "$text" in
                PENDING|"") ;;
                DONE*) echo "${text#DONE }"; return 0 ;;
                *) echo "$text"; return 1 ;;
            esac
        fi
        sleep 15
    done
    echo "TIMEOUT"
    return 1
}

# ── 1 preflight ──────────────────────────────────────────────────────────────
phase_preflight() {
    step "1/6 preflight"
    need node; need jq; need sha256sum; need md5sum; need curl
    if [[ $DRY_RUN == 1 ]]; then
        command -v podman >/dev/null || command -v docker >/dev/null || die "no podman/docker (build phase)"
    else
        need aliyun
        command -v podman >/dev/null || command -v docker >/dev/null || die "no podman/docker (build phase)"
    fi

    cmp -s verify.html index.html \
        || die "verify.html and index.html must stay byte-identical (the ESP ships verify.html)"
    ok "page copies identical (sha256 $(sha256_of verify.html | cut -c1-16)…)"

    local page_sha; page_sha=$(sha256_of verify.html)
    grep -q "$page_sha" README.md \
        || warn "README digest rows do not carry this verify.html sha256 — auditors would check a stale one"

    [[ -n "$CONFIG_FILE" ]] || die "set ALI_CONFIG_FILE_PATH (the enclave config JSON for user_data)"
    [[ -f "$CONFIG_FILE" ]] || die "config not found: $CONFIG_FILE"
    node -e 'JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))' "$CONFIG_FILE" \
        || die "config is not valid JSON: $CONFIG_FILE"
    ok "config parses ($(wc -c <"$CONFIG_FILE") B)"

    [[ -n "$BUCKET" ]] || die "set ALI_OSS_BUCKET (an OSS bucket in $REGION)"
    [[ -n "$INSTANCE_ID" ]] || die "set ALI_INSTANCE_ID (the prod instance to rotate)"

    local head; head=$(git rev-parse --short HEAD)
    if [[ $ALLOW_DIRTY != 1 ]]; then
        local dirty; dirty=$(git status --porcelain | grep -v '^ M output-alibaba/disk-alibaba.raw' || true)
        [[ -z "$dirty" ]] || { echo "$dirty"; die "tree is dirty — the disk digest must map to a commit (or pass --allow-dirty)"; }
    fi
    ok "source at $head$( [[ $ALLOW_DIRTY == 1 ]] && echo ' (dirty allowed)' )"

    if [[ $DRY_RUN == 1 ]]; then
        say "   [dry-run] would check $INSTANCE_ID exists in $REGION"
    else
        local found
        found=$(aliyun ecs DescribeInstances --RegionId "$REGION" --InstanceIds "[\"$INSTANCE_ID\"]" 2>/dev/null \
            | jq -r '.Instances.Instance[0].InstanceId // empty')
        [[ "$found" == "$INSTANCE_ID" ]] || die "instance $INSTANCE_ID not visible in $REGION"
        ok "instance $INSTANCE_ID exists"
    fi
}

# ── 2 build ──────────────────────────────────────────────────────────────────
phase_build() {
    step "2/6 build"
    if [[ $DRY_RUN == 1 ]]; then
        say "   [dry-run] would run: bash build-alibaba-docker.sh"
        [[ -f "$DISK_FILE" ]] && say "   [dry-run] existing disk: $(sha256_of "$DISK_FILE" | cut -c1-16)… ($(stat -c%s "$DISK_FILE") B)"
        return 0
    fi
    bash build-alibaba-docker.sh || die "build failed"
    [[ -f "$DISK_FILE" ]] || die "build produced no $DISK_FILE"
    DISK_SHA=$(sha256_of "$DISK_FILE")
    DISK_MD5=$(md5_of "$DISK_FILE")
    DISK_SIZE=$(stat -c%s "$DISK_FILE")
    BIN_SHA=$(sha256_of paypal-auth-vm)
    [[ "$DISK_SIZE" -gt 40000000 ]] || die "disk is only $DISK_SIZE B — the ESP did not assemble"
    [[ -n "$BIN_SHA" ]] || die "no built enclave binary to fingerprint"
    say "   disk   : $DISK_FILE ($DISK_SIZE B)"
    say "   sha256 : $DISK_SHA"
    say "   md5    : $DISK_MD5"
    say "   binary : $BIN_SHA"
    ok "build artifacts fingerprinted"
}

# ── 3 stage ──────────────────────────────────────────────────────────────────
phase_stage() {
    step "3/6 stage bytes into OSS"
    local object
    object="paypal-auth-vm/$(basename "$DISK_FILE")"
    DISK_SHA=${DISK_SHA:-$(sha256_of "$DISK_FILE")}
    DISK_MD5=${DISK_MD5:-$(md5_of "$DISK_FILE")}
    DISK_SIZE=${DISK_SIZE:-$(stat -c%s "$DISK_FILE")}

    if [[ $DRY_RUN == 1 ]]; then
        say "   [dry-run] would stage oss://$BUCKET/$object ($DISK_SIZE B, md5 $DISK_MD5)"
        say "   [dry-run] RELAY_MODE=$RELAY_MODE (stage bucket: ${STAGE_BUCKET:-unset}, relay: ${RELAY_INSTANCE_ID:-unset})"
        return 0
    fi

    if [[ "$RELAY_MODE" == "direct" ]]; then
        aliyun oss cp "$DISK_FILE" "oss://$BUCKET/$object" >/dev/null || die "aliyun oss cp failed"
        local stat_out; stat_out=$(aliyun oss stat "oss://$BUCKET/$object" 2>&1) || die "cannot stat staged object"
        local remote_size remote_etag
        remote_size=$(echo "$stat_out" | grep -oE 'Content-Length[^0-9]*[0-9]+' | grep -oE '[0-9]+$' | head -1)
        remote_etag=$(echo "$stat_out" | grep -oiE 'etag[^a-f0-9]*[a-f0-9]{32}' | grep -oiE '[a-f0-9]{32}' | head -1 | tr 'A-Z' 'a-z')
        [[ "$remote_size" == "$DISK_SIZE" ]] || die "OSS size $remote_size != local $DISK_SIZE"
        [[ -z "$remote_etag" || "$remote_etag" == "$DISK_MD5" ]] || die "OSS ETag $remote_etag != local md5 $DISK_MD5"
        ok "direct upload verified ($remote_size B, etag ${remote_etag:-n/a})"
        return 0
    fi

    # The OSS presigner reads the STS token straight off the CLI profile, and
    # only a CLI call refreshes it — a token that expired while the build ran
    # surfaces as InvalidAccessKeyId on the first PUT. Poke the CLI first.
    aliyun sts GetCallerIdentity >/dev/null 2>&1 \
        || warn "sts GetCallerIdentity failed — presigned URLs may be signed with a stale token"

    # Relay legs (the path that works from outside mainland China).
    [[ -n "$STAGE_BUCKET" ]] || die "set ALI_STAGE_BUCKET (HK relay bucket) or RELAY_MODE=direct"
    [[ -n "$RELAY_INSTANCE_ID" ]] || die "set ALI_RELAY_INSTANCE_ID (cn-beijing relay) or RELAY_MODE=direct"
    local stage_host="${ALI_STAGE_ENDPOINT:-${STAGE_BUCKET}.oss-cn-hongkong.aliyuncs.com}"
    local bj_host="${ALI_OSS_ENDPOINT:-${BUCKET}.oss-cn-beijing-internal.aliyuncs.com}"

    say "   leg 1: operator -> HK bucket"
    local put_url; put_url=$(presign PUT "$STAGE_BUCKET" "$object" "$stage_host")
    curl -fsS -T "$DISK_FILE" "$put_url" >/dev/null || die "presigned PUT to the HK bucket failed"
    local hk_head; hk_head=$(presign HEAD "$STAGE_BUCKET" "$object" "$stage_host")
    local hdr; hdr=$(curl -fsS -I "$hk_head") || die "cannot HEAD the HK object"
    local hk_size hk_etag
    hk_size=$(echo "$hdr" | tr -d '\r' | awk 'tolower($1)=="content-length:"{print $2}')
    hk_etag=$(echo "$hdr" | tr -d '\r"' | awk 'tolower($1)=="etag:"{print $2}' | tr 'A-Z' 'a-z')
    [[ "$hk_size" == "$DISK_SIZE" ]] || die "HK object size $hk_size != local $DISK_SIZE"
    [[ "$hk_etag" == "$DISK_MD5" ]] || die "HK object etag $hk_etag != local md5 $DISK_MD5"
    ok "leg 1 verified ($hk_size B, etag $hk_etag)"

    relay_ensure_running
    say "   leg 2: relay $RELAY_INSTANCE_ID -> Beijing bucket (detached)"
    local get_url bj_put_url
    get_url=$(presign GET "$STAGE_BUCKET" "$object" "$stage_host")
    bj_put_url=$(presign PUT "$BUCKET" "$object" "$bj_host")
    relay_start "setsid bash -c 'rm -f /tmp/pav-relay.status; curl -fsS -o /tmp/pav-relay.raw \"$get_url\" && curl -fsS -T /tmp/pav-relay.raw \"$bj_put_url\" && echo DONE ok > /tmp/pav-relay.status || echo FAIL > /tmp/pav-relay.status' >/dev/null 2>&1 &"
    local status
    status=$(relay_poll /tmp/pav-relay.status 1800) || die "relay leg failed: $status"
    ok "leg 2 finished on the relay"

    say "   leg 3: verify the Beijing object from the relay (intranet)"
    local bj_head; bj_head=$(presign HEAD "$BUCKET" "$object" "$bj_host")
    local b64 bk_out
    b64=$(printf 'curl -sS -I "%s"' "$bj_head" | base64 -w0)
    local inv
    inv=$(aliyun ecs RunCommand --RegionId "$REGION" --InstanceId.1 "$RELAY_INSTANCE_ID" \
        --Type RunShellScript --ContentEncoding Base64 --CommandContent "$b64" --Timeout 120 \
        | jq -r '.InvokeId // empty')
    [[ -n "$inv" ]] || die "could not run the verification command on the relay"
    for _ in $(seq 1 12); do
        bk_out=$(aliyun ecs DescribeInvocationResults --RegionId "$REGION" \
            --InstanceId "$RELAY_INSTANCE_ID" --InvokeId "$inv" 2>/dev/null \
            | jq -r '.Invocation.InvocationResults.InvocationResult[0].Output // empty' 2>/dev/null || true)
        bk_out=$(printf '%s' "$bk_out" | base64 -d 2>/dev/null || printf '%s' "$bk_out")
        [[ -n "$bk_out" ]] && break
        sleep 10
    done
    local bj_size bj_etag
    bj_size=$(printf '%s' "$bk_out" | tr -d '\r' | awk 'tolower($1)=="content-length:"{print $2}')
    bj_etag=$(printf '%s' "$bk_out" | tr -d '\r"' | awk 'tolower($1)=="etag:"{print $2}' | tr 'A-Z' 'a-z')
    [[ "$bj_size" == "$DISK_SIZE" ]] || die "Beijing object size ${bj_size:-?} != local $DISK_SIZE"
    [[ "$bj_etag" == "$DISK_MD5" ]] || die "Beijing object etag ${bj_etag:-?} != local md5 $DISK_MD5"
    ok "leg 3 verified ($bj_size B, etag $bj_etag) — oss://$BUCKET/$object"
}

# ── 4 import ─────────────────────────────────────────────────────────────────
phase_import() {
    step "4/6 import as a custom image"
    DISK_SHA=${DISK_SHA:-$(sha256_of "$DISK_FILE")}
    if [[ $DRY_RUN == 1 ]]; then
        say "   [dry-run] would import oss://$BUCKET/paypal-auth-vm/$(basename "$DISK_FILE") as $IMAGE_NAME"
        say "   [dry-run] then Features.NvmeSupport=supported, poll by name until Available, check Description sha256"
        return 0
    fi
    local out image_id
    out=$(ALI_IMAGE_NAME="$IMAGE_NAME" ALI_REGION="$REGION" ALI_OSS_BUCKET="$BUCKET" \
          DISK_FILE="$DISK_FILE" SKIP_OSS_UPLOAD=1 bash import-alibaba-image.sh 2>&1) \
        || { printf '%s\n' "$out"; die "import-alibaba-image.sh failed"; }
    printf '%s\n' "$out" | tail -6
    image_id=$(printf '%s\n' "$out" | grep -oE 'Image ID *: *m-[a-z0-9]+' | grep -oE 'm-[a-z0-9]+' | head -1)
    image_id=${image_id:-${ALI_IMAGE_ID:-}}
    [[ -n "$image_id" ]] || die "could not determine the imported ImageId"
    IMAGE_ID="$image_id"
    ok "imported as $IMAGE_ID"

    # The CLI rejects --Features.NvmeSupport; without it ReplaceSystemDisk refuses.
    rpc "{\"Action\":\"ModifyImageAttribute\",\"RegionId\":\"$REGION\",\"ImageId\":\"$IMAGE_ID\",\"Features.NvmeSupport\":\"supported\"}" >/dev/null \
        || die "ModifyImageAttribute NvmeSupport failed"
    ok "NVMe support enabled"

    local desc status
    desc=$(aliyun ecs DescribeImages --RegionId "$REGION" --ImageName "$IMAGE_NAME" 2>/dev/null \
        | jq -r '.Images.Image[0].Description // empty')
    case "$desc" in
        *"$DISK_SHA"*) ok "image Description carries sha256=$DISK_SHA" ;;
        *) die "image Description does not carry the local disk sha256 (got: ${desc:-empty})" ;;
    esac
    for _ in $(seq 1 60); do
        status=$(aliyun ecs DescribeImages --RegionId "$REGION" --ImageName "$IMAGE_NAME" 2>/dev/null \
            | jq -r '.Images.Image[0].Status // "Unknown"')
        [[ "$status" == "Available" ]] && break
        sleep 10
    done
    [[ "$status" == "Available" ]] || die "image $IMAGE_ID not Available (status=$status)"
    ok "image Available"
}

# ── 5 rotate ─────────────────────────────────────────────────────────────────
phase_rotate() {
    step "5/6 rotate prod onto the new image"
    IMAGE_ID=${IMAGE_ID:-${ALI_IMAGE_ID:-}}
    if [[ $DRY_RUN == 1 ]]; then
        say "   [dry-run] would stop $INSTANCE_ID, ReplaceSystemDisk -> ${IMAGE_ID:-<image from the import phase>} (size $SYSTEM_DISK_SIZE GiB),"
        say "   [dry-run] then push user_data from $CONFIG_FILE and start"
        return 0
    fi
    [[ "$IMAGE_ID" == m-* ]] || die "set ALI_IMAGE_ID (or run the import phase) — no image id to boot"

    local before_disk before_status
    before_disk=$(aliyun ecs DescribeInstances --RegionId "$REGION" --InstanceIds "[\"$INSTANCE_ID\"]" 2>/dev/null \
        | jq -r '.Instances.Instance[0].SystemDisk.DiskId // empty')
    say "   rollback pointer: disk ${before_disk:-unknown}"

    aliyun ecs StopInstance --RegionId "$REGION" --InstanceId "$INSTANCE_ID" --ForceStop true >/dev/null \
        || die "StopInstance failed"
    for _ in $(seq 1 40); do
        before_status=$(aliyun ecs DescribeInstances --RegionId "$REGION" --InstanceIds "[\"$INSTANCE_ID\"]" 2>/dev/null \
            | jq -r '.Instances.Instance[0].Status // "Unknown"')
        [[ "$before_status" == "Stopped" ]] && break
        sleep 5
    done
    [[ "$before_status" == "Stopped" ]] || die "instance did not stop (status=$before_status)"
    ok "stopped"

    rpc "{\"Action\":\"ReplaceSystemDisk\",\"RegionId\":\"$REGION\",\"InstanceId\":\"$INSTANCE_ID\",\"ImageId\":\"$IMAGE_ID\",\"SystemDisk.Size\":\"$SYSTEM_DISK_SIZE\"}" >/dev/null \
        || die "ReplaceSystemDisk failed"
    local new_disk
    new_disk=$(aliyun ecs DescribeInstances --RegionId "$REGION" --InstanceIds "[\"$INSTANCE_ID\"]" 2>/dev/null \
        | jq -r '.Instances.Instance[0].SystemDisk.DiskId // empty')
    ok "disk replaced (${before_disk:-old} -> ${new_disk:-new})"

    # Order matters: a user_data push before the swap is discarded with the old disk.
    local ud want_sha got_sha
    ud=$(base64 -w0 < "$CONFIG_FILE")
    want_sha=$(printf '%s' "$ud" | sha256sum | cut -d' ' -f1)
    aliyun ecs ModifyInstanceAttribute --RegionId "$REGION" --InstanceId "$INSTANCE_ID" --UserData "$ud" >/dev/null \
        || die "ModifyInstanceAttribute --UserData failed"
    got_sha=$(aliyun ecs DescribeUserData --RegionId "$REGION" --InstanceId "$INSTANCE_ID" 2>/dev/null \
        | jq -r '.UserData // empty' | tr -d '\n' | sha256sum | cut -d' ' -f1)
    [[ "$got_sha" == "$want_sha" ]] || die "user_data readback sha256 $got_sha != pushed $want_sha"
    ok "user_data pushed and read back byte-identical (${#ud} B b64, sha256 ${want_sha:0:16}…)"

    aliyun ecs StartInstance --RegionId "$REGION" --InstanceId "$INSTANCE_ID" >/dev/null 2>&1 || true
    local st
    for _ in $(seq 1 60); do
        st=$(aliyun ecs DescribeInstances --RegionId "$REGION" --InstanceIds "[\"$INSTANCE_ID\"]" 2>/dev/null \
            | jq -r '.Instances.Instance[0].Status // "Unknown"')
        [[ "$st" == "Running" ]] && break
        # StartInstance right after a disk swap is sometimes dropped: retry.
        aliyun ecs StartInstance --RegionId "$REGION" --InstanceId "$INSTANCE_ID" >/dev/null 2>&1 || true
        sleep 5
    done
    [[ "$st" == "Running" ]] || die "instance did not start (status=$st)"
    ok "running"
}

# ── 6 verify ─────────────────────────────────────────────────────────────────
phase_verify() {
    step "6/6 verify the deployed bytes"
    BIN_SHA=${BIN_SHA:-$(sha256_of paypal-auth-vm)}
    if [[ $DRY_RUN == 1 ]]; then
        say "   [dry-run] would poll $PROD_URL for 200, compare /debug/envelope binary_sha256 to $BIN_SHA,"
        say "   [dry-run] then run: node scripts/check-manifest-parity.mjs $PROD_URL $DISK_FILE"
        say "   [dry-run] then run: node scripts/check-live-tls-cert.mjs --url $PROD_URL"
        say "   [dry-run] then run: node scripts/check-live-callback.mjs --url $PROD_URL"
        say "   [dry-run] then run: node scripts/check-live-notary.mjs --url $PROD_URL"
        say "   [dry-run] then run: PROXY_RESTART_TOKEN=… node scripts/check-live-proxy-restart.mjs --url $PROD_URL"
        return 0
    fi

    # A freshly booted guest serves NOTHING until its certificate exists, and
    # issuance is a retry loop with no self-signed fallback (by design: a
    # self-signed cert would be a lie the padlock cannot expose). So "not 200
    # yet" is a normal boot state for minutes, not a failed deployment — the
    # wait budget must cover a full issuance retry cycle (the CA's own refusal
    # windows reach ~30 min), or the rotation aborts on a healthy box and the
    # operator has to re-run the checks by hand (v231 pass 2 did exactly that).
    local wait_secs=${VERIFY_WAIT_SECS:-1500}
    local code="" waited=0 last_note=0
    while [[ $waited -lt $wait_secs ]]; do
        code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$PROD_URL/" 2>/dev/null || true)
        [[ "$code" == "200" ]] && break
        if [[ $((waited - last_note)) -ge 60 ]]; then
            say "   waiting for the guest to finish its boot: ${waited}s elapsed, last HTTP ${code:-no response} (budget ${wait_secs}s)"
            last_note=$waited
        fi
        sleep 15
        waited=$((waited + 15))
    done
    if [[ "$code" != "200" ]]; then
        say "   not serving after ${waited}s. If the guest is up but dark, its boot self-report says why:"
        say "   the ACME retry loop publishes every attempt to the self_request sink (kind=fatal, reason='acme attempt N: …')."
        die "$PROD_URL did not serve 200 (last: ${code:-no response})"
    fi
    ok "HTTPS 200 (after ${waited}s)"

    local live_bin
    # Nested under the boot measurements; the top-level fallback keeps this
    # working if the envelope is ever flattened.
    live_bin=$(curl -fsS --max-time 20 "$PROD_URL/debug/envelope" \
        | jq -r '.attestation_report.enclave_config.boot_measurements.binary_sha256 // .binary_sha256 // empty')
    [[ -n "$live_bin" ]] || die "envelope carried no binary_sha256 — cannot prove which binary is running"
    [[ "$live_bin" == "$BIN_SHA" ]] || die "running binary $live_bin != built $BIN_SHA"
    ok "running binary matches the build ($live_bin)"

    local parity
    parity=$(node scripts/check-manifest-parity.mjs "$PROD_URL" "$DISK_FILE" 2>&1) || {
        printf '%s\n' "$parity" | tail -12; die "ESP parity check failed"; }
    printf '%s\n' "$parity" | grep -E 'SAME|EXCLUDED|RESULT' | tail -10
    printf '%s\n' "$parity" | grep -q 'PARITY OK' || die "parity checker did not report PARITY OK"
    ok "deployed ESP == $DISK_FILE"

    # v227 made /tls-cert.pem the visitor's proof of the channel, so the served
    # body, the live handshake and session_context.tls_certificate_pem must all
    # be the same leaf. A proxy or a stale report copy breaks it silently.
    local certchk
    certchk=$(node scripts/check-live-tls-cert.mjs --url "$PROD_URL" 2>&1) || {
        printf '%s\n' "$certchk" | tail -20; die "live TLS certificate binding failed"; }
    printf '%s\n' "$certchk" | grep -E '✅|❌|RESULT' | tail -10
    ok "certificate download == live handshake == report"

    # The only Return URL PayPal knows: junk must be refused in sealed plain
    # text, not exchanged and not answered with a framework error page.
    local cbchk
    cbchk=$(node scripts/check-live-callback.mjs --url "$PROD_URL" 2>&1) || {
        printf '%s\n' "$cbchk" | tail -20; die "live callback refusal check failed"; }
    printf '%s\n' "$cbchk" | grep -E '✅|❌|RESULT' | tail -8
    ok "callback refuses missing/forged/denied input in sealed plain text"

    # The second webservice: the config can say `services.tls_proxy.enabled` all
    # it likes, but only the disk decides whether the binary exists. A rotation
    # that ships a PayPal-only disk onto this config looks healthy everywhere
    # else and silently drops the notary (v227–v229).
    local notchk
    notchk=$(node scripts/check-live-notary.mjs --url "$PROD_URL" 2>&1) || {
        printf '%s\n' "$notchk" | tail -20; die "live notary check failed (was the disk built with TLS_PROXY=1?)"; }
    printf '%s\n' "$notchk" | grep -E '✅|❌|RESULT' | tail -8
    ok "TLSNotary notary spawned, listening and serving its attestation list"

    # v234: the envelope cache must FOLLOW the notary key, not just exist. The
    # check cycles the child through the operator-gated POST /proxy/restart and
    # proves /debug/envelope names the NEW key inside the old 15-minute window —
    # exactly the bug v232 fixed (a cached envelope published the previous
    # boot's signing key, so every auditor's fail-closed binding check failed
    # until the window ran out). Running it here means every release proves it on
    # the real instance instead of trusting a unit test.
    local token restartchk
    token=$(node -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(String(((c.services||{}).tls_proxy||{}).restart_token||""))' "$CONFIG_FILE")
    [[ -n "$token" ]] || die "config has no services.tls_proxy.restart_token — the notary restart path cannot be exercised from outside (add one; see docs/tls-proxy.md)"
    restartchk=$(PROXY_RESTART_TOKEN="$token" node scripts/check-live-proxy-restart.mjs --url "$PROD_URL" 2>&1) || {
        printf '%s\n' "$restartchk" | tail -20; die "live notary-restart check failed — does /debug/envelope still follow the notary key?"; }
    printf '%s\n' "$restartchk" | grep -E '✅|❌|RESULT' | tail -8
    ok "envelope cache re-mints with the new notary key across a live restart"
}

# ── run ──────────────────────────────────────────────────────────────────────
PHASES=(preflight build stage import rotate verify)
start=0
for i in "${!PHASES[@]}"; do [[ "${PHASES[$i]}" == "$FROM_PHASE" ]] && start=$i; done
[[ "${PHASES[$start]}" == "$FROM_PHASE" ]] || die "unknown phase '$FROM_PHASE' (one of: ${PHASES[*]})"

[[ $DRY_RUN == 1 ]] && say "DRY RUN — no cloud calls, no writes"
say "region=$REGION instance=${INSTANCE_ID:-unset} image=$IMAGE_NAME"

for ((i=start; i<${#PHASES[@]}; i++)); do
    "phase_${PHASES[$i]}"
done

echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅ rotation complete"
echo "   image    : ${IMAGE_ID:-?} ($IMAGE_NAME)"
echo "   disk sha : ${DISK_SHA:-$(sha256_of "$DISK_FILE" 2>/dev/null || echo ?)}"
echo "   prod     : ${INSTANCE_ID:-?} @ $PROD_URL"
echo ""
echo "Next:"
echo "   1. commit output-alibaba/disk-alibaba.raw so the released disk maps to a commit"
echo "   2. record the rotation in HANDOVER.md (image, disk, sha256, boot time)"
echo "   3. delete the superseded image + snapshot, stop the relay (StopCharging)"
echo "════════════════════════════════════════════════════════════"
