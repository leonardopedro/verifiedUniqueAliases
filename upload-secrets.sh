#!/bin/bash
# =============================================================================
# upload-secrets.sh — rotate the enclave's credentials on the LIVE instance
#
# Rewritten 2026-10-31 for the current stack. The previous version drove GCP
# Secret Manager and ended with
#   gcloud compute instances reset paypal-auth-vm-v60 --zone=europe-west4-a
# Neither that project nor that VM exists any more; it would have failed at
# the first gcloud call, so nothing it did can have taken effect since the
# move to Alibaba Cloud.
#
# WHY THERE IS NO SECRET STORE HERE
# The enclave's config IS the instance `user_data` — a base64 JSON blob read
# at boot from http://100.100.100.200/latest/user-data. "Rotating a secret"
# therefore means: read the live config, merge the one change, write it back,
# reboot. This script MERGES; it never rebuilds the JSON from scratch, because
# a from-scratch rebuild is exactly how `self_report` (the boot-heartbeat RAM
# key), `attestation_signing_key`, `acme_account_json` and `dns01_secret` get
# silently dropped — see HANDOVER §0.10, where the previous config generator
# did precisely that.
#
# PUSH ORDER IS LOAD-BEARING (HANDOVER §0.6)
# user_data is DISK-BOUND: a push is discarded by any later ReplaceSystemDisk,
# and a push while Running may be ignored. The only correct order is
#   Stop -> wait Stopped -> ModifyInstanceAttribute --UserData -> Start
# DescribeUserData may return 0 bytes right after a good push — that is a
# known CLI quirk, not a failure. THE BOOT IS THE TEST.
#
# Usage:
#   interactive:        bash upload-secrets.sh
#   dry run:            PAV_DRY_RUN=1 bash upload-secrets.sh
#   non-interactive:    PAV_NONINTERACTIVE=1 PAV_MODE=production \
#                         PAYPAL_CLIENT_ID=... PAYPAL_CLIENT_SECRET=... \
#                         PAYPAL_VERIFIED_CLIENT_ID=... \
#                         PAYPAL_VERIFIED_CLIENT_SECRET=... \
#                         bash upload-secrets.sh
#
# NO LOCAL COPY IS WRITTEN (v2). The pre-rotation config stays in this
# process's memory ($CURRENT) and is used for rollback from memory. Nothing
# containing a credential is written to disk on this machine.
#
# If you deliberately want a file anyway, export PAV_BACKUP_DIR=<path> before
# running; it defaults to EMPTY, i.e. no backup file at all. It is opt-in
# because ~/.paypal-auth-backups used to be written unconditionally and that
# is a plaintext credential store sitting in your home directory.
#
# NON-INTERACTIVE LEAK CAVEAT: `PAYPAL_CLIENT_SECRET=... bash
# upload-secrets.sh` records the secret in your shell history. Prefix the
# command with a space (HISTCONTROL=ignorespace), or read the secret from a
# descriptor instead:
#   PAYPAL_CLIENT_SECRET="$(< /dev/fd/3)" bash upload-secrets.sh 3< <(secret-tool lookup paypal)
# =============================================================================
set -eo pipefail

info()  { echo -e "\033[0;32m[INFO]\033[0m $*"; }

# read(1) exits non-zero on EOF; under `set -e` that kills the script with no
# message at all. Every prompt goes through ask() so a closed stdin says so.
#   ask VARNAME "prompt"          — visible input, default kept on empty line
#   ask_secret VARNAME "prompt"   — no echo (secret-ISH values)
#   ask_secret2 VARNAME "prompt"  — no echo, entered TWICE (real secrets)
#
# `read -s` is what makes it a password field: the terminal does not echo the
# characters. Use ask_secret2 for anything that IS a credential, because a
# hidden prompt hides typos too — and a typo'd secret pushed here does not
# fail at the prompt, it fails at the next boot as a dark :443. Confirming
# costs one extra line; not confirming costs a rollback.
ask() {
    local __var="$1" __prompt="$2" __val
    read -r -p "$__prompt" __val || die "stdin closed while waiting for '$__prompt' — nothing was pushed"
    printf -v "$__var" '%s' "$__val"
}
ask_secret() {
    local __var="$1" __prompt="$2" __val
    read -r -s -p "$__prompt" __val || die "stdin closed while waiting for '$__prompt' — nothing was pushed"
    echo ""
    printf -v "$__var" '%s' "$__val"
}
# Empty first entry is returned unchanged: for most fields an empty answer
# means "keep the live value", so a confirmation prompt would be noise there.
ask_secret2() {
    local __var="$1" __prompt="$2" __first __again
    ask_secret "$__var" "$__prompt"
    __first="${!__var}"
    [[ -z "$__first" ]] && return 0
    ask_secret __again "  retype to confirm: "
    [[ "$__first" == "$__again" ]] \
        || die "the two entries for '$__var' did not match — nothing was pushed"
    printf -v "$__var" '%s' "$__first"
}
warn()  { echo -e "\033[0;33m[WARN]\033[0m $*"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; }
die()   { error "$*"; exit 1; }

# --- Target ------------------------------------------------------------------
PAV_REGION="${PAV_REGION:-cn-beijing}"
PROD_NAME="${PAV_PROD_NAME:-paypal-auth-vm}"
# The instance ID CHANGES on every spot recreate (HANDOVER: prod moved
# i-2ze4tvkuf12u933nsw8a -> i-2zef7xhigzn70d6zwimj), so always locate by name.
# EMPTY by default: no backup file is written. Set PAV_BACKUP_DIR=<path> to
# opt in to a plaintext copy on this machine (mode 600, outside the repo).
PAV_BACKUP_DIR="${PAV_BACKUP_DIR:-}"
PAV_NONINTERACTIVE="${PAV_NONINTERACTIVE:-0}"
PAV_DRY_RUN="${PAV_DRY_RUN:-0}"
BOOT_TIMEOUT_SECS="${PAV_BOOT_TIMEOUT_SECS:-900}"

echo "============================================================"
echo "🔐 Vault Manager: enclave credentials (Alibaba ECS user_data)"
echo "============================================================"
echo "Region        : $PAV_REGION"
echo "Instance name : $PROD_NAME"
echo "Mode          : $([[ "$PAV_DRY_RUN" == "1" ]] && echo 'DRY RUN (nothing is pushed)' || echo 'LIVE')"
echo ""

for dep in aliyun jq base64 node; do
    command -v "$dep" >/dev/null 2>&1 || die "missing dependency: $dep"
done

# --- Locate the live instance by name ----------------------------------------
find_prod() {
    local list
    list=$(aliyun ecs DescribeInstances --RegionId "$PAV_REGION" 2>/dev/null) \
        || die "DescribeInstances failed — aliyun credentials invalid/expired? Run any aliyun command to refresh STS."
    PROD_ID=$(echo "$list" | node -e "
        let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{
          const l=JSON.parse(s).Instances.Instance||[];
          const p=l.filter(i=>i.InstanceName===process.argv[1]);
          if(!p.length){process.exit(3)}
          console.log(p[0].InstanceId);
        })" "$PROD_NAME") || die "no instance named '$PROD_NAME' in $PAV_REGION"
    PROD_STATUS=$(echo "$list" | node -e "
        let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{
          const l=JSON.parse(s).Instances.Instance||[];
          const p=l.find(i=>i.InstanceId===process.argv[1]);
          console.log(p?p.Status:'');
        })" "$PROD_ID")
    info "prod instance: $PROD_ID (status: ${PROD_STATUS:-unknown})"
}

# --- Read the live config (the source of truth) ------------------------------
# DescribeUserData returns UserData as a BASE64 string (not the nested
# UserData.Value shape) — see watchdog/deploy-watchdog.sh, which had to learn
# the same thing.
fetch_live_config() {
    local ud
    ud=$(aliyun ecs DescribeUserData --RegionId "$PAV_REGION" --InstanceId "$PROD_ID" \
        | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const j=JSON.parse(s);process.stdout.write(typeof j.UserData==='string'?j.UserData:((j.UserData&&j.UserData.Value)||''))})")
    [[ -n "$ud" ]] || die "DescribeUserData returned nothing for $PROD_ID — refusing to build a config from an unknown baseline"
    LIVE_CONFIG=$(printf '%s' "$ud" | base64 -d 2>/dev/null) \
        || die "live user_data is not valid base64"
    echo "$LIVE_CONFIG" | jq -e . >/dev/null 2>&1 \
        || die "live user_data is not valid JSON — inspect it by hand before rotating"
    info "read live config: $(echo "$LIVE_CONFIG" | jq -r 'keys|join(", ")')"
}

# --- Fail-closed validation (mirrors require_credentials in src/main.rs) -----
# The enclave refuses to boot on empty / YOUR_* / MISSING_* / ***REMOVED***
# placeholders. Catching them HERE means the VM is never rebooted into a
# fail-closed state that only shows up as a dark :443.
assert_real() {
    local field="$1" val="$2" t
    t=$(printf '%s' "$val" | tr -d '[:space:]')
    [[ -n "$t" ]] || die "$field is empty"
    case "$t" in
        YOUR_*|MISSING_*|*REMOVED*) die "$field is a placeholder ('$t') — the enclave would refuse to boot" ;;
    esac
    [[ ${#t} -ge 8 ]] || die "$field looks too short (${#t} chars) — check for a truncated paste"
}

validate_config() {
    local cfg="$1"
    echo "$cfg" | jq -e . >/dev/null 2>&1 || die "merged config is not valid JSON"

    assert_real "paypal_client_id"               "$(echo "$cfg" | jq -r '.paypal_client_id // ""')"
    assert_real "paypal_client_secret"           "$(echo "$cfg" | jq -r '.paypal_client_secret // ""')"
    assert_real "paypal_verified_client_id"      "$(echo "$cfg" | jq -r '.paypal_verified_client_id // ""')"
    assert_real "paypal_verified_client_secret"  "$(echo "$cfg" | jq -r '.paypal_verified_client_secret // ""')"
    assert_real "domain"                         "$(echo "$cfg" | jq -r '.domain // ""')"

    echo "$cfg" | jq -e '.staging | type == "boolean"' >/dev/null 2>&1 \
        || die "'staging' must be a JSON boolean (true/false), not a string"

    # EAB is a PAIR: one half present means the enclave will try ZeroSSL with a
    # broken binding. Either both or neither.
    local eab_id eab_hmac
    eab_id=$(echo "$cfg" | jq -r '.eab_key_id // ""')
    eab_hmac=$(echo "$cfg" | jq -r '.eab_hmac_key // ""')
    if [[ -n "$eab_id" && -z "$eab_hmac" ]] || [[ -z "$eab_id" && -n "$eab_hmac" ]]; then
        die "eab_key_id and eab_hmac_key must be set together (or both cleared to fall back to Let's Encrypt)"
    fi

    # The things a careless rebuild drops, called out explicitly so their loss
    # is a visible decision rather than an accident.
    for preserved in self_report attestation_signing_key acme_account_json; do
        echo "$cfg" | jq -e --arg k "$preserved" 'has($k)' >/dev/null 2>&1 \
            || warn "NOTE: '$preserved' is absent from the config being pushed"
    done
    echo "$cfg" | jq -e 'has("dns01_secret")' >/dev/null 2>&1 \
        || warn "NOTE: 'dns01_secret' is absent — DNS-01 ACME will fail and TLS will stay dark"
}

# --- Report which values change (never print the values themselves) ----------
# A value is hidden if ITS OWN key looks secret OR if any nested key does:
# `self_report` carries access_key_secret one level down and must not be
# printed either. Default-deny for objects: if we cannot convince ourselves a
# subtree is clean, we print a shape summary instead of the data.
show_plan() {
    local before="$1" after="$2"
    node -e "
      const a=JSON.parse(process.argv[1]), b=JSON.parse(process.argv[2]);
      const keys=[...new Set([...Object.keys(a),...Object.keys(b)])].sort();
      const secret=/secret|token|hmac|key|password|credential|authorization/i;
      // true if this node or any descendant holds something secret-looking
      const dirty=(v)=>{
        if(v===null||typeof v!=='object') return false;
        if(Array.isArray(v)) return v.some(dirty);
        return Object.entries(v).some(([k,val])=>secret.test(k)||dirty(val));
      };
      const shape=(v)=>{
        if(v===null) return 'null';
        if(Array.isArray(v)) return 'array['+v.length+']';
        if(typeof v==='object') return '{'+Object.keys(v).sort().join(',')+'}';
        return JSON.stringify(v);
      };
      for(const k of keys){
        const av=a[k], bv=b[k];
        const sa=JSON.stringify(av===undefined?null:av);
        const sb=JSON.stringify(bv===undefined?null:bv);
        const st = sa===sb ? 'unchanged' : 'CHANGED';
        let shown;
        if(bv===undefined) shown='(absent)';
        else if(secret.test(k)||dirty(bv)) shown = (sa===sb ? '(hidden)' : '(hidden, changed)');
        else shown = shape(bv);
        console.log('  '+k.padEnd(32)+st.padEnd(11)+shown);
      }" "$before" "$after"
}

# --- The push: Stop -> Modify -> Start (HANDOVER §0.6) -----------------------
wait_for_status() {
    local want="$1" timeout="${2:-300}" waited=0 cur
    while (( waited < timeout )); do
        cur=$(aliyun ecs DescribeInstances --RegionId "$PAV_REGION" 2>/dev/null | node -e "
            let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{
              const l=JSON.parse(s).Instances.Instance||[];
              const p=l.find(i=>i.InstanceId===process.argv[1]);
              console.log(p?p.Status:'');
            })" "$PROD_ID")
        [[ "$cur" == "$want" ]] && return 0
        sleep 5; waited=$((waited+5))
    done
    die "timed out after ${timeout}s waiting for '$want' (currently '${cur:-unknown}')"
}

push_config() {
    local cfg="$1" b64
    b64=$(printf '%s' "$cfg" | base64 -w0)

    if [[ "$PROD_STATUS" != "Stopped" ]]; then
        info "stopping $PROD_ID ..."
        aliyun ecs StopInstance --RegionId "$PAV_REGION" --InstanceId "$PROD_ID" --ForceStop true >/dev/null
        wait_for_status Stopped 300
    fi

    info "pushing user_data (${#b64} b64 chars) ..."
    aliyun ecs ModifyInstanceAttribute --RegionId "$PAV_REGION" \
        --InstanceId "$PROD_ID" --UserData "$b64" >/dev/null

    info "starting $PROD_ID ..."
    aliyun ecs StartInstance --RegionId "$PAV_REGION" --InstanceId "$PROD_ID" >/dev/null
    wait_for_status Running 300
}

# The rebuild path is a DIFFERENT copy of the same secret: `pav-watchdog` runs
# RunInstances with the `user_data` baked into the OOS template at deploy time.
# Pushing to the instance alone therefore leaves it booting the PRE-rotation
# credentials after any recreate (heartbeat or the 5-minute preemption notice).
# Feed the blob we just pushed straight into the template.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sync_rebuild_template() {
    local cfg="$1" out
    info "syncing the rebuild template with the pushed user_data ..."
    out=$(printf '%s' "$cfg" | base64 -w0 \
        | bash "$ROOT_DIR/watchdog/sync-enclave-userdata.sh" from-stdin 2>&1)
    if [[ $? -eq 0 ]]; then
        while IFS= read -r line; do info "  $line"; done <<< "$out"
    else
        warn "rebuild template NOT synced — a recreate would boot the OLD credentials:"
        while IFS= read -r line; do warn "  $line"; done <<< "$out"
        warn "fix later with: bash watchdog/sync-enclave-userdata.sh from-instance"
    fi
}

# --- Verify the boot, not the CLI readback -----------------------------------
verify_boot() {
    info "waiting for TLS on https://${DOMAIN} (ACME can take minutes) ..."
    local waited=0 code
    while (( waited < BOOT_TIMEOUT_SECS )); do
        code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
            "https://${DOMAIN}/" 2>/dev/null || echo "000")
        if [[ "$code" == "200" ]]; then
            info "✅ https://${DOMAIN}/ answered 200 in ${waited}s"
            return 0
        fi
        sleep 15; waited=$((waited+15))
        echo -n "."
    done
    warn "no 200 from https://${DOMAIN}/ after ${BOOT_TIMEOUT_SECS}s (last code: ${code})"
    warn "serial console: aliyun ecs GetInstanceConsoleOutput --RegionId $PAV_REGION --InstanceId $PROD_ID | base64 -d"
    return 1
}

# Optional, and OFF by default. Rollback uses the in-memory $CURRENT, so a
# file is never required — this exists only for operators who explicitly want
# an on-disk copy they can inspect or hand to another machine.
backup_config() {
    if [[ -z "$PAV_BACKUP_DIR" ]]; then
        info "no backup file written (PAV_BACKUP_DIR unset) — rollback uses the in-memory copy"
        return 0
    fi
    mkdir -p "$PAV_BACKUP_DIR"
    local f="$PAV_BACKUP_DIR/config-$(date -u +%Y%m%dT%H%M%SZ)-$PROD_ID.json"
    printf '%s' "$1" > "$f"
    chmod 600 "$f"
    warn "plaintext credentials written to $f — PAV_BACKUP_DIR was set explicitly"
    warn "shred it when you no longer need it: shred -u '$f'"
}

# =============================================================================
# Menu
# =============================================================================
find_prod
fetch_live_config
CURRENT="$LIVE_CONFIG"

CHOICE=""
if [[ "$PAV_NONINTERACTIVE" == "1" ]]; then
    CHOICE="${PAV_CHOICE:-2}"
    IS_STAGING=false
    [[ "${PAV_MODE:-production}" == "staging" ]] && { CHOICE=1; IS_STAGING=true; }
    info "non-interactive: choice=$CHOICE staging=$IS_STAGING"
else
    echo "Current mode: $(echo "$CURRENT" | jq -r 'if .staging then "SANDBOX (staging: true)" else "PRODUCTION (staging: false)" end')"
    echo "Domain      : $(echo "$CURRENT" | jq -r '.domain')"
    echo ""
    echo "What do you want to do?"
    echo "  1) Configure Staging/Sandbox"
    echo "  2) Configure Production"
    echo "  3) Switch Active Mode only (keep all credentials)"
    echo "  4) Rotate ACME EAB keys (ZeroSSL) — or clear them to fall back to Let's Encrypt"
    ask CHOICE "Choice (1-4): "
fi

NEW_STAGING=$(echo "$CURRENT" | jq '.staging')

case "$CHOICE" in
    1) NEW_STAGING=true;  echo "--- Staging/Sandbox Configuration ---" ;;
    2) NEW_STAGING=false; echo "--- Production Configuration ---" ;;
    3) NEW_STAGING=true;  echo "--- Switch Active Mode ---"
       if [[ "$PAV_NONINTERACTIVE" == "1" ]]; then
           NEW_STAGING=$( [[ "${PAV_MODE:-production}" == "staging" ]] && echo true || echo false )
       else
           echo "  1) Staging   2) Production"
           ask MODE_CHOICE "Active Mode (1-2): "
           NEW_STAGING=$( [[ "$MODE_CHOICE" == "1" ]] && echo true || echo false )
       fi
       info "mode -> $( [[ "$NEW_STAGING" == "true" ]] && echo staging || echo production )" ;;
    4) NEW_STAGING=$(echo "$CURRENT" | jq '.staging')
       echo "--- ACME EAB keys ---"
       echo "EAB present  -> ZeroSSL directory. Cleared -> Let's Encrypt (no EAB needed)."
       if [[ "$PAV_NONINTERACTIVE" == "1" ]]; then
           FINAL_EAB_ID="${PAV_EAB_KEY_ID-}"
           FINAL_EAB_HMAC="${PAV_EAB_HMAC_KEY-}"
       else
           cur_eab=$(echo "$CURRENT" | jq -r '.eab_key_id // ""')
           ask EAB_IN "New EAB Key ID (blank = keep '${cur_eab:-none}', 'clear' = drop EAB): "
           if [[ "$EAB_IN" == "clear" ]]; then
               FINAL_EAB_ID=""; FINAL_EAB_HMAC=""
           elif [[ -n "$EAB_IN" ]]; then
               FINAL_EAB_ID="$EAB_IN"
               # This one used to go through ask(), which ECHOES the HMAC key
               # into the terminal (and into terminal scrollback). It is a
               # credential: password field, entered twice.
               ask_secret2 FINAL_EAB_HMAC "New EAB HMAC key: "
           else
               FINAL_EAB_ID=$(echo "$CURRENT" | jq -r '.eab_key_id // ""')
               FINAL_EAB_HMAC=$(echo "$CURRENT" | jq -r '.eab_hmac_key // ""')
           fi
       fi
       NEW_CONFIG=$(echo "$CURRENT" | jq --arg i "$FINAL_EAB_ID" --arg h "$FINAL_EAB_HMAC" \
           '.eab_key_id=$i | .eab_hmac_key=$h')
       ;;
    *) die "invalid choice '$CHOICE'" ;;
esac

# --- Build the merged config (merge, never rebuild) --------------------------
# Choice 3 flips ONLY the staging bit — the menu promises "keep all
# credentials", so it must not re-prompt for them. Choice 4 already built its
# config in the case block above. Only 1 and 2 collect credentials.
if [[ "$CHOICE" == "3" ]]; then
    NEW_CONFIG=$(echo "$CURRENT" | jq --argjson st "$NEW_STAGING" '.staging=$st')
elif [[ "$CHOICE" != "4" ]]; then
    # A blank answer means "keep the live value" — that is the whole point of
    # reading the baseline first. Defaults come from the live config, so a
    # partial run (rotate only the secret you are holding) cannot blank out the
    # fields you did not mention.
    def_dom=$(echo "$CURRENT" | jq -r '.domain')
    def_pid=$(echo "$CURRENT" | jq -r '.paypal_client_id')
    def_psec=$(echo "$CURRENT" | jq -r '.paypal_client_secret')
    def_vid=$(echo "$CURRENT" | jq -r '.paypal_verified_client_id')
    def_vsec=$(echo "$CURRENT" | jq -r '.paypal_verified_client_secret')

    if [[ "$PAV_NONINTERACTIVE" == "1" ]]; then
        P_ID="${PAYPAL_CLIENT_ID:-$def_pid}"
        P_SEC="${PAYPAL_CLIENT_SECRET:-$def_psec}"
        V_ID="${PAYPAL_VERIFIED_CLIENT_ID:-$def_vid}"
        V_SEC="${PAYPAL_VERIFIED_CLIENT_SECRET:-$def_vsec}"
        DOM="${DOMAIN:-$def_dom}"
    else
        ask DOM "Domain (default: $def_dom): "
        ask P_ID "PayPal Client ID (default: $def_pid): "
        ask_secret2 P_SEC "PayPal Client Secret (Enter = keep current): "
        ask V_ID "Verified App Client ID (default: $def_vid): "
        ask_secret2 V_SEC "Verified App Client Secret (Enter = keep current): "
    fi

    P_ID="${P_ID:-$def_pid}"; P_SEC="${P_SEC:-$def_psec}"
    V_ID="${V_ID:-$def_vid}"; V_SEC="${V_SEC:-$def_vsec}"
    DOM="${DOM:-$def_dom}"

    NEW_CONFIG=$(echo "$CURRENT" | jq \
        --argjson st "$NEW_STAGING" \
        --arg dom "$(printf '%s' "$DOM" | tr -d '[:space:]')" \
        --arg cid "$(printf '%s' "$P_ID" | tr -d '[:space:]')" \
        --arg csec "$(printf '%s' "$P_SEC" | tr -d '[:space:]')" \
        --arg vcid "$(printf '%s' "$V_ID" | tr -d '[:space:]')" \
        --arg vcsec "$(printf '%s' "$V_SEC" | tr -d '[:space:]')" \
        '.staging=$st | .domain=$dom
         | .paypal_client_id=$cid | .paypal_client_secret=$csec
         | .paypal_verified_client_id=$vcid | .paypal_verified_client_secret=$vcsec')
fi

echo ""
echo "Planned changes (secrets never printed):"
show_plan "$CURRENT" "$NEW_CONFIG"
echo ""

validate_config "$NEW_CONFIG"

if [[ "$PAV_DRY_RUN" == "1" ]]; then
    info "DRY RUN — validated, nothing pushed. Re-run without PAV_DRY_RUN=1 to apply."
    exit 0
fi

if [[ "$PAV_NONINTERACTIVE" != "1" ]]; then
    ask CONFIRM "Push this to $PROD_ID and reboot it? (type 'yes'): "
    [[ "$CONFIRM" == "yes" ]] || die "aborted — nothing pushed"
fi

DOMAIN=$(echo "$NEW_CONFIG" | jq -r '.domain')
backup_config "$CURRENT"
push_config "$NEW_CONFIG"
sync_rebuild_template "$NEW_CONFIG"

info "user_data pushed. DescribeUserData may read 0 right after a good push (known quirk) — verifying via the boot instead."
if verify_boot; then
    NEWMODE=$(echo "$NEW_CONFIG" | jq -r 'if .staging then "sandbox" else "production" end')
    info "✅ rotation complete — enclave is serving, mode = $NEWMODE"
    info "Confirm the environment on the next real login: the signed report's"
    info "'paypal_environment' field must read 'production' (the auditor refuses 'sandbox')."
else
    warn "the enclave has not answered yet. It may still be in the ACME retry ladder"
    warn "(HANDOVER: ZeroSSL flakiness has held :443 dark for over an hour before)."
    warn "Serial console: aliyun ecs GetInstanceConsoleOutput --RegionId $PAV_REGION --InstanceId $PROD_ID | base64 -d"
    # The pre-rotation config is still in THIS process ($CURRENT). Offer the
    # rollback now, before it goes away with the exit — that is what replaces
    # the old on-disk backup file.
    if [[ "$PAV_NONINTERACTIVE" != "1" ]]; then
        echo ""
        ask RB "Push the PRE-ROTATION config back to $PROD_ID? (yes/no): "
        if [[ "$RB" == "yes" ]]; then
            info "restoring pre-rotation config from memory ..."
            push_config "$CURRENT"
            sync_rebuild_template "$CURRENT"
            if verify_boot; then
                info "✅ rollback succeeded — the enclave is serving the pre-rotation config again"
            else
                warn "rollback pushed, but TLS is still not answering."
                warn "Serial console: aliyun ecs GetInstanceConsoleOutput --RegionId $PAV_REGION --InstanceId $PROD_ID | base64 -d"
            fi
        else
            warn "no rollback performed. The pre-rotation values are gone with this"
            warn "process — recover them from the source you originally got them"
            warn "from (PayPal app dashboard, ZeroSSL ACME, the RAM key)."
        fi
    else
        warn "non-interactive: no rollback attempted. Re-run with the original"
        warn "values (PAV_DRY_RUN=1 first) to restore, or fix forward."
    fi
    exit 1
fi
