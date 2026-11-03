#!/usr/bin/env bash
# sync-enclave-userdata.sh — keep the REBUILD path holding the CURRENT credentials.
#
#   bash watchdog/sync-enclave-userdata.sh status              # live vs deployed hashes
#   bash watchdog/sync-enclave-userdata.sh from-instance       # copy live user_data into the template
#   printf '%s' "$CONFIG_JSON" | base64 -w0 | \
#     bash watchdog/sync-enclave-userdata.sh from-stdin        # copy a just-pushed blob
#
# WHY THIS EXISTS
# The enclave's config IS its `user_data` (base64 JSON read at boot from
# http://100.100.100.200/latest/user-data), and `upload-secrets.sh` rotates it
# with Stop -> ModifyInstanceAttribute --UserData -> Start. That writes the
# LIVE INSTANCE only. The rebuild path is different: `pav-watchdog` runs
# RunInstances with the `user_data` baked into the OOS template at deploy time
# (from the gitignored watchdog/dist/config.json). So without this sync, a box
# recreated after a rotation — by the 1-minute heartbeat or by the 5-minute
# preemption notice — boots the OLD credentials while the operator sees a
# healthy instance. Silent, and only visible when PayPal finally rejects them.
#
# This script re-bakes the template from whatever the instance (or the blob you
# just pushed) actually holds, so "recreate" means "same credentials".
#
# SECRETS
# The blob already lives in the deployed template (that is how the rebuild got
# its user_data before this script existed), so this adds no new exposure — it
# keeps the secret out of git, out of execution parameters (ListExecutions
# echoes those in cleartext) and out of this script's output: only sizes and
# sha256 prefixes are printed.
set -uo pipefail

REGION="${PAV_REGION:-cn-beijing}"
TEMPLATE="${PAV_OOS_TEMPLATE:-pav-watchdog}"
SRC="watchdog/oos-watchdog.yaml"
BUILT="/tmp/pav-watchdog.synced.yaml"
TAG_KEY="${PAV_TAG_KEY:-pav-watchdog}"
TAG_VALUE="${PAV_TAG_VALUE:-prod}"

die() { echo "error: $*" >&2; exit 1; }
sha() { printf '%s' "$1" | sha256sum | cut -c1-16; }

prod_instance_id() {
  aliyun ecs DescribeInstances --RegionId "$REGION" --Tag.1.Key "$TAG_KEY" --Tag.1.Value "$TAG_VALUE" 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let j;try{j=JSON.parse(s)}catch(e){return}const i=((j.Instances||{}).Instance||[])[0];console.log(i?i.InstanceId:"")})'
}

live_b64() { # base64 user_data exactly as the API returns it
  local id="$1"
  aliyun ecs DescribeUserData --RegionId "$REGION" --InstanceId "$id" 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let j;try{j=JSON.parse(s)}catch(e){return}const v=typeof j.UserData==="string"?j.UserData:((j.UserData&&j.UserData.Value)||"");process.stdout.write(v)})'
}

# UserData line currently inside the DEPLOYED template.
deployed_b64() {
  aliyun oos GetTemplate --RegionId "$REGION" --TemplateName "$TEMPLATE" 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let j;try{j=JSON.parse(s)}catch(e){return}
        // GetTemplate returns the body at the TOP level (`.Content`);
        // `.Template` only holds metadata (Hash, TemplateVersion, ...).
        const c=j.Content||(j.Template&&j.Template.Content)||"";
        const m=c.match(/UserData:\s*\x27([^\x27]+)\x27/);
        process.stdout.write(m?m[1]:"")})'
}

cmd_status() {
  local id b64 dep
  id=$(prod_instance_id)
  [ -n "$id" ] || die "no instance tagged $TAG_KEY=$TAG_VALUE in $REGION"
  b64=$(live_b64 "$id")
  dep=$(deployed_b64)
  echo "instance        : $id"
  echo "live user_data  : ${#b64} b64 chars, sha256 ${b64:+$(sha "$b64")}"
  echo "template        : $TEMPLATE"
  echo "deployed        : ${#dep} b64 chars, sha256 ${dep:+$(sha "$dep")}"
  if [ -n "$b64" ] && [ "$b64" = "$dep" ]; then
    echo "verdict         : IN SYNC — a rebuild boots the same credentials"
    return 0
  fi
  echo "verdict         : DRIFT — a rebuild would boot DIFFERENT credentials"
  echo "                  fix: bash watchdog/sync-enclave-userdata.sh from-instance"
  return 1
}

apply_b64() {
  local b64="$1" src
  [ -n "$b64" ] || die "empty user_data — refusing to bake an empty config into the rebuild path"
  printf '%s' "$b64" | base64 -d >/dev/null 2>&1 || die "user_data is not valid base64"
  printf '%s' "$b64" | base64 -d | jq -e . >/dev/null 2>&1 || die "user_data does not decode to JSON"

  [ -f "$SRC" ] || die "$SRC missing"
  SRC="$SRC" node -e '
    const fs = require("fs");
    const src = fs.readFileSync(process.env.SRC, "utf8");
    if (!src.includes("__USERDATA_B64__")) { console.error("placeholder missing"); process.exit(1); }
    fs.writeFileSync(process.argv[1], src.replaceAll("__USERDATA_B64__", process.argv[2]));
  ' "$BUILT" "$b64" || die "template build failed"

  aliyun oos UpdateTemplate --RegionId "$REGION" --TemplateName "$TEMPLATE" --Content "$(cat "$BUILT")" >/dev/null 2>&1 \
    || die "UpdateTemplate $TEMPLATE failed"

  local dep; dep=$(deployed_b64)
  if [ "$dep" != "$b64" ]; then
    die "template did not take the new user_data (deployed sha256 $(sha "$dep"))"
  fi
  rm -f "$BUILT"
  echo "synced: $TEMPLATE now carries ${#b64} b64 chars, sha256 $(sha "$b64")"
  echo "        (values are never printed — hashes only)"
}

cmd_from_instance() {
  local id b64
  id=$(prod_instance_id)
  [ -n "$id" ] || die "no instance tagged $TAG_KEY=$TAG_VALUE in $REGION"
  b64=$(live_b64 "$id")
  if [ -z "$b64" ]; then
    die "DescribeUserData returned 0 bytes for $id (known quirk right after a push) — retry in a minute, or pipe the blob in with from-stdin"
  fi
  echo "source: live instance $id"
  apply_b64 "$b64"
}

cmd_from_stdin() {
  local b64
  b64=$(cat)
  echo "source: stdin"
  apply_b64 "$b64"
}

case "${1:-status}" in
  status) cmd_status ;;
  from-instance) cmd_from_instance ;;
  from-stdin) cmd_from_stdin ;;
  *) die "usage: sync-enclave-userdata.sh status|from-instance|from-stdin" ;;
esac
