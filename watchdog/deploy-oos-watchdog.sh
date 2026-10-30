#!/usr/bin/env bash
# deploy-oos-watchdog.sh — FC-free self-healing watchdog for the TDX enclave.
#
# Replaces watchdog/deploy-watchdog.sh's Function Compute path with Operation
# Orchestration Service (OOS), which this account can use while `CreateFunction`
# still answers 'code: 403, Current user is in debt overdue'.
#
#   bash watchdog/deploy-oos-watchdog.sh deploy     # templates + start the 5-min chain
#   bash watchdog/deploy-oos-watchdog.sh schedule on|off|status
#   bash watchdog/deploy-oos-watchdog.sh run        # one reconcile now (real tag)
#   bash watchdog/deploy-oos-watchdog.sh selftest   # create+delete a THROWAWAY box
#   bash watchdog/deploy-oos-watchdog.sh status     # templates, chain, last runs
#   bash watchdog/deploy-oos-watchdog.sh delete     # remove templates (stops the chain)
#
# Two templates:
#   pav-watchdog     — the idempotent reconciler (create the box only when the
#                      prod tag is absent, then bind the reserved EIP).
#   pav-watchdog-hb  — the 5-minute heartbeat, a self-rearming chain (see the
#                      header of oos-heartbeat.yaml for why no native scheduler
#                      on this account can do it: state configurations reject
#                      user templates, its rate floor is 30 minutes, EventBridge
#                      has no OOS target, FnF is not enabled, FC is 403).
#
# The enclave config never leaves watchdog/dist/config.json except as the
# deployed template's inline user_data (OOS cannot carry it as a parameter: a
# secret parameter is capped at 4096 chars and `{{ oos-secret:name }}` is
# rejected in task parameters).
set -uo pipefail

REGION="${PAV_REGION:-cn-beijing}"
TEMPLATE="${PAV_OOS_TEMPLATE:-pav-watchdog}"
HB_TEMPLATE="${PAV_OOS_HB_TEMPLATE:-pav-watchdog-hb}"
CONFIG="watchdog/dist/config.json"
SRC="watchdog/oos-watchdog.yaml"
HB_SRC="watchdog/oos-heartbeat.yaml"
BUILT="/tmp/pav-oos-watchdog.built.yaml"
HB_BUILT="/tmp/pav-oos-hb.built.yaml"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/jget.js" <<'JS'
const fs = require('fs');
let s = fs.readFileSync(0, 'utf8');
let j;
try { j = JSON.parse(s); } catch (e) { console.log(''); process.exit(0); }
let v = j;
for (const p of (process.argv[2] || '').split('.')) { if (p === '') continue; v = v == null ? v : v[p]; }
if (v === undefined) console.log('');
else if (typeof v === 'object') console.log(JSON.stringify(v));
else console.log(String(v));
JS
jget() { node "$TMP/jget.js" "$1"; }

die() { echo "error: $*" >&2; exit 1; }
need_config() { [ -f "$CONFIG" ] || die "$CONFIG missing (run: node watchdog/make-zip.mjs)"; }
image_id() { node -p 'require("./'"$CONFIG"'").spec.imageId'; }

# Build the deployable templates: substitute the enclave user_data blob and the
# rotating image id. Placeholders are the only secret-bearing hook, and they
# live in the repo copies.
build_watchdog_template() {
  need_config
  node -e '
    const fs = require("fs");
    const cfg = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    if (!cfg.userDataB64) { console.error("config.json has no userDataB64"); process.exit(1); }
    const src = fs.readFileSync(process.argv[2], "utf8");
    if (!src.includes("__USERDATA_B64__")) { console.error("placeholder missing in template"); process.exit(1); }
    fs.writeFileSync(process.argv[3], src.replaceAll("__USERDATA_B64__", cfg.userDataB64));
    console.log("built watchdog template (user_data " + cfg.userDataB64.length + " b64 chars)");
  ' "$CONFIG" "$SRC" "$BUILT" || die "template build failed"
}

build_heartbeat_template() {
  need_config
  local IMG IV
  IMG=$(image_id)
  IV="${PAV_OOS_INTERVAL:-PT1M}"
  sed -e "s|__IMAGE_ID__|$IMG|g" -e "s|__INTERVAL__|$IV|g" "$HB_SRC" > "$HB_BUILT" || die "heartbeat build failed"
  grep -q '__IMAGE_ID__\|__INTERVAL__' "$HB_BUILT" && die "heartbeat placeholder not substituted"
  echo "built heartbeat template (image $IMG, interval $IV)"
}

# ListTemplates matches on a NAME PREFIX, so asking for `pav-watchdog` also
# returns `pav-watchdog-hb`; checking only index 0 made a present template look
# absent and turned `deploy` into a failing CreateTemplate. Match exactly across
# the whole list.
template_exists() {
  aliyun oos ListTemplates --RegionId "$REGION" --TemplateName "$1" 2>/dev/null \
    | node -e '
      const fs = require("fs");
      let j; try { j = JSON.parse(fs.readFileSync(0, "utf8")); } catch (e) { process.exit(1); }
      const hit = (j.Templates || []).some((t) => t.TemplateName === process.argv[1]);
      process.exit(hit ? 0 : 1);
    ' "$1"
}

upsert_template() {
  local NAME="$1" FILE="$2"
  if template_exists "$NAME"; then
    aliyun oos UpdateTemplate --RegionId "$REGION" --TemplateName "$NAME" --Content "$(cat "$FILE")" >/dev/null 2>&1 \
      || die "UpdateTemplate $NAME failed"
    echo "template updated: $NAME"
  else
    aliyun oos CreateTemplate --RegionId "$REGION" --TemplateName "$NAME" --Content "$(cat "$FILE")" >/dev/null 2>&1 \
      || die "CreateTemplate $NAME failed"
    echo "template created: $NAME"
  fi
}

start_exec() { # start_exec <template> [parameters-json]
  local NAME="$1" PARAMS="${2:-}" OUT ID
  if [ -n "$PARAMS" ]; then
    OUT=$(aliyun oos StartExecution --RegionId "$REGION" --TemplateName "$NAME" --Parameters "$PARAMS" 2>&1)
  else
    OUT=$(aliyun oos StartExecution --RegionId "$REGION" --TemplateName "$NAME" 2>&1)
  fi
  ID=$(printf '%s' "$OUT" | jget 'Execution.ExecutionId')
  [ -n "$ID" ] || { printf '%s\n' "$OUT" | head -5; return 1; }
  printf '%s' "$ID"
}

# Live heartbeat executions = the chain(s) in flight. A successor is created in
# `Started`/`Waiting` while it sleeps out its interval, so filtering on
# `Running` alone reports a perfectly healthy chain as NONE (observed live).
hb_running_ids() {
  aliyun oos ListExecutions --RegionId "$REGION" --TemplateName "$HB_TEMPLATE" --MaxResults 100 2>/dev/null \
    | node -e '
      const fs = require("fs");
      const LIVE = new Set(["Running", "Started", "Queued", "Waiting", "Pending"]);
      let j; try { j = JSON.parse(fs.readFileSync(0, "utf8")); } catch (e) { console.log(""); process.exit(0); }
      const list = (j.Executions || []).filter((e) => e.TemplateName === process.argv[1] && LIVE.has(e.Status));
      console.log(list.map((e) => e.ExecutionId).join(" "));
    ' "$HB_TEMPLATE"
}

stop_chain() {
  local IDS
  IDS=$(hb_running_ids)
  if [ -z "$IDS" ]; then echo "no running heartbeat"; return 0; fi
  for id in $IDS; do
    aliyun oos CancelExecution --RegionId "$REGION" --ExecutionId "$id" >/dev/null 2>&1 \
      && echo "cancelled heartbeat $id" || echo "could not cancel $id"
  done
}

cmd_deploy() {
  build_watchdog_template
  build_heartbeat_template
  upsert_template "$TEMPLATE" "$BUILT"
  upsert_template "$HB_TEMPLATE" "$HB_BUILT"
  cmd_schedule_on
}

cmd_schedule_on() {
  # Exactly one chain: cancel whatever is running, then start a fresh heartbeat.
  stop_chain
  local ID
  ID=$(start_exec "$HB_TEMPLATE") || die "could not start the heartbeat"
  local IV
  IV="${PAV_OOS_INTERVAL:-PT1M}"
  echo "heartbeat started: $ID (reconciles every $IV)"
  echo "  chain: $ID sleeps $IV, rearms exactly ONE successor, then runs $TEMPLATE"
}

cmd_schedule_off() { stop_chain; }

cmd_schedule_status() {
  local IDS
  IDS=$(hb_running_ids)
  echo "running heartbeats: ${IDS:-NONE}"
  aliyun oos ListExecutions --RegionId "$REGION" --TemplateName "$HB_TEMPLATE" --MaxResults 5 2>/dev/null \
    | node -e '
      const fs = require("fs");
      let j; try { j = JSON.parse(fs.readFileSync(0, "utf8")); } catch (e) { process.exit(0); }
      for (const e of (j.Executions || []).slice(0, 5))
        console.log("  hb:", e.ExecutionId, e.Status, e.StartDate || "", e.Outputs || "");
    '
}

cmd_run() {
  need_config
  local ID ST
  ID=$(start_exec "$TEMPLATE" "{\"imageId\":\"$(image_id)\"}") || die "StartExecution failed"
  for _ in $(seq 1 30); do
    ST=$(aliyun oos ListExecutions --RegionId "$REGION" --ExecutionId "$ID" 2>/dev/null | jget 'Executions.0.Status')
    case "$ST" in Success|Failed|Cancelled) break;; esac
    sleep 3
  done
  echo "execution $ID: $ST"
  aliyun oos ListExecutions --RegionId "$REGION" --ExecutionId "$ID" 2>/dev/null | jget 'Executions.0.Outputs'
}

cmd_selftest() {
  need_config
  echo "creating a THROWAWAY box tagged pav-watchdog=oos-selftest (never prod)"
  local ID ST LIST OUT NEWID
  ID=$(start_exec "$TEMPLATE" "{\"imageId\":\"$(image_id)\",\"tagValue\":\"oos-selftest\",\"instanceName\":\"pav-oos-selftest\"}") \
    || die "StartExecution failed"
  for _ in $(seq 1 30); do
    LIST=$(aliyun oos ListExecutions --RegionId "$REGION" --ExecutionId "$ID" 2>/dev/null)
    ST=$(printf '%s' "$LIST" | jget 'Executions.0.Status')
    case "$ST" in Success|Failed|Cancelled) break;; esac
    sleep 5
  done
  OUT=$(printf '%s' "$LIST" | jget 'Executions.0.Outputs')
  echo "  status: $ST | outputs: ${OUT:-{}}"
  NEWID=$(printf '%s' "$OUT" | jget 'instanceId')
  aliyun oos DeleteExecutions --RegionId "$REGION" --ExecutionIds "[\"$ID\"]" >/dev/null 2>&1
  if [ -n "$NEWID" ] && [ "$NEWID" != "null" ]; then
    aliyun ecs DescribeDisks --RegionId "$REGION" --InstanceId "$NEWID" 2>/dev/null \
      | node -e '
        const fs = require("fs");
        let j; try { j = JSON.parse(fs.readFileSync(0, "utf8")); } catch (e) { process.exit(0); }
        for (const d of ((j.Disks || {}).Disk || [])) console.log("  disk:", d.Category, d.Size + "GiB", d.Type);
      '
    echo "deleting selftest box $NEWID"
    for _ in 1 2 3 4 5; do
      aliyun ecs DeleteInstance --RegionId "$REGION" --InstanceId "$NEWID" --Force true >/dev/null 2>&1
      sleep 4
      aliyun ecs DescribeInstances --RegionId "$REGION" --InstanceIds "[\"$NEWID\"]" 2>/dev/null \
        | node -e '
          const fs = require("fs");
          let j; try { j = JSON.parse(fs.readFileSync(0, "utf8")); } catch (e) { console.log("  state: GONE"); process.exit(0); }
          const i = ((j.Instances || {}).Instance || [])[0];
          console.log("  state:", i ? i.Status : "GONE");
        '
    done
  fi
}

cmd_status() {
  echo "template: $(aliyun oos ListTemplates --RegionId "$REGION" --TemplateName "$TEMPLATE" 2>/dev/null | jget 'Templates.0.TemplateName') $(aliyun oos ListTemplates --RegionId "$REGION" --TemplateName "$TEMPLATE" 2>/dev/null | jget 'Templates.0.TemplateVersion')"
  echo "heartbeat template: $(aliyun oos ListTemplates --RegionId "$REGION" --TemplateName "$HB_TEMPLATE" 2>/dev/null | jget 'Templates.0.TemplateName') $(aliyun oos ListTemplates --RegionId "$REGION" --TemplateName "$HB_TEMPLATE" 2>/dev/null | jget 'Templates.0.TemplateVersion')"
  cmd_schedule_status
  aliyun oos ListExecutions --RegionId "$REGION" --TemplateName "$TEMPLATE" --MaxResults 3 2>/dev/null \
    | node -e '
      const fs = require("fs");
      let j; try { j = JSON.parse(fs.readFileSync(0, "utf8")); } catch (e) { process.exit(0); }
      for (const e of (j.Executions || []).slice(0, 3))
        console.log("  run:", e.ExecutionId, e.Status, e.EndDate || "", e.Outputs || "");
    '
}

cmd_delete() {
  stop_chain
  aliyun oos DeleteTemplate --RegionId "$REGION" --TemplateName "$HB_TEMPLATE" 2>&1 | head -2
  aliyun oos DeleteTemplate --RegionId "$REGION" --TemplateName "$TEMPLATE" 2>&1 | head -2
}

case "${1:-deploy}" in
  deploy) cmd_deploy ;;
  schedule)
    case "${2:-status}" in
      on) cmd_schedule_on ;;
      off) cmd_schedule_off ;;
      status) cmd_schedule_status ;;
      *) die "usage: schedule on|off|status" ;;
    esac ;;
  run) cmd_run ;;
  selftest) cmd_selftest ;;
  status) cmd_status ;;
  delete) cmd_delete ;;
  *) die "unknown action: $1" ;;
esac
