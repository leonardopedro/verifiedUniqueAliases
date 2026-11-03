#!/usr/bin/env bash
# deploy-spot-notice.sh — wire the 5-minute spot preemption notice INTO OOS.
#
#   bash watchdog/deploy-spot-notice.sh deploy   # role + OOS template + rule targets
#   bash watchdog/deploy-spot-notice.sh test     # fire a synthetic notice, prove the chain
#   bash watchdog/deploy-spot-notice.sh status   # rule targets + last notice executions
#
# What it builds:
#   * RAM role `pav-eventbridge-oos` (trusted by eventbridge.aliyuncs.com) with a
#     policy allowing oos:StartExecution only — EventBridge assumes it to call
#     the OOS OpenAPI. The SLS target keeps its own `pav-eventbridge-sls` role.
#   * OOS template `pav-spot-notice` (watchdog/oos-spot-notice.yaml) with the
#     rotating image id injected.
#   * EventBridge rule `pav-spot-interruption` on the default bus with TWO
#     targets: the existing SLS audit log and the new `acs.openapi` target that
#     starts the OOS template. Target keys were discovered live against the API
#     (`acs.openapi.oos` does not exist; `acs.openapi` + Product/Version/Action
#     does) — see the header of watchdog/oos-spot-notice.yaml.
#
# Why the notice needs OOS at all: the reconciler's contract is "a running box
# is left alone". A preemption notice says the box is doomed while it is still
# running, so it is the only way to start the rebuild clock before the box
# disappears. The template records the notice, preflights image/EIP/spot-stock
# and fires an early reconcile.
#
# The enclave config never appears here: user_data lives only in the deployed
# `pav-watchdog` template; this stack of resources carries no secret.
set -uo pipefail

REGION="${PAV_REGION:-cn-beijing}"
ZONE="${PAV_ZONE:-cn-beijing-i}"
EIP="${PAV_EIP_ID:-eip-2zet05jbat6wr6rp7elrc}"
INSTANCE_TYPE="${PAV_INSTANCE_TYPE:-ecs.c9i.large}"
RULE="${PAV_SPOT_RULE:-pav-spot-interruption}"
NOTICE_TEMPLATE="${PAV_NOTICE_TEMPLATE:-pav-spot-notice}"
ROLE="pav-eventbridge-oos"
POLICY="pav-eventbridge-oos-policy"
SLS_PROJECT="${PAV_SLS_PROJECT:-pav-events}"
SLS_LOGSTORE="${PAV_SLS_LOGSTORE:-spot-notices}"
SLS_ROLE="pav-eventbridge-sls"
CONFIG="watchdog/dist/config.json"
SRC="watchdog/oos-spot-notice.yaml"
BUILT="/tmp/pav-spot-notice.built.yaml"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/jget.js" <<'JS'
const fs = require('fs');
let s = fs.readFileSync(0, 'utf8');
let v;
try { v = JSON.parse(s); } catch (e) { console.log(''); process.exit(0); }
for (const p of (process.argv[2] || '').split('.')) {
  if (!p) continue;
  v = v == null ? v : v[p];
}
if (v === undefined) console.log('');
else if (typeof v === 'object') console.log(JSON.stringify(v));
else console.log(String(v));
JS
jget() { node "$TMP/jget.js" "$1"; }

die() { echo "error: $*" >&2; exit 1; }

image_id() { node -p "require('./$CONFIG').spec.imageId" 2>/dev/null || die "$CONFIG missing (run: node watchdog/make-zip.mjs)"; }

build_template() {
  [ -f "$CONFIG" ] || die "$CONFIG missing"
  local IMG; IMG=$(image_id)
  sed "s|__IMAGE_ID__|$IMG|g" "$SRC" > "$BUILT" || die "template build failed"
  grep -q '__IMAGE_ID__' "$BUILT" && die "placeholder not substituted"
  echo "built notice template (image $IMG)"
}

ensure_role() {
  cat > /tmp/pav-eb-trust.json <<'EOF'
{"Statement":[{"Action":"sts:AssumeRole","Effect":"Allow","Principal":{"Service":["eventbridge.aliyuncs.com"]}}],"Version":"1"}
EOF
  if aliyun ram GetRole --RoleName "$ROLE" >/dev/null 2>&1; then
    echo "role present: $ROLE"
  else
    aliyun ram CreateRole --RoleName "$ROLE" \
      --AssumeRolePolicyDocument "$(cat /tmp/pav-eb-trust.json)" \
      --Description "EventBridge -> OOS StartExecution for spot preemption notices" >/dev/null 2>&1 \
      || die "CreateRole $ROLE failed"
    echo "role created: $ROLE"
  fi
  # The OOS execution STARTED BY EVENTBRIDGE runs as THIS role, not as the OOS
  # default role: the first live delivery failed every ECS call with
  # `Forbidden.RAM` until the ECS/VPC actions were added. The notice template
  # (Describe*) and the reconcile it starts (RunInstances + EIP bind) both run
  # under it, so the set below is the union of what they call.
  cat > /tmp/pav-eb-policy.json <<'EOF'
{"Version":"1","Statement":[
 {"Effect":"Allow","Action":["oos:StartExecution","oos:GetTemplate","oos:ListTemplates"],"Resource":"*"},
 {"Effect":"Allow","Action":["ecs:DescribeInstances","ecs:RunInstances","ecs:DescribeImages","ecs:DescribeDisks","ecs:DescribeTags","ecs:DescribeAvailableResource","ecs:DescribeUserData"],"Resource":"*"},
 {"Effect":"Allow","Action":["vpc:DescribeEipAddresses","vpc:AssociateEipAddress"],"Resource":"*"}
]}
EOF
  if aliyun ram GetPolicy --PolicyName "$POLICY" --PolicyType Custom 2>/dev/null | grep -q '"PolicyName"'; then
    # RAM caps custom policies at 5 versions; prune the oldest non-default one
    # before adding, or every later deploy silently keeps a stale policy.
    if ! aliyun ram CreatePolicyVersion --PolicyName "$POLICY" \
          --PolicyDocument "$(cat /tmp/pav-eb-policy.json)" --SetAsDefault true >/dev/null 2>&1; then
      local OLD
      OLD=$(aliyun ram ListPolicyVersions --PolicyName "$POLICY" --PolicyType Custom 2>/dev/null \
        | jq -r '[.PolicyVersions.PolicyVersion[] | select(.IsDefaultVersion==false)] | sort_by(.CreateDate) | .[0].VersionId // empty')
      [ -n "$OLD" ] || die "policy version cap hit and no prunable version exists"
      aliyun ram DeletePolicyVersion --PolicyName "$POLICY" --VersionId "$OLD" >/dev/null 2>&1 \
        || die "could not prune policy version $OLD"
      aliyun ram CreatePolicyVersion --PolicyName "$POLICY" \
        --PolicyDocument "$(cat /tmp/pav-eb-policy.json)" --SetAsDefault true >/dev/null 2>&1 \
        || die "CreatePolicyVersion $POLICY failed after pruning $OLD"
      echo "policy version pruned: $OLD"
    fi
  else
    aliyun ram CreatePolicy --PolicyName "$POLICY" \
      --PolicyDocument "$(cat /tmp/pav-eb-policy.json)" \
      --Description "Allow EventBridge to start OOS executions" >/dev/null 2>&1 \
      || die "CreatePolicy $POLICY failed"
  fi
  aliyun ram AttachPolicyToRole --PolicyType Custom --PolicyName "$POLICY" --RoleName "$ROLE" >/dev/null 2>&1 || true
  echo "policy attached: $POLICY"
}

upsert_notice_template() {
  if aliyun oos ListTemplates --RegionId "$REGION" --TemplateName "$NOTICE_TEMPLATE" 2>/dev/null \
      | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let j;try{j=JSON.parse(s)}catch(e){process.exit(1)}process.exit((j.Templates||[]).some(t=>t.TemplateName===process.argv[1])?0:1)})' "$NOTICE_TEMPLATE"; then
    aliyun oos UpdateTemplate --RegionId "$REGION" --TemplateName "$NOTICE_TEMPLATE" --Content "$(cat "$BUILT")" >/dev/null 2>&1 \
      || die "UpdateTemplate $NOTICE_TEMPLATE failed"
    echo "template updated: $NOTICE_TEMPLATE"
  else
    aliyun oos CreateTemplate --RegionId "$REGION" --TemplateName "$NOTICE_TEMPLATE" --Content "$(cat "$BUILT")" >/dev/null 2>&1 \
      || die "CreateTemplate $NOTICE_TEMPLATE failed"
    echo "template created: $NOTICE_TEMPLATE"
  fi
}

# Two targets: the audit log and the signal. Parameters arrives as a CONSTANT
# JSON string; the nested `Parameters` member is itself a JSON string because
# OOS StartExecution takes its template parameters as a string. Built with node
# so the escaping is real JSON (a shell heredoc produced JSON the API rejected
# with `JSON Array parsing error`).
rule_targets_json() {
  local ACCT; ACCT=$(aliyun sts GetCallerIdentity 2>/dev/null | jget 'AccountId')
  [ -n "$ACCT" ] || die "cannot resolve account id"
  node - "$ACCT" "$REGION" "$SLS_PROJECT" "$SLS_LOGSTORE" "$SLS_ROLE" "$ROLE" "$NOTICE_TEMPLATE" "$(image_id)" <<'JS'
const [acct, region, proj, ls, slsRole, role, tpl, img] = process.argv.slice(2);
const inner = JSON.stringify({ imageId: img });
const outer = JSON.stringify({ TemplateName: tpl, Parameters: inner });
const targets = [
  { Id: 'sls-spot-notices', Type: 'acs.sls',
    Endpoint: `acs:sls:${region}:${acct}:project/${proj}/logstore/${ls}`,
    PushRetryStrategy: 'BACKOFF_RETRY', ErrorsTolerance: 'ALL', PushSelector: 'PARAM_TRANSFORMER',
    ParamList: [
      { ResourceKey: 'Project', Form: 'CONSTANT', Value: proj },
      { ResourceKey: 'LogStore', Form: 'CONSTANT', Value: ls },
      { ResourceKey: 'RoleName', Form: 'CONSTANT', Value: slsRole },
      { ResourceKey: 'Body', Form: 'ORIGINAL', Value: '' },
      { ResourceKey: 'ContentType', Form: 'CONSTANT', Value: 'JSON' },
    ] },
  { Id: 'oos-spot-notice', Type: 'acs.openapi',
    PushRetryStrategy: 'BACKOFF_RETRY', ErrorsTolerance: 'ALL', PushSelector: 'PARAM_TRANSFORMER',
    ParamList: [
      { ResourceKey: 'TargetRegion', Form: 'CONSTANT', Value: region },
      { ResourceKey: 'Product', Form: 'CONSTANT', Value: 'oos' },
      { ResourceKey: 'Version', Form: 'CONSTANT', Value: '2019-06-01' },
      { ResourceKey: 'Action', Form: 'CONSTANT', Value: 'StartExecution' },
      { ResourceKey: 'RoleName', Form: 'CONSTANT', Value: role },
      { ResourceKey: 'Parameters', Form: 'CONSTANT', Value: outer },
    ] },
];
process.stdout.write(JSON.stringify(targets));
JS
}

upsert_rule() {
  local FILTER='{"source":[{"prefix":"acs.ecs"}],"type":[{"prefix":"ecs:Instance:PreemptibleInstanceInterruption"}]}'
  local TARGETS; TARGETS=$(rule_targets_json)
  local OUT
  # UpdateRule accepts no targets (verified: only FilterPattern/Description/Status),
  # so the rule is recreated with the full target list. The gate is seconds long and
  # a notice arriving in that window is still in SLS-free limbo only once.
  if aliyun eventbridge GetRule --EventBusName default --RuleName "$RULE" >/dev/null 2>&1; then
    aliyun eventbridge DeleteRule --EventBusName default --RuleName "$RULE" >/dev/null 2>&1 \
      || die "DeleteRule $RULE failed (cannot recreate with both targets)"
  fi
  OUT=$(aliyun eventbridge CreateRule --EventBusName default --RuleName "$RULE" \
    --FilterPattern "$FILTER" --EventTargets "$TARGETS" 2>&1)
  printf '%s' "$OUT" | grep -qE '"RuleARN"|"RequestId"' || { printf '%s\n' "$OUT" | head -5; die "rule upsert failed"; }
  echo "rule upserted: $RULE (targets: sls-spot-notices, oos-spot-notice)"
}

cmd_deploy() {
  build_template
  ensure_role
  upsert_notice_template
  upsert_rule
}

# Proves BOTH halves, because publishing to the default bus is impossible here:
#   * the default bus only accepts Aliyun's own sources (a custom source is
#     refused outright), so a synthetic event cannot be aimed at the live rule;
#   * PutEvents has no usable path (CLI plugin -> console endpoint 503, a hand
#     signed ROA request -> SignatureDoesNotMatch on the OAuth STS token, OOS
#     ExecuteAPI -> no PutEvents in its whitelist).
# So: a throwaway bus carries an exact copy of the PRODUCTION target (same
# acs.openapi action, same role, same parameter mapping) and an HTTP event
# source feeds the event in. Everything downstream of the bus is the real
# thing. The source is publicly reachable while it exists, hence the immediate
# teardown below.
cmd_test() {
  local BUS="pav-test-$RANDOM" SRC="pav-test-$RANDOM-src" RULE_T="pav-test-$RANDOM-rule"
  local IID; IID=$(aliyun ecs DescribeInstances --RegionId "$REGION" \
    --Tag.1.Key pav-watchdog --Tag.1.Value prod 2>/dev/null | jget 'Instances.Instance.0.InstanceId')
  [ -n "$IID" ] || die "no pav-watchdog=prod instance to build a notice for"

  aliyun eventbridge GetRule --EventBusName default --RuleName "$RULE" 2>/dev/null \
    | jq '[.Data.Targets[] | select(.Id == "oos-spot-notice")]' > /tmp/pav-test-target.json
  jq -e 'length == 1' /tmp/pav-test-target.json >/dev/null 2>&1 \
    || die "production rule $RULE has no oos-spot-notice target (run deploy first)"

  cleanup_test() {
    aliyun eventbridge delete-event-source --event-bus-name "$BUS" --event-source-name "$SRC" >/dev/null 2>&1
    aliyun eventbridge DeleteRule --EventBusName "$BUS" --RuleName "$RULE_T" >/dev/null 2>&1
    aliyun eventbridge DeleteEventBus --EventBusName "$BUS" >/dev/null 2>&1
    rm -f /tmp/pav-test-target.json /tmp/pav-ce.json
  }
  trap cleanup_test RETURN

  aliyun eventbridge CreateEventBus --EventBusName "$BUS" >/dev/null 2>&1 || die "CreateEventBus failed"
  aliyun eventbridge CreateRule --EventBusName "$BUS" --RuleName "$RULE_T" --FilterPattern '{}' \
    --EventTargets "$(cat /tmp/pav-test-target.json)" >/dev/null 2>&1 || die "CreateRule failed"
  aliyun eventbridge CreateEventSource --EventBusName "$BUS" --EventSourceName "$SRC" \
    --Description "transient synthetic spot notice" \
    --SourceHttpEventParameters '{"Type":"HTTPS","Method":["POST"],"SecurityConfig":"none"}' >/dev/null 2>&1 \
    || die "CreateEventSource failed"
  local URL
  URL=$(aliyun eventbridge list-user-defined-event-sources --event-bus-name "$BUS" 2>/dev/null \
    | jq -r '.Data.EventSourceList[0].ExternalSourceConfig.PublicWebHookUrl[0] // empty')
  [ -n "$URL" ] || die "event source has no webhook url"

  local BEFORE; BEFORE=$(notice_exec_ids)
  echo "[sender] posting a synthetic notice for $IID through a transient HTTP event source"
  node -e 'const iid=process.argv[1];require("fs").writeFileSync("/tmp/pav-ce.json",JSON.stringify({id:"pav-test-"+Date.now(),source:"pav.test",type:"pav.test:PreemptibleInstanceInterruption",specversion:"1.0",subject:"acs:ecs:cn-beijing:"+iid,datacontenttype:"application/json",time:new Date().toISOString(),data:{instanceId:iid}}))' "$IID"
  curl -sS -X POST -H 'Content-Type: application/cloudevents+json' --data-binary @/tmp/pav-ce.json \
    "$URL" -o /dev/null -w '[sender] webhook HTTP %{http_code}\n' --max-time 30

  local ID="" i
  for i in $(seq 1 15); do
    sleep 4
    ID=$(comm -13 <(printf '%s\n' $BEFORE | sort -u) <(notice_exec_ids | tr ' ' '\n' | sort -u) | head -1)
    [ -n "$ID" ] && break
  done
  [ -n "$ID" ] || { echo "[sender] NO execution appeared (check the role policy + target)"; return 1; }
  echo "[sender] delivered - execution: $ID"
  for i in $(seq 1 20); do
    local ST
    ST=$(aliyun oos ListExecutions --RegionId "$REGION" --ExecutionId "$ID" 2>/dev/null | jget 'Executions.0.Status')
    case "$ST" in Success|Failed|Cancelled) break;; esac
    sleep 4
  done
  aliyun oos ListExecutions --RegionId "$REGION" --ExecutionId "$ID" 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let j;try{j=JSON.parse(s)}catch(e){return}const e=(j.Executions||[])[0]||{};console.log("  status:",e.Status);console.log("  message:",e.StatusMessage||"-");console.log("  outputs:",e.Outputs||"-")})'
}

notice_exec_ids() {
  # MaxResults must be 10..100: a smaller value is rejected, and the rejected
  # call looks exactly like "no executions" if the error is swallowed.
  aliyun oos ListExecutions --RegionId "$REGION" --TemplateName "$NOTICE_TEMPLATE" --MaxResults 10 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let j;try{j=JSON.parse(s)}catch(e){return}console.log((j.Executions||[]).map(e=>e.ExecutionId).join(" "))})'
}

cmd_status() {
  echo "rule: $RULE"
  aliyun eventbridge GetRule --EventBusName default --RuleName "$RULE" 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let j;try{j=JSON.parse(s)}catch(e){return}const d=j.Data||{};console.log("  status:",d.Status);for(const t of (d.Targets||[]))console.log("  target:",t.Id,t.Type)})'
  echo "last notice executions:"
  aliyun oos ListExecutions --RegionId "$REGION" --TemplateName "$NOTICE_TEMPLATE" --MaxResults 10 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let j;try{j=JSON.parse(s)}catch(e){return}for(const e of (j.Executions||[]).slice(0,5))console.log("  ",e.ExecutionId,e.Status,e.StartDate||"",e.Outputs||"")})'
}

case "${1:-deploy}" in
  deploy) cmd_deploy ;;
  test) cmd_test ;;
  status) cmd_status ;;
  *) die "usage: deploy-spot-notice.sh deploy|test|status" ;;
esac
