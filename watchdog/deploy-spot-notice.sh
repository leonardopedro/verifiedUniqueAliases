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
  cat > /tmp/pav-eb-policy.json <<'EOF'
{"Version":"1","Statement":[{"Effect":"Allow","Action":["oos:StartExecution","oos:GetTemplate","oos:ListTemplates"],"Resource":"*"}]}
EOF
  if aliyun ram GetPolicy --PolicyName "$POLICY" --PolicyType Custom 2>/dev/null | grep -q '"PolicyName"'; then
    aliyun ram CreatePolicyVersion --PolicyName "$POLICY" \
      --PolicyDocument "$(cat /tmp/pav-eb-policy.json)" --SetAsDefault true >/dev/null 2>&1 \
      || echo "warn: could not add a policy version (5-version cap?), keeping current"
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

# Two halves, tested separately because the sender half cannot be faked here:
#
#   sender   publish a CloudEvent whose source/type match the real notice. The
#            CLI's eventbridge plugin only talks to eventbridge-console.* (503),
#            a hand-signed ROA request is refused on the OAuth-STS token, and
#            OOS's ExecuteAPI whitelist has no PutEvents - so publishing works
#            only when the plugin's endpoint is healthy. When it is not, the
#            real notice (or any cloud event on the bus) is the sender test.
#   receiver run pav-spot-notice directly: proves preflight + early reconcile.
cmd_test() {
  local IID; IID=$(aliyun ecs DescribeInstances --RegionId "$REGION" \
    --Tag.1.Key pav-watchdog --Tag.1.Value prod 2>/dev/null | jget 'Instances.Instance.0.InstanceId')
  IID=${IID:-i-synthetic-notice-test}
  local BEFORE; BEFORE=$(notice_exec_ids)
  echo "[sender] publishing a synthetic spot notice for $IID"
  local PUB
  PUB=$(aliyun eventbridge put-events --event-bus-name default \
    --event-list "[{\"Id\":\"pav-test-$(date +%s)\",\"Source\":\"acs.ecs\",\"Type\":\"ecs:Instance:PreemptibleInstanceInterruption\",\"SpecVersion\":\"1.0\",\"Subject\":\"acs:ecs:$REGION:$IID\",\"DataContentType\":\"application/json\",\"Data\":\"{\\\"instanceId\\\":\\\"$IID\\\"}\"}]" 2>&1 | head -4)
  printf '%s\n' "$PUB"
  local ID="" i
  if ! printf '%s' "$PUB" | grep -qiE 'error|503|403'; then
    for i in $(seq 1 20); do
      sleep 3
      ID=$(comm -13 <(printf '%s\n' $BEFORE | sort -u) <(notice_exec_ids | tr ' ' '\n' | sort -u) | head -1)
      [ -n "$ID" ] && break
    done
  fi
  if [ -z "$ID" ]; then
    echo "[sender] publish unavailable here - exercising the receiver directly instead"
    ID=$(aliyun oos StartExecution --RegionId "$REGION" --TemplateName "$NOTICE_TEMPLATE" \
      --Parameters "{\"imageId\":\"$(image_id)\",\"instanceId\":\"$IID\",\"noticeTime\":\"manual-test\"}" 2>/dev/null \
      | jget 'Execution.ExecutionId')
    [ -n "$ID" ] || { echo "could not start $NOTICE_TEMPLATE"; return 1; }
    echo "[receiver] padded run: $ID (sender half unproven - first real notice is the test)"
  else
    echo "[sender] delivered - new execution: $ID"
  fi
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
  aliyun oos ListExecutions --RegionId "$REGION" --TemplateName "$NOTICE_TEMPLATE" --MaxResults 10 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let j;try{j=JSON.parse(s)}catch(e){return}console.log((j.Executions||[]).map(e=>e.ExecutionId).join(" "))})'
}

cmd_status() {
  echo "rule: $RULE"
  aliyun eventbridge GetRule --EventBusName default --RuleName "$RULE" 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let j;try{j=JSON.parse(s)}catch(e){return}const d=j.Data||{};console.log("  status:",d.Status);for(const t of (d.Targets||[]))console.log("  target:",t.Id,t.Type)})'
  echo "last notice executions:"
  aliyun oos ListExecutions --RegionId "$REGION" --TemplateName "$NOTICE_TEMPLATE" --MaxResults 5 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let j;try{j=JSON.parse(s)}catch(e){return}for(const e of (j.Executions||[]).slice(0,5))console.log("  ",e.ExecutionId,e.Status,e.StartDate||"",e.Outputs||"")})'
}

case "${1:-deploy}" in
  deploy) cmd_deploy ;;
  test) cmd_test ;;
  status) cmd_status ;;
  *) die "usage: deploy-spot-notice.sh deploy|test|status" ;;
esac
