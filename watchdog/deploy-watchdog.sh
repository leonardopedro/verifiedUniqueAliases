#!/bin/bash
# deploy-watchdog.sh — provision the pav-watchdog Function Compute watchdog.
#
# The watchdog replaces the TDX confidential VM when it is RELEASED (spot
# eviction, account-level release). It never touches a Stopped instance, so
# the operator's in-place disk rewrites are safe.
#
#   deploy           tag prod, capture its spec + user_data, bind the FC
#                    function role, build the zip, create the FC function and
#                    both triggers (5-min timer + EventBridge HTTP rule),
#                    then invoke once as a smoke test
#   enable|disable   flip the PAV_WATCHDOG_ENABLED kill switch
#   status           show function, triggers and event rule
#   invoke           run one poll by hand
#   selftest         create a THROWAWAY tagged instance to prove the
#                    recreate path works end to end (prints its id)
#   selftest-cleanup release whatever the selftest created
#
# Credentials: the function runs under the RAM role named by $PAV_ROLE
# (default FC-ECS-Watchdog-Role). Function Compute assumes that role and hands
# the temporary STS credentials to the handler through context.credentials, so
# no AccessKey is created, embedded in the zip, or stored in env vars. The
# script only guarantees the role can be assumed (trust policy names the FC
# service principal) and carries the ECS/VPC policy.
#
# Config lives in watchdog/dist/config.json (built here, gitignored: it holds
# the enclave user_data, i.e. real secrets).
set -euo pipefail
cd "$(dirname "$0")"

REGION="${PAV_REGION:-cn-beijing}"
FN="${PAV_FN:-pav-watchdog}"
ROLE_NAME="${PAV_ROLE:-FC-ECS-Watchdog-Role}"
POLICY_NAME="${PAV_POLICY:-pav-watchdog-ecs}"
PROD_NAME="${PAV_PROD_NAME:-paypal-auth-vm}"
TAG_KEY="pav-watchdog"
RULE_NAME="pav-prod-watchdog"
TIMER_NAME="poll-5m"
HTTP_TRIG_NAME="eventbridge"

jget() { node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{const j=JSON.parse(s);const v=eval(process.argv[1]);console.log(typeof v==='object'?JSON.stringify(v):v)}catch(e){console.error('jget fail: '+e.message);process.exit(2)}})" "$1"; }
ali() { timeout "${ALI_TIMEOUT:-120}" aliyun "$@"; }
die() { echo "ERROR: $*" >&2; exit 1; }

require_creds() {
  ali sts GetCallerIdentity >/dev/null || die "aliyun credentials invalid/expired (run any aliyun command to refresh STS)"
  ACCOUNT_ID=$(ali sts GetCallerIdentity | jget 'j.AccountId')
  [ -n "$ACCOUNT_ID" ] || die "no account id"
}

find_prod() {
  # The instance id changes on role swaps; locate by name (AGENTS: re-list first).
  PROD_JSON=$(ali ecs DescribeInstances --RegionId "$REGION" | node -e "
    let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{
      const list=JSON.parse(s).Instances.Instance||[];
      const p=list.filter(i=>i.InstanceName===process.argv[1]);
      if(!p.length){console.error('no instance named '+process.argv[1]);process.exit(3)}
      console.log(JSON.stringify(p[0]));
    })" "$PROD_NAME")
  PROD_ID=$(echo "$PROD_JSON" | jget 'j.InstanceId')
  echo "prod instance: $PROD_ID"
}

capture_spec() {
  find_prod
  DISK_SIZE=$(ali ecs DescribeDisks --RegionId "$REGION" --InstanceId "$PROD_ID" | jget 'j.Disks.Disk[0].Size')
  # CLI returns `UserData` as a bare string (AGENTS: the nested
  # `UserData.Value` shape is not what this version emits).
  UD=$(ali ecs DescribeUserData --RegionId "$REGION" --InstanceId "$PROD_ID" | jget 'typeof j.UserData==="string"?j.UserData:((j.UserData&&j.UserData.Value)||"")')
  [ -n "$UD" ] || die "DescribeUserData returned nothing for $PROD_ID"
  mkdir -p dist
  PROD_JSON="$PROD_JSON" DISK_SIZE="$DISK_SIZE" UD="$UD" TAG_KEY="$TAG_KEY" ACCOUNT_ID="$ACCOUNT_ID" REGION="$REGION" node -e '
    const i = JSON.parse(process.env.PROD_JSON);
    const cfg = {
      version: 1,
      enabled: true,
      region: process.env.REGION,
      tagKey: process.env.TAG_KEY,
      tagValue: "prod",
      eipAllocationId: i.EipAddress && i.EipAddress.AllocationId || "",
      userDataB64: process.env.UD,
      httpToken: require("crypto").randomBytes(16).toString("hex"),
      maxAttempts: 5,
      retryDelayMs: 10000,
      clientTokenPrefix: "pav-watchdog",
      accountId: process.env.ACCOUNT_ID,
      capturedFrom: { instanceId: i.InstanceId, imageId: i.ImageId, at: new Date().toISOString() },
      spec: {
        zoneId: i.ZoneId,
        imageId: i.ImageId,
        instanceTypes: [i.InstanceType, "ecs.c9i.xlarge"],   // primary, then known-good TDX fallback
        instanceType: i.InstanceType,
        vSwitchId: i.VpcAttributes.VSwitchId,
        vpcId: i.VpcAttributes.VpcId,
        securityGroupId: i.SecurityGroupIds.SecurityGroupId[0],
        instanceName: i.InstanceName,
        systemDiskCategory: "cloud_auto",
        systemDiskSize: Number(process.env.DISK_SIZE),
        internetMaxBandwidthOut: Number(i.InternetMaxBandwidthOut || 0),
      },
    };
    require("fs").writeFileSync("dist/config.json", JSON.stringify(cfg, null, 2));
    console.log("wrote dist/config.json:", JSON.stringify({spec: cfg.spec, eip: cfg.eipAllocationId, udBytes: Buffer.from(cfg.userDataB64,"base64").length}));
  '
}

tag_prod() {
  # CLI exposes the tagging API as `add-tags` (kebab-case), not `CreateTags`.
  ali ecs add-tags --biz-region-id "$REGION" --resource-type instance \
    --resource-id "$PROD_ID" --tag "Key=$TAG_KEY Value=prod" >/dev/null \
    && echo "tagged $PROD_ID with $TAG_KEY=prod"
}

# The function role is created by the operator in RAM (console: Principal
# type = Cloud Service, Principal = Function Compute). This step verifies it
# exists, makes sure the FC service principal may assume it, and attaches the
# ECS/VPC policy the watchdog needs.
ensure_role() {
  local cur has new attached
  ROLE_JSON=$(ali ram GetRole --RoleName "$ROLE_NAME") \
    || die "RAM role '$ROLE_NAME' not found — create it in the RAM console (Principal type: Cloud Service, Principal: Function Compute) or set PAV_ROLE"
  ROLE_ARN=$(printf '%s' "$ROLE_JSON" | jget 'j.Role.Arn')
  [ -n "$ROLE_ARN" ] || die "role $ROLE_NAME returned no ARN"
  echo "function role: $ROLE_NAME -> $ROLE_ARN"

  # FC can only assume a role whose trust policy names fc.aliyuncs.com. A role
  # created for a different FC-family service (agentrun.fc.aliyuncs.com) is NOT
  # assumable by Function Compute, so merge the principal in and keep whatever
  # else was trusted.
  cur=$(printf '%s' "$ROLE_JSON" | jget 'j.Role.AssumeRolePolicyDocument')
  has=$(CUR="$cur" node -e '
    let d = {}; try { d = JSON.parse(process.env.CUR || "{}"); } catch (e) {}
    const st = Array.isArray(d.Statement) ? d.Statement : [];
    const yes = st.some((s) => {
      const svc = [].concat((s && s.Principal && s.Principal.Service) || []);
      return svc.includes("fc.aliyuncs.com");
    });
    console.log(yes ? "yes" : "no");')
  if [ "$has" = "yes" ]; then
    echo "trust policy: fc.aliyuncs.com already allowed"
  else
    new=$(CUR="$cur" node -e '
      let d;
      try { d = JSON.parse(process.env.CUR || "{}"); } catch (e) { d = {}; }
      d.Version = d.Version || "1";
      d.Statement = Array.isArray(d.Statement) ? d.Statement : [];
      let found = false;
      for (const s of d.Statement) {
        if (![].concat((s && s.Action) || []).includes("sts:AssumeRole")) continue;
        found = true;
        s.Principal = s.Principal || {};
        const svc = [].concat(s.Principal.Service || []);
        if (!svc.includes("fc.aliyuncs.com")) svc.push("fc.aliyuncs.com");
        s.Principal.Service = svc;
      }
      if (!found) d.Statement.push({ Action: "sts:AssumeRole", Effect: "Allow", Principal: { Service: ["fc.aliyuncs.com"] } });
      console.log(JSON.stringify(d));')
    ali ram UpdateRole --RoleName "$ROLE_NAME" --NewAssumeRolePolicyDocument "$new" >/dev/null \
      && echo "trust policy: added fc.aliyuncs.com (other principals preserved)"
  fi

  local POLICY_DOC
  POLICY_DOC='{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:DescribeInstances","ecs:RunInstances","ecs:DescribeImages","ecs:DescribeDisks","ecs:DescribeTags"],"Resource":"*"},{"Effect":"Allow","Action":["vpc:DescribeEipAddresses","vpc:AssociateEipAddress"],"Resource":"*"}]}'
  if ali ram GetPolicy --PolicyName "$POLICY_NAME" --PolicyType Custom >/dev/null 2>&1; then
    echo "ram policy: $POLICY_NAME exists"
  else
    ali ram CreatePolicy --PolicyName "$POLICY_NAME" --PolicyDocument "$POLICY_DOC" \
      --Description "pav-watchdog: recreate the TDX enclave box" >/dev/null \
      && echo "ram policy: created $POLICY_NAME"
  fi
  attached=$(ali ram ListPoliciesForRole --RoleName "$ROLE_NAME" \
    | jget "((j.Policies||{}).Policy||[]).some(p=>p.PolicyName==='$POLICY_NAME')")
  if [ "$attached" = "true" ]; then
    echo "role policy: $POLICY_NAME already attached"
  else
    ali ram AttachPolicyToRole --RoleName "$ROLE_NAME" --PolicyName "$POLICY_NAME" --PolicyType Custom >/dev/null \
      && echo "role policy: attached $POLICY_NAME"
  fi
}

build_zip() {
  node make-zip.mjs
  [ -f dist/pav-watchdog.zip ] || die "zip not built"
}

# /tmp/pav-fn-body.json — the CreateFunction body (shared by deploy + selftest).
write_fn_body() {
  local b64
  b64=$(base64 -w0 dist/pav-watchdog.zip 2>/dev/null || base64 dist/pav-watchdog.zip | tr -d '\n')
  FN="$FN" ROLE_ARN="$ROLE_ARN" ZIP_B64="$b64" node -e '
    const fs = require("fs");
    const body = {
      functionName: process.env.FN,
      handler: "handler.handler",
      runtime: "nodejs20",
      description: "Recreate the TDX enclave if it is released (5-min poll + EventBridge). Never touches a Stopped box.",
      timeout: 300,
      memorySize: 256,
      code: { zipFile: process.env.ZIP_B64 },
      // No AccessKey here: FC assumes this role per invocation and passes the
      // STS credentials to the handler in context.credentials.
      role: process.env.ROLE_ARN,
      environmentVariables: {
        PAV_WATCHDOG_ENABLED: "true",
      },
    };
    fs.writeFileSync("/tmp/pav-fn-body.json", JSON.stringify(body));
  '
}

create_function() {
  local out
  FN_GATE=none
  write_fn_body
  if ali fc GetFunction --functionName "$FN" >/dev/null 2>&1; then
    echo "function exists — replacing code + config"
    ali fc DeleteFunction --functionName "$FN" >/dev/null
  fi
  if out=$(ali fc CreateFunction --body "$(cat /tmp/pav-fn-body.json)" 2>&1); then
    echo "$out" | head -c 300
    echo
    return 0
  fi
  case "$out" in
    *"debt overdue"*)
      FN_GATE=debt
      cat <<'EOF'

[gate] Function Compute refused CreateFunction: "Current user is in debt overdue."
       Nothing is wrong with the code, the role or the zip — FC will not
       provision functions while the account balance is overdue.

       Fix: settle the balance in the Alibaba Cloud Billing console, then run:
              bash watchdog/deploy-watchdog.sh deploy

       Already in place and reused by that run: the function role + its policy,
       dist/config.json (prod spec + user_data) and the code zip.
EOF
      ;;
    *)
      FN_GATE=error
      echo "$out"
      ;;
  esac
  return 1
}

create_triggers() {
  if ! ali fc GetTrigger --functionName "$FN" --triggerName "$TIMER_NAME" >/dev/null 2>&1; then
    ali fc CreateTrigger --functionName "$FN" --body '{
      "triggerName":"'"$TIMER_NAME"'",
      "triggerType":"timer",
      "triggerConfig":{"cron":"0 0/5 * * * *","enable":true,"payload":"poll"}
    }' | head -c 300
    echo
  else
    echo "timer trigger exists"
  fi

  if ! ali fc GetTrigger --functionName "$FN" --triggerName "$HTTP_TRIG_NAME" >/dev/null 2>&1; then
    ali fc CreateTrigger --functionName "$FN" --body '{
      "triggerName":"'"$HTTP_TRIG_NAME"'",
      "triggerType":"http",
      "triggerConfig":{"authType":"anonymous","methods":["POST","GET"],"invokeMode":"blocking"}
    }' | head -c 400
    echo
  else
    echo "http trigger exists"
  fi
}

create_eventbridge_rule() {
  local token url
  EB_GATE=none
  token=$(jget 'j.httpToken' < dist/config.json)
  url="https://${ACCOUNT_ID}.${REGION}.fc.aliyuncs.com/2023-03-30/proxy/${FN}/eventbridge"
  FILTER='{"source":["acs.ecs"],"type":["ecs:Instance:StateChange","ecs:Instance:PreemptibleInstanceInterruption","ecs:Instance:SystemFailure.Delete"]}'
  TARGETS=$(TOKEN="$token" URL="$url" node -e '
    const t=process.env.TOKEN, u=process.env.URL;
    console.log(JSON.stringify([{
      Id:"fc-watchdog",
      Type:"https",
      Endpoint:u,
      PushRetryStrategy:"EXPONENTIAL_DECAY_RETRY",
      ErrorsTolerance:"ALL",
      ParamList:[
        {ResourceKey:"url",Form:"CONSTANT",Value:u},
        {ResourceKey:"Body",Form:"ORIGINAL"},
        {ResourceKey:"Network",Form:"CONSTANT",Value:"PublicNetwork"},
        {ResourceKey:"Token",Form:"CONSTANT",Value:t}
      ]
    }]))')
  # EventBridge is regional: the rule must live in the REGION of the ECS
  # instance, not the CLI's configured default (cn-hangzhou here), or no event
  # will ever match it.
  if ali eventbridge CreateRule --region "$REGION" --EventBusName default --RuleName "$RULE_NAME" \
       --Description "pav: recreate the TDX enclave when ECS reports it gone" \
       --FilterPattern "$FILTER" --EventTargets "$TARGETS" > /tmp/pav-rule.out 2>&1 \
     && grep -q '"Code":"Success"' /tmp/pav-rule.out; then
    echo "eventbridge rule created"
  elif grep -q 'ServiceNotEnable' /tmp/pav-rule.out; then
    EB_GATE=disabled
    cat <<'EOF'

[gate] EventBridge is not activated for this account (ServiceNotEnable), so
       the event rule cannot be created.

       Fix: Alibaba Cloud console -> EventBridge -> activate the service
            (one click, free), then run:
              bash watchdog/deploy-watchdog.sh deploy
            The rule step is idempotent — already-created pieces are reused.

       Until then only the 5-minute timer leg runs: recovery still happens,
       just within 5 minutes instead of seconds.
EOF
  else
    cat /tmp/pav-rule.out
    # already exists? treat as success so re-runs are idempotent
    if grep -qi 'already exists\|Duplicate' /tmp/pav-rule.out; then
      echo "eventbridge rule already present"
    else
      EB_GATE=error
    fi
  fi
}

invoke_once() {
  echo "--- invoking function ---"
  local out
  out=$(ali fc InvokeFunction --functionName "$FN" --body '{}' 2>&1 || true)
  echo "$out" | head -c 1200
  echo
}

status_report() {
  echo "== function =="
  ali fc GetFunction --functionName "$FN" 2>/dev/null | node -e '
    let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
      try{const j=JSON.parse(s);console.log(JSON.stringify({functionName:j.functionName||j.FunctionName,runtime:j.runtime||j.Runtime,timeout:j.timeout||j.Timeout,role:j.role||j.Role,env:Object.keys(j.environmentVariables||j.EnvironmentVariables||{})},null,1))}catch(e){console.log(s.slice(0,400))}})'
  echo "== triggers =="
  ali fc ListTriggers --functionName "$FN" 2>/dev/null | node -e '
    let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
      try{const j=JSON.parse(s);const t=j.triggers||j.Triggers||[];for(const x of t)console.log(JSON.stringify({name:x.triggerName||x.TriggerName,type:x.triggerType||x.TriggerType,config:x.triggerConfig||x.TriggerConfig}))}catch(e){console.log(s.slice(0,400))}})'
  echo "== event rule ($REGION) =="
  ali eventbridge DescribeRule --region "$REGION" --EventBusName default --RuleName "$RULE_NAME" 2>&1 | head -c 500 || true
  echo
  echo "== prod =="
  find_prod
  echo "$PROD_JSON" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const i=JSON.parse(s);console.log(JSON.stringify({id:i.InstanceId,status:i.Status,type:i.InstanceType,image:i.ImageId,eip:i.EipAddress&&i.EipAddress.IpAddress,tags:(i.Tags.Tag||[]).map(t=>t.TagKey+"="+t.TagValue)}))})'
}

# Create a throwaway tagged instance (different tagValue) to prove the
# recreate path, without touching prod. No EIP binding: the allocation is
# already attached to prod and must never be moved.
selftest() {
  require_creds
  capture_spec   # also refreshes PROD_ID/PROD_JSON
  PROD_ID="$PROD_ID" REGION="$REGION" node -e '
    const cfg = JSON.parse(require("fs").readFileSync("dist/config.json","utf8"));
    cfg.tagValue = "selftest";
    cfg.eipAllocationId = "";                    // never touch the reserved EIP
    cfg.spec.instanceName = "paypal-watchdog-selftest";
    cfg.enabled = true;
    console.log(JSON.stringify(cfg));' > /tmp/pav-selftest-config.json
  cat /tmp/pav-selftest-config.json > dist/config.json
  ensure_role
  build_zip
  write_fn_body
  ZIP_B64=$(base64 -w0 dist/pav-watchdog.zip) node -e '
    const fs=require("fs");
    const b=JSON.parse(fs.readFileSync("/tmp/pav-fn-body.json","utf8"));
    b.functionName=process.env.FN+"-selftest";
    b.code={zipFile:process.env.ZIP_B64};
    b.description="SELFTEST of pav-watchdog recreate path — release me";
    fs.writeFileSync("/tmp/pav-fn-selftest-body.json", JSON.stringify(b));'
  FN_S="${FN}-selftest"
  ali fc DeleteFunction --functionName "$FN_S" >/dev/null 2>&1 || true
  ali fc CreateFunction --body "$(cat /tmp/pav-fn-selftest-body.json)" >/dev/null
  echo "--- invoking selftest function (creates a throwaway instance) ---"
  ali fc InvokeFunction --functionName "$FN_S" --body '{}' 2>&1 | head -c 800
  echo
  sleep 5
  echo "--- instances tagged $TAG_KEY=selftest ---"
  ali ecs DescribeInstances --RegionId "$REGION" --Tag.1.Key "$TAG_KEY" --Tag.1.Value selftest \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const l=JSON.parse(s).Instances.Instance||[];if(!l.length){console.log("NONE");process.exit(1)}for(const i of l)console.log(JSON.stringify({id:i.InstanceId,status:i.Status,type:i.InstanceType,image:i.ImageId,zone:i.ZoneId,sg:i.SecurityGroupIds.SecurityGroupId[0],vsw:i.VpcAttributes.VSwitchId,tags:(i.Tags.Tag||[]).map(t=>t.TagKey+"="+t.TagValue)}))})'
}

selftest_cleanup() {
  require_creds
  echo "--- releasing selftest instances ---"
  local ids
  ids=$(ali ecs DescribeInstances --RegionId "$REGION" --Tag.1.Key "$TAG_KEY" --Tag.1.Value selftest \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const l=JSON.parse(s).Instances.Instance||[];console.log(l.map(i=>i.InstanceId).join(" "))})')
  for id in $ids; do
    echo "releasing $id"
    ali ecs DeleteInstance --InstanceId "$id" --Force true 2>&1 | head -c 200 || true
    echo
  done
  ali fc DeleteFunction --functionName "${FN}-selftest" >/dev/null 2>&1 && echo "removed selftest function" || true
  # restore the real config + zip
  capture_spec
  build_zip
  echo "restored dist/config.json to the prod spec"
}

usage() { sed -n '2,30p' "$0"; }

cmd="${1:-deploy}"
case "$cmd" in
  deploy)
    require_creds
    capture_spec
    tag_prod
    ensure_role
    build_zip
    FN_GATE=none
    EB_GATE=skipped
    if create_function; then
      create_triggers
      create_eventbridge_rule
      invoke_once
    else
      echo "[skip] triggers, event rule and smoke invoke — no function exists yet"
    fi
    echo
    echo "=== deploy summary ==="
    if [ "$FN_GATE" = "none" ]; then
      echo "  function : $FN (role $ROLE_NAME)"
      echo "  timer    : $TIMER_NAME (every 5 min)"
    else
      echo "  function : NOT created (gate: $FN_GATE)"
      echo "  timer    : not configured"
    fi
    case "$EB_GATE" in
      none)    echo "  events   : $RULE_NAME" ;;
      skipped) echo "  events   : not configured (skipped — no function)" ;;
      *)       echo "  events   : not configured (gate: $EB_GATE)" ;;
    esac
    if [ "$FN_GATE" = "none" ] && [ "$EB_GATE" = "none" ]; then
      echo "  state    : fully deployed — use '$0 status' / '$0 disable'"
    else
      echo "  state    : INCOMPLETE — clear the gate(s) above, then re-run '$0 deploy'"
      exit 1
    fi
    ;;
  enable|disable)
    require_creds
    val=$([ "$cmd" = "enable" ] && echo true || echo false)
    ali fc GetFunction --functionName "$FN" > /tmp/pav-fn-cur.json
    VAL="$val" FN="$FN" node -e '
      const fs=require("fs");
      const j=JSON.parse(fs.readFileSync("/tmp/pav-fn-cur.json","utf8"));
      const env=Object.assign({}, j.environmentVariables||{});
      env.PAV_WATCHDOG_ENABLED=process.env.VAL;
      fs.writeFileSync("/tmp/pav-fn-update.json", JSON.stringify({functionName:process.env.FN, environmentVariables:env}));
    '
    ali fc UpdateFunction --functionName "$FN" --body "$(cat /tmp/pav-fn-update.json)" >/dev/null && echo "watchdog $cmd'd"
    ;;
  status)   require_creds; status_report ;;
  invoke)   require_creds; invoke_once ;;
  selftest) selftest ;;
  selftest-cleanup) selftest_cleanup ;;
  *) usage; exit 1 ;;
esac
