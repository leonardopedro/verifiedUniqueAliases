#!/bin/bash
# deploy-watchdog.sh — provision the pav-watchdog Function Compute watchdog.
#
# The watchdog replaces the TDX confidential VM when it is RELEASED (spot
# eviction, account-level release). It never touches a Stopped instance, so
# the operator's in-place disk rewrites are safe.
#
#   deploy           tag prod, capture its spec + user_data, create RAM
#                    credentials, build the zip, create the FC function and
#                    both triggers (5-min timer + EventBridge HTTP rule),
#                    then invoke once as a smoke test
#   enable|disable   flip the PAV_WATCHDOG_ENABLED kill switch
#   status           show function, triggers and event rule
#   invoke           run one poll by hand
#   selftest         create a THROWAWAY tagged instance to prove the
#                    recreate path works end to end (prints its id)
#   selftest-cleanup release whatever the selftest created
#
# Config lives in watchdog/dist/config.json (built here, gitignored: it holds
# the enclave user_data, i.e. real secrets). The RAM key pair is written to
# /tmp/pav-watchdog-ak.json with mode 600 and injected as FC env vars — never
# echoed, never committed.
set -euo pipefail
cd "$(dirname "$0")"

REGION="${PAV_REGION:-cn-beijing}"
FN="${PAV_FN:-pav-watchdog}"
RAM_USER="${PAV_RAM_USER:-pav-watchdog}"
POLICY_NAME="${PAV_POLICY:-pav-watchdog-ecs}"
PROD_NAME="${PAV_PROD_NAME:-paypal-auth-vm}"
TAG_KEY="pav-watchdog"
RULE_NAME="pav-prod-watchdog"
TIMER_NAME="poll-5m"
HTTP_TRIG_NAME="eventbridge"
AK_FILE="/tmp/pav-watchdog-ak.json"

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

ensure_ram() {
  ali ram CreateUser --UserName "$RAM_USER" --DisplayName "pav watchdog" 2>/dev/null || echo "ram user exists"
  POLICY_DOC='{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:DescribeInstances","ecs:RunInstances","ecs:DescribeImages","ecs:DescribeDisks","ecs:DescribeTags"],"Resource":"*"},{"Effect":"Allow","Action":["vpc:DescribeEipAddresses","vpc:AssociateEipAddress"],"Resource":"*"}]}'
  ali ram CreatePolicy --PolicyName "$POLICY_NAME" --PolicyDocument "$POLICY_DOC" \
      --Description "pav-watchdog: recreate the TDX enclave box" 2>/dev/null || echo "ram policy exists"
  ali ram AttachPolicyToUser --UserName "$RAM_USER" --PolicyName "$POLICY_NAME" --PolicyType Custom 2>/dev/null || echo "policy already attached"

  local has_ak
  has_ak=$(ali ram ListAccessKeys --UserName "$RAM_USER" | jget 'j.AccessKeys.AccessKey.length' || echo 0)
  if [ "${has_ak:-0}" = "0" ]; then
    ali ram CreateAccessKey --UserName "$RAM_USER" | node -e "
      let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{
        const a=JSON.parse(s).AccessKey;
        require('fs').writeFileSync('$AK_FILE', JSON.stringify({accessKeyId:a.AccessKeyId,accessKeySecret:a.AccessKeySecret}), {mode:0o600});
        console.log('created RAM access key -> $AK_FILE (mode 600)');
      })"
  else
    [ -f "$AK_FILE" ] || die "RAM key exists but $AK_FILE is missing — re-create it (ram CreateAccessKey) and re-run"
    chmod 600 "$AK_FILE"
    echo "reusing RAM access key from $AK_FILE"
  fi
}

build_zip() {
  node make-zip.mjs
  [ -f dist/pav-watchdog.zip ] || die "zip not built"
}

create_function() {
  local b64
  b64=$(base64 -w0 dist/pav-watchdog.zip 2>/dev/null || base64 dist/pav-watchdog.zip | tr -d '\n')
  FN="$FN" AK_FILE="$AK_FILE" ZIP_B64="$b64" node -e '
    const fs = require("fs");
    const ak = JSON.parse(fs.readFileSync(process.env.AK_FILE, "utf8"));
    const body = {
      functionName: process.env.FN,
      handler: "handler.handler",
      runtime: "nodejs20",
      description: "Recreate the TDX enclave if it is released (5-min poll + EventBridge). Never touches a Stopped box.",
      timeout: 300,
      memorySize: 256,
      code: { zipFile: process.env.ZIP_B64 },
      environmentVariables: {
        PAV_AK_ID: ak.accessKeyId,
        PAV_AK_SECRET: ak.accessKeySecret,
        PAV_WATCHDOG_ENABLED: "true",
      },
    };
    fs.writeFileSync("/tmp/pav-fn-body.json", JSON.stringify(body));
  '
  if ali fc GetFunction --functionName "$FN" >/dev/null 2>&1; then
    echo "function exists — replacing code + config"
    ali fc DeleteFunction --functionName "$FN" >/dev/null
  fi
  ali fc CreateFunction --body "$(cat /tmp/pav-fn-body.json)" | head -c 400
  echo
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
  if ali eventbridge CreateRule --EventBusName default --RuleName "$RULE_NAME" \
       --Description "pav: recreate the TDX enclave when ECS reports it gone" \
       --FilterPattern "$FILTER" --EventTargets "$TARGETS" > /tmp/pav-rule.out 2>&1 \
     && grep -q '"Code":"Success"' /tmp/pav-rule.out; then
    echo "eventbridge rule created"
  else
    cat /tmp/pav-rule.out
    # already exists? treat as success so re-runs are idempotent
    if grep -qi 'already exists\|Duplicate' /tmp/pav-rule.out; then
      echo "eventbridge rule already present"
    else
      die "CreateRule failed (see above)"
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
      try{const j=JSON.parse(s);console.log(JSON.stringify({functionName:j.functionName||j.FunctionName,runtime:j.runtime||j.Runtime,timeout:j.timeout||j.Timeout,env:Object.keys(j.environmentVariables||j.EnvironmentVariables||{})},null,1))}catch(e){console.log(s.slice(0,400))}})'
  echo "== triggers =="
  ali fc ListTriggers --functionName "$FN" 2>/dev/null | node -e '
    let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
      try{const j=JSON.parse(s);const t=j.triggers||j.Triggers||[];for(const x of t)console.log(JSON.stringify({name:x.triggerName||x.TriggerName,type:x.triggerType||x.TriggerType,config:x.triggerConfig||x.TriggerConfig}))}catch(e){console.log(s.slice(0,400))}})'
  echo "== event rule =="
  ali eventbridge DescribeRule --EventBusName default --RuleName "$RULE_NAME" 2>&1 | head -c 500 || true
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
  build_zip
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
    ensure_ram
    build_zip
    create_function
    create_triggers
    create_eventbridge_rule
    invoke_once
    echo "=== deployed. use '$0 status' / '$0 disable' ==="
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
