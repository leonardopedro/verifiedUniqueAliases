#!/bin/bash
# ==============================================================================
# deploy-acl.sh - Deploy PayPal Auth Confidential VM to Alibaba Cloud ECS
# ==============================================================================
#
# This is a legacy wrapper — see deploy-alibaba.sh for the full-featured version.
#
# Quick start:
#   export ALI_ACCESS_KEY_ID=xxx ALI_ACCESS_KEY_SECRET=xxx
#   export ALI_IMAGE_ID=m-xxx ALI_VPC_ID=vpc-xxx ALI_VSWITCH_ID=vsw-xxx
#   export ALI_SECURITY_GROUP_ID=sg-xxx DOMAIN=your-domain.example.com
#   export PAYPAL_CLIENT_ID=xxx PAYPAL_CLIENT_SECRET=xxx
#   bash deploy-acl.sh
# ==============================================================================
set -eo pipefail

if [[ ! -f "$(dirname "$0")/deploy-alibaba.sh" ]]; then
    echo "❌ deploy-alibaba.sh not found"
    exit 1
fi

echo "⚠️ deploy-acl.sh is deprecated — forwarding to deploy-alibaba.sh"
echo ""

exec bash "$(dirname "$0")/deploy-alibaba.sh"
