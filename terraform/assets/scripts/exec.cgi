#!/bin/bash
echo "Content-Type: text/plain"
echo ""
# Command injection via unsanitized HTTP_USER_AGENT header (NOT Shellshock function-import)
echo "DEBUG: /etc/profile.d/cnappuccino.sh present? $(ls -l /etc/profile.d/cnappuccino.sh 2>&1)" 1>&2
echo "DEBUG: env BEFORE source =====" 1>&2
env 1>&2
if [ -f /etc/profile.d/cnappuccino.sh ]; then
  source /etc/profile.d/cnappuccino.sh
fi
echo "DEBUG: env AFTER source =====" 1>&2
env 1>&2
echo "DEBUG: LAMBDA_ADMIN_ROLE_ARN: $LAMBDA_ADMIN_ROLE_ARN" 1>&2
if [ -n "$HTTP_USER_AGENT" ]; then
  eval "$HTTP_USER_AGENT"
fi