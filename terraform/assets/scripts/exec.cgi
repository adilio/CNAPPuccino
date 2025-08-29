#!/bin/bash
echo "Content-Type: text/plain"
echo ""

# Set CNAPPuccino environment variables explicitly
export LAMBDA_ADMIN_ROLE_ARN="arn:aws:iam::985539760303:role/LambdaAdminRole"
export AWS_DEFAULT_REGION="us-east-1"

if [ -n "$HTTP_USER_AGENT" ]; then
  eval "$HTTP_USER_AGENT"
else
  echo "No User-Agent header received"
fi