locals {
  common_tags = {
    owner   = var.owner
    purpose = var.purpose
  }
}

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "region-name"
    values = [var.region]
  }
}

locals {
  # Use the first available AZ in the region
  # This is more reliable than trying to filter by instance type availability
  selected_az = data.aws_availability_zones.available.names[0]
}

# Inline minimal bootstrap user_data script (heredoc) to bypass AWS 16KB limit

# AMI selection using region mapping for Ubuntu 16.04 (Xenial)

resource "aws_vpc" "vpc" {
  cidr_block           = "10.77.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.common_tags, { Name = "cnappuccino-vpc" })
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = "10.77.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = local.selected_az
  tags                    = merge(local.common_tags, { Name = "cnappuccino-public" })
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags   = merge(local.common_tags, { Name = "cnappuccino-igw" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = merge(local.common_tags, { Name = "cnappuccino-rt" })
}

resource "aws_route_table_association" "a" {
  route_table_id = aws_route_table.public.id
  subnet_id      = aws_subnet.public.id
}

resource "aws_security_group" "ec2" {
  name        = "cnappuccino-ec2-sg"
  description = "Base SG for CNAPPuccino lab"
  vpc_id      = aws_vpc.vpc.id

  # SSH access
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # HTTP for Apache/CGI Shellshock testing
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # HTTPS for Heartbleed testing
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # Nginx alternate ports
  ingress {
    description = "Nginx HTTP Alt"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  ingress {
    description = "Nginx HTTPS Alt"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # MySQL for database testing
  ingress {
    description = "MySQL"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }
  
  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "cnappuccino-ec2-sg" })
}

resource "aws_key_pair" "kp" {
  key_name   = "cnappuccino-kp"
  public_key = file(var.ssh_pub_key_path)
  tags       = merge(local.common_tags, { Name = "cnappuccino-kp" })
}

# GitHub-based asset management - no S3 dependencies
# Assets are downloaded directly from GitHub raw URLs during bootstrap

# No S3 permissions needed - using GitHub raw URLs for asset downloads




# Minimal instance role and profile. Assume-role to Lambda arrives in a later step.
data "aws_iam_policy_document" "ec2_trust" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "instance_role" {
  name               = "cnappuccino_lab_instance_role"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
  tags               = local.common_tags
}

############################################################
# Lambda Admin Role and cross-role AssumeRole privilege for CIEM simulation
############################################################

# Trust policy so only cnappuccino_lab_instance_role can assume this LambdaAdminRole
# Also allow Lambda service to assume the role for function execution
data "aws_iam_policy_document" "lambda_admin_trust" {
  statement {
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [
        aws_iam_role.instance_role.arn
      ]
    }
    actions = ["sts:AssumeRole"]
  }
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "lambda_admin" {
  name               = "LambdaAdminRole"
  assume_role_policy = data.aws_iam_policy_document.lambda_admin_trust.json
  tags               = local.common_tags
}

# Attach AWSLambda_FullAccess policy so compromised LambdaAdminRole has admin on Lambda
resource "aws_iam_role_policy_attachment" "lambda_admin_fullaccess" {
  role       = aws_iam_role.lambda_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AWSLambda_FullAccess"
}

# EC2 instance role permission to assume LambdaAdminRole
data "aws_iam_policy_document" "ec2_can_assume_lambdaadmin" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRole"]
    resources = [
      aws_iam_role.lambda_admin.arn
    ]
  }
}

resource "aws_iam_role_policy" "ec2_assume_lambdaadmin" {
  name   = "AllowAssumeLambdaAdmin"
  role   = aws_iam_role.instance_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "sts:AssumeRole",
          "iam:GetRole",
          "iam:ListRolePolicies",
          "iam:GetRolePolicy",
          "iam:SimulatePrincipalPolicy",
          "iam:GetInstanceProfile"
        ],
        Resource = [
          aws_iam_role.lambda_admin.arn,
          aws_iam_role.instance_role.arn,
          aws_iam_instance_profile.instance_profile.arn
        ]
      }
    ]
  })
}


resource "aws_iam_instance_profile" "instance_profile" {
  name = "cnappuccino_lab_instance_profile"
  role = aws_iam_role.instance_role.name
  tags = local.common_tags
}

resource "aws_instance" "host" {
  ami                         = lookup(var.xenial_ami_map, var.region, var.ami_id)
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.ec2.id]
  key_name                    = aws_key_pair.kp.key_name
  iam_instance_profile        = aws_iam_instance_profile.instance_profile.name
  associate_public_ip_address = true
  
  # No S3 dependencies - using GitHub-based asset management

  metadata_options {
    http_tokens = "optional" # IMDSv1 reachable (intentionally insecure)
  }

  user_data = <<-EOT
    #!/bin/bash
    # CNAPPuccino Minimal Bootstrap - Downloads full script from GitHub
    # This minimal script works around Terraform's 16KB user_data limit

    set -euo pipefail

    # Set environment variables for Terraform interpolation
    export LAMBDA_ADMIN_ROLE_ARN="${aws_iam_role.lambda_admin.arn}"
    export AWS_DEFAULT_REGION="${var.region}"

    # Create required directories
    mkdir -p /opt/cnappuccino/state /tmp/cnappuccino-setup 2>/dev/null || true

    # Download and execute the full bootstrap script from GitHub
    echo "=== Downloading CNAPPuccino Bootstrap Script ==="
    if curl -fsSL --connect-timeout 30 --max-time 60 \
        "https://raw.githubusercontent.com/adilio/CNAPPuccino/main/terraform/user_data.sh" \
        -o /tmp/bootstrap.sh; then

        echo "✅ Bootstrap script downloaded successfully"
        chmod +x /tmp/bootstrap.sh

        # Execute the bootstrap script
        echo "🚀 Executing bootstrap script..."
        bash /tmp/bootstrap.sh

    else
        echo "❌ Failed to download bootstrap script from GitHub"
        echo "Falling back to minimal setup..."

        # Minimal fallback setup
        apt-get update -qq && apt-get install -yq apache2 curl
        systemctl enable apache2 && systemctl start apache2

        # Create basic CGI script
        mkdir -p /usr/lib/cgi-bin
        cat > /usr/lib/cgi-bin/exec.cgi << 'EOF'
#!/bin/bash
echo "Content-type: text/plain"
echo ""
echo "CNAPPuccino CGI Endpoint - Fallback Mode"
echo "Bootstrap script download failed, running in minimal mode"
EOF
        chmod +x /usr/lib/cgi-bin/exec.cgi

        echo "✅ Minimal setup complete - basic functionality available"
    fi
  EOT

  tags = merge(local.common_tags, { Name = "cnappuccino-host" })
}
 
# Allocate and associate a static Elastic IP to preserve public IP across applies/restarts
resource "aws_eip" "lab_ip" {
  instance   = aws_instance.host.id
  domain     = "vpc"
  depends_on = [aws_internet_gateway.igw]
  tags       = merge(local.common_tags, { Name = "cnappuccino-elastic-ip" })
}

# Debug output to confirm AMI resolution before provisioning
output "debug_selected_ami" {
  value = lookup(var.xenial_ami_map, var.region, var.ami_id)
}

# Output LambdaAdminRole ARN for debugging
output "lambda_admin_role_arn" {
  value = aws_iam_role.lambda_admin.arn
}

# Output EC2 instance role ARN for comparison
output "instance_role_arn" {
  value = aws_iam_role.instance_role.arn
}