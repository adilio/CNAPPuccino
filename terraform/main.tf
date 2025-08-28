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

# S3 bucket for bootstrapping files like user_daa.sh
resource "aws_s3_bucket" "bootstrap" {
  bucket        = "cnappuccino-bootstrap"
  force_destroy = true

  tags = merge(
    local.common_tags,
    { Name = "cnappuccino-bootstrap" }
  )
}

resource "aws_s3_bucket_versioning" "bootstrap" {
  bucket = aws_s3_bucket.bootstrap.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bootstrap" {
  bucket = aws_s3_bucket.bootstrap.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Upload the user_data script to S3 during apply
resource "aws_s3_object" "user_data_gist" {
  bucket        = aws_s3_bucket.bootstrap.bucket
  key           = "user_data.sh"
  source        = "${path.module}/user_data.sh"
  etag          = filemd5("${path.module}/user_data.sh")
}

# Asset files mapping for DRY S3 upload
locals {
  vulnerable_assets = {
    # Scripts (executable)
    "assets/scripts/exec.cgi"                           = "assets/scripts/exec.cgi"
    "assets/scripts/ciem_test.sh"                       = "assets/scripts/ciem_test.sh"
    "assets/scripts/command_injection_test.sh"          = "assets/scripts/command_injection_test.sh"
    "assets/scripts/webshell.php"                       = "assets/scripts/webshell.php"
    
    # Web content
    "assets/web/index.html"                             = "assets/web/index.html"
    "assets/web/upload.php"                             = "assets/web/upload.php"
    "assets/web/view.php"                               = "assets/web/view.php"
    
    # Configuration files
    "assets/configs/apache-vhost.conf"                  = "assets/configs/apache-vhost.conf"
    "assets/configs/nginx-vulnerable.conf"              = "assets/configs/nginx-vulnerable.conf"
    "assets/configs/fastcgi-php.conf"                   = "assets/configs/fastcgi-php.conf"
    "assets/configs/cgi-enabled.conf"                   = "assets/configs/cgi-enabled.conf"
    "assets/configs/ubuntu-trusty-sources.list"         = "assets/configs/ubuntu-trusty-sources.list"
    "assets/configs/cnappuccino-vulnerable-preferences" = "assets/configs/cnappuccino-vulnerable-preferences"
  }
}

# Upload all asset files to S3 using for_each (DRY approach)
resource "aws_s3_object" "vulnerable_assets" {
  for_each = local.vulnerable_assets
  
  bucket = aws_s3_bucket.bootstrap.bucket
  key    = each.key
  source = "${path.module}/${each.value}"
  etag   = filemd5("${path.module}/${each.value}")
  
  tags = merge(local.common_tags, {
    AssetType = "vulnerable-content"
    AssetPath = each.key
  })
}

# S3 assets are downloaded using AWS CLI with instance profile credentials

# IAM policy for EC2 instance role to read bootstrap script from S3
resource "aws_iam_role_policy" "instance_role_s3_read" {
  name = "AllowReadBootstrapScript"
  role = aws_iam_role.instance_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject"
        ],
        Resource = "${aws_s3_bucket.bootstrap.arn}/*"
      },
      {
        Effect = "Allow",
        Action = [
          "s3:ListBucket"
        ],
        Resource = "${aws_s3_bucket.bootstrap.arn}"
      }
    ]
  })
}




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

  metadata_options {
    http_tokens = "optional" # IMDSv1 reachable (intentionally insecure)
  }

  user_data = <<-EOT
    #!/bin/bash
    TMP_SCRIPT="/tmp/cnappuccino_full_setup.sh"
    echo "[BOOTSTRAP] Downloading full CNAPPuccino setup script from S3 using instance profile credentials..."
    # Install AWS CLI if not present
    if ! command -v aws >/dev/null 2>&1; then
        apt-get update -y && apt-get install -y awscli
    fi
    # Set environment variables for Terraform interpolation
    export LAMBDA_ADMIN_ROLE_ARN="${aws_iam_role.lambda_admin.arn}"
    export AWS_DEFAULT_REGION="${var.region}"
    export S3_BUCKET="${aws_s3_bucket.bootstrap.bucket}"
    
    # Download using instance profile credentials
    aws s3 cp "s3://${aws_s3_bucket.bootstrap.bucket}/user_data.sh" "$TMP_SCRIPT" --region "${var.region}"
    if [ ! -s "$TMP_SCRIPT" ]; then
        echo "[BOOTSTRAP] ERROR: Failed to download full setup script from s3://${aws_s3_bucket.bootstrap.bucket}/user_data.sh"
        exit 1
    fi
    chmod +x "$TMP_SCRIPT"
    echo "[BOOTSTRAP] Executing full CNAPPuccino setup script..."
    bash "$TMP_SCRIPT"
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