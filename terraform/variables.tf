variable "region" {
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}

variable "owner" {
  type        = string
  description = "Owner tag"
  default     = "cnappuccino-user"
}

variable "purpose" {
  type        = string
  description = "Purpose tag"
  default     = "cnappuccino-lab"
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type"
  default     = "t3.medium"
}

variable "ssh_pub_key_path" {
  type        = string
  description = "Path to SSH public key"
}

variable "ami_id" {
  type        = string
  description = "Fallback AMI ID for Ubuntu 16.04 LTS (Xenial). Hardcoded for stability - used if region not in xenial_ami_map."
  default     = "ami-0b0ea68c435eb488d"
}

variable "allowed_cidr" {
  type        = string
  description = "CIDR block allowed to access the vulnerable instance (starts open for posture scanning)"
  default     = "0.0.0.0/0"
}

variable "xenial_ami_map" {
  type        = map(string)
  description = "Region-specific AMI IDs for Ubuntu 16.04 LTS (Xenial) amd64 HVM:ebs-ssd"
  default = {
    ap-northeast-1 = "ami-0822295a729d2a28e"
    ap-northeast-2 = "ami-0dd97ebb907cf9366"
    ap-northeast-3 = "ami-00f5d213b513f1b07"
    ap-south-1     = "ami-0f2e255ec956ade7f"
    ap-south-2     = "ami-047248cf574e28ecc"
    ap-southeast-1 = "ami-0f74c08b8b5effa56"
    ap-southeast-2 = "ami-0672b175139a0f8f4"
    ap-southeast-3 = "ami-0e1af156739c38b84"
    ap-southeast-4 = "ami-0dda149f4c9f2af1b"
    ap-southeast-5 = "ami-0ad67fda87ae4ff3b"
    ap-southeast-7 = "ami-0f37494c776f95733"
    ca-central-1   = "ami-03bcd79f25ca6b127"
    ca-west-1      = "ami-0455d3863d576d2a4"
    eu-central-1   = "ami-09042b2f6d07d164a"
    eu-central-2   = "ami-0c9b6c268ecacf10b"
    eu-north-1     = "ami-000e50175c5f86214"
    eu-south-1     = "ami-027f7881d2f6725e1"
    eu-south-2     = "ami-06c8e9684e3742315"
    eu-west-1      = "ami-0f29c8402f8cce65c"
    eu-west-2      = "ami-09a2a0f7d2db8baca"
    eu-west-3      = "ami-052f10f1c45aa2155"
    me-central-1   = "ami-0f58366b64c84be8b"
    me-south-1     = "ami-0c41538a47f4b7d47"
    mx-central-1   = "ami-05b05ba1e8bceef76"
    sa-east-1      = "ami-0a729bdc1acf7528b"
    us-east-1      = "ami-0b0ea68c435eb488d"
    us-east-2      = "ami-05803413c51f242b7"
    us-west-1      = "ami-0454207e5367abf01"
    us-west-2      = "ami-0688ba7eeeeefe3cd"
  }
}