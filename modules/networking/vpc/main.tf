# modules/networking/vpc/main.tf
# Bank-Grade VPC Module with PCI-DSS/NIST Compliance

terraform {
  required_version = ">= 1.6.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Data Sources
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # Calculate subnet CIDRs automatically
  az_count = var.multi_az ? 3 : 2
  
  # Public subnets: .0.0/24, .1.0/24, .2.0/24
  public_subnet_cidrs = [
    for i in range(local.az_count) :
    cidrsubnet(var.vpc_cidr, 8, i)
  ]
  
  # Private subnets: .10.0/24, .11.0/24, .12.0/24
  private_subnet_cidrs = [
    for i in range(local.az_count) :
    cidrsubnet(var.vpc_cidr, 8, i + 10)
  ]
  
  # Data subnets: .20.0/24, .21.0/24, .22.0/24
  data_subnet_cidrs = [
    for i in range(local.az_count) :
    cidrsubnet(var.vpc_cidr, 8, i + 20)
  ]
  
  azs = slice(data.aws_availability_zones.available.names, 0, local.az_count)
  
  common_tags = merge(
    var.tags,
    {
      ManagedBy   = "terraform"
      Module      = "networking/vpc"
      Environment = var.environment
      Compliance  = "pci-dss-nist-800-53"
    }
  )
}

################################################################################
# VPC
################################################################################

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # Enable VPC Flow Logs for compliance
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-vpc"
    }
  )
}

################################################################################
# VPC Flow Logs (NIST SC-7, PCI-DSS 10.3)
################################################################################

resource "aws_flow_log" "vpc" {
  count = var.enable_flow_logs ? 1 : 0
  
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs[0].arn
  log_destination = aws_cloudwatch_log_group.flow_logs[0].arn
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-vpc-flow-logs"
    }
  )
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  
  name              = "/aws/vpc/${var.environment}/flow-logs"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = var.kms_key_arn
  
  tags = local.common_tags
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  
  name = "${var.environment}-vpc-flow-logs-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  
  name = "${var.environment}-vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs[0].id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

################################################################################
# Internet Gateway
################################################################################

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-igw"
    }
  )
}

################################################################################
# Public Subnets (DMZ)
################################################################################

resource "aws_subnet" "public" {
  count = local.az_count
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false  # Security: No auto-assign public IPs
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-public-${local.azs[count.index]}"
      Tier = "public"
      Zone = "dmz"
    }
  )
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-public-rt"
      Tier = "public"
    }
  )
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  count = local.az_count
  
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Public Network ACL (PCI-DSS 1.2)
resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.public[*].id
  
  # Inbound: HTTPS from internet
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }
  
  # Inbound: HTTP for redirect to HTTPS
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }
  
  # Inbound: Ephemeral ports for return traffic
  ingress {
    rule_no    = 120
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }
  
  # Outbound: All traffic (controlled by security groups)
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-public-nacl"
      Tier = "public"
    }
  )
}

################################################################################
# Private Subnets (Application Tier)
################################################################################

resource "aws_subnet" "private" {
  count = local.az_count
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]
  
  tags = merge(
    local.common_tags,
    {
      Name                              = "${var.environment}-private-${local.azs[count.index]}"
      Tier                              = "private"
      Zone                              = "application"
      "kubernetes.io/role/internal-elb" = "1"  # For EKS
    }
  )
}

# NAT Gateways (one per AZ for high availability)
resource "aws_eip" "nat" {
  count = local.az_count
  
  domain = "vpc"
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-nat-eip-${local.azs[count.index]}"
    }
  )
  
  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  count = local.az_count
  
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-nat-${local.azs[count.index]}"
    }
  )
  
  depends_on = [aws_internet_gateway.main]
}

# Private Route Tables (one per AZ)
resource "aws_route_table" "private" {
  count = local.az_count
  
  vpc_id = aws_vpc.main.id
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-private-rt-${local.azs[count.index]}"
      Tier = "private"
    }
  )
}

resource "aws_route" "private_nat" {
  count = local.az_count
  
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[count.index].id
}

resource "aws_route_table_association" "private" {
  count = local.az_count
  
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Private Network ACL
resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id
  
  # Inbound: From public subnets
  ingress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }
  
  # Inbound: Ephemeral ports from internet (for NAT return traffic)
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }
  
  # Outbound: All traffic
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-private-nacl"
      Tier = "private"
    }
  )
}

################################################################################
# Data Subnets (Database Tier) - ISOLATED
################################################################################

resource "aws_subnet" "data" {
  count = local.az_count
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.data_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-data-${local.azs[count.index]}"
      Tier = "data"
      Zone = "database"
    }
  )
}

# Data Route Table (NO internet access)
resource "aws_route_table" "data" {
  vpc_id = aws_vpc.main.id
  
  # No default route - completely isolated
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-data-rt"
      Tier = "data"
    }
  )
}

resource "aws_route_table_association" "data" {
  count = local.az_count
  
  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.data.id
}

# Data Network ACL (Most Restrictive)
resource "aws_network_acl" "data" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.data[*].id
  
  # Inbound: Only from private subnets
  dynamic "ingress" {
    for_each = local.private_subnet_cidrs
    content {
      rule_no    = 100 + ingress.key
      protocol   = "tcp"
      action     = "allow"
      cidr_block = ingress.value
      from_port  = 3306  # MySQL/Aurora
      to_port    = 3306
    }
  }
  
  dynamic "ingress" {
    for_each = local.private_subnet_cidrs
    content {
      rule_no    = 200 + ingress.key
      protocol   = "tcp"
      action     = "allow"
      cidr_block = ingress.value
      from_port  = 5432  # PostgreSQL
      to_port    = 5432
    }
  }
  
  # Outbound: Only to private subnets
  dynamic "egress" {
    for_each = local.private_subnet_cidrs
    content {
      rule_no    = 100 + egress.key
      protocol   = "tcp"
      action     = "allow"
      cidr_block = egress.value
      from_port  = 1024
      to_port    = 65535
    }
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-data-nacl"
      Tier = "data"
    }
  )
}

################################################################################
# VPC Endpoints (PrivateLink) - NIST SC-7
################################################################################

# S3 Gateway Endpoint (no data charges)
resource "aws_vpc_endpoint" "s3" {
  count = var.enable_vpc_endpoints ? 1 : 0
  
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat(aws_route_table.private[*].id, [aws_route_table.data.id])
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-s3-endpoint"
    }
  )
}

# DynamoDB Gateway Endpoint
resource "aws_vpc_endpoint" "dynamodb" {
  count = var.enable_vpc_endpoints ? 1 : 0
  
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat(aws_route_table.private[*].id, [aws_route_table.data.id])
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-dynamodb-endpoint"
    }
  )
}

# EC2 Interface Endpoint
resource "aws_vpc_endpoint" "ec2" {
  count = var.enable_vpc_endpoints ? 1 : 0
  
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ec2"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints[0].id]
  private_dns_enabled = true
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-ec2-endpoint"
    }
  )
}

# Security Group for VPC Endpoints
resource "aws_security_group" "vpc_endpoints" {
  count = var.enable_vpc_endpoints ? 1 : 0
  
  name_prefix = "${var.environment}-vpce-"
  description = "Security group for VPC endpoints"
  vpc_id      = aws_vpc.main.id
  
  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-vpce-sg"
    }
  )
  
  lifecycle {
    create_before_destroy = true
  }
}

################################################################################
# Default Security Group (Lock Down)
################################################################################

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  
  # No rules = deny all
  # This prevents accidental use of default SG
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-default-sg-locked"
    }
  )
}

################################################################################
# DHCP Options
################################################################################

resource "aws_vpc_dhcp_options" "main" {
  domain_name_servers = ["AmazonProvidedDNS"]
  domain_name         = data.aws_region.current.name == "us-east-1" ? "ec2.internal" : "${data.aws_region.current.name}.compute.internal"
  
  tags = merge(
    local.common_tags,
    {
      Name = "${var.environment}-dhcp-options"
    }
  )
}

resource "aws_vpc_dhcp_options_association" "main" {
  vpc_id          = aws_vpc.main.id
  dhcp_options_id = aws_vpc_dhcp_options.main.id
}
