############################################
# VPC
############################################
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.app_name}-vpc"
  }
}

############################################
# Availability Zones
############################################
data "aws_availability_zones" "available" {
  state = "available"
}

############################################
# Subnets
############################################
resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.app_name}-public-${count.index}"
  }
}

resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index + 3)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.app_name}-private-${count.index}"
  }
}

############################################
# Internet Gateway
############################################
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.app_name}-igw"
  }
}

############################################
# NAT Gateways + EIPs
############################################
resource "aws_eip" "nat" {
  count  = 3
  domain = "vpc"

  tags = {
    Name = "${var.app_name}-eip-${count.index}"
  }
}

resource "aws_nat_gateway" "nat" {
  count         = 3
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "${var.app_name}-nat-${count.index}"
  }
}

############################################
# Route Tables
############################################
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${var.app_name}-public-rt"
  }
}

resource "aws_route_table" "private" {
  count  = 3
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[count.index].id
  }

  tags = {
    Name = "${var.app_name}-private-rt-${count.index}"
  }
}

############################################
# Route Table Associations
############################################
resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

############################################
# KMS for Flow Logs
############################################
resource "aws_kms_key" "flow_log" {
  description             = "KMS key for VPC Flow Logs encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

resource "aws_kms_alias" "flow_log" {
  name          = "alias/${var.app_name}-flow-log"
  target_key_id = aws_kms_key.flow_log.key_id
}

############################################
# CloudWatch Log Group
############################################
resource "aws_cloudwatch_log_group" "flow_log" {
  name              = "/aws/vpc/flow-log/${var.app_name}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.flow_log.arn
}

############################################
# IAM Role for VPC Flow Logs
############################################
resource "aws_iam_role" "flow_log" {
  name = "${var.app_name}-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

############################################
# IAM Policy for VPC Flow Logs
# tfsec false-positive suppression justified:
# AWS requires wildcarded log-stream ARNs
############################################
resource "aws_iam_role_policy" "flow_log" {
  #tfsec:ignore:aws-iam-no-policy-wildcards
  name = "${var.app_name}-flow-log-policy"
  role = aws_iam_role.flow_log.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowWriteToSpecificLogGroup"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.flow_log.arn}:*"
      },
      {
        Sid    = "AllowDescribeLogs"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

############################################
# VPC Flow Logs
############################################
resource "aws_flow_log" "vpc" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow_log.arn
  iam_role_arn   = aws_iam_role.flow_log.arn
}
