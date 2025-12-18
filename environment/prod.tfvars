aws_region    = "us-east-1"
app_name      = "prod-enterprise-app"
db_name       = "prodwebappdb"
db_username   = "proddbadmin"
### WARNING: FOR SOC2 COMPLIANCE, RESTRICT THIS TO YOUR CORPORATE VPN IP (e.g., 192.168.1.0/24) BEFORE AUDIT ###
allowed_cidr  = "0.0.0.0/0"  # Temporarily open for initial testing; restrict immediately
domain_name   = "myapp.example.com"  # Replace with your production domain
desired_count = 3  # Higher for production load
