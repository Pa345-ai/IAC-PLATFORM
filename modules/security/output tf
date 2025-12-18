output "alb_dns" { value = aws_lb.main.dns_name }
output "target_group_arn" { value = aws_lb_target_group.app.arn }
output "alb_sg_id" { value = aws_security_group.alb.id }
output "ecs_sg_id" { value = aws_security_group.ecs.id }
output "rds_sg_id" { value = aws_security_group.rds.id }
output "sg_ids" { value = { alb = aws_security_group.alb.id, ecs = aws_security_group.ecs.id, rds = aws_security_group.rds.id } }
output "route53_nameservers" { value = aws_route53_zone.main.name_servers }
