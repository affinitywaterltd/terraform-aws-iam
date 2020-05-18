output "ec2_ssm_role" {
  description = "Default role for EC2 instances to give SSM access"
  value       = aws_iam_instance_profile.ec2_ssm_role.name
}

output "lambda_report_role" {
  description = "Default role for Lambda Reporting"
  value       = aws_iam_role.lambda_reporting_role.arn
}

output "lambda_snapshot_cleanup_role" {
  description = "Default role for MW Snapshot cleanups"
  value       = aws_iam_role.lambda_snapshot_cleanup_role.arn
}

output "lambda_maintenance_window_update_role" {
  description = "Default role for MW Updates"
  value       = aws_iam_role.lambda_maintenance_window_update_role.arn
}

output "lambda_ec2_tagging_citrix_mcs_servers_role" {
  description = "Default role for Tagging Citrix MCS EC2s"
  value       = aws_iam_role.lambda_ec2_tagging_citrix_mcs_servers_role.arn
}

output "lambda_cloudwatch_logs_expiration_role" {
  description = "Default role for configuring expiration on all unconfigured Cloudwatch Logs"
  value       = aws_iam_role.lambda_cloudwatch_logs_expiration_role.arn
}

output "ssm_service_role" {
  description = "SSM Service Linked Role"
  value       = aws_iam_role.iam_service_linked_role_for_ssm.arn
}

output "sophos_central_aws" {
  description = "Sophos Central Console Connector Role"
  value       = aws_iam_role.sophos_central_aws.arn
}

output "ssm_maintenance_window_create_image_role" {
  description = "IAM role used by CreateImage automation task"
  value       = aws_iam_role.ssm_maintenance_window_create_image_role.arn
}

output "ssm_maintenance_window_start_instance_role" {
  description = "IAM role used by StartStoppedInstances automation task"
  value       = aws_iam_role.ssm_maintenance_window_start_instance_role.arn
}

output "rds_enhanced_monitoring_role" {
  description = "IAM role used for RDS Enhanced Monitoring"
  value       = aws_iam_role.rds_enhanced_monitoring_role.arn
}

output "elasticbeanstalk_ec2_role" {
  description = "IAM role used for ElasticBeanstalk EC2"
  value       = aws_iam_role.elasticbeanstalk_ec2_role.arn
}

output "elasticbeanstalk_service_role" {
  description = "IAM role used for ElasticBeanstalk Service"
  value       = aws_iam_role.elasticbeanstalk_service_role.arn
}

output "aws_instace_scheduler_role" {
  description = "AWS Instance Scheduler Role"
  value       = aws_iam_role.aws_instace_scheduler_role.arn
}
