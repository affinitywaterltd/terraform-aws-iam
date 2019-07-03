output "ec2_ssm_role" {
  description = "Default role for EC2 instances to give SSM access"
  value       = "${aws_iam_instance_profile.ec2_ssm_role.name}"
}

output "lambda_report_role" {
  description = "Default role for Lambda Reporting"
  value       = "${aws_iam_role.lambda_reporting_role.arn}"
} 

output "lambda_snapshot_cleanup_role" {
  description = "Default role for Snapshot cleanups"
  value       = "${aws_iam_role.lambda_snapshot_cleanup_role.arn}"
} 

output "ssm_service_role" {
  description = "SSM Service Linked Role"
  value       = "${aws_iam_service_linked_role.iam_service_linked_role_for_ssm.arn}"
} 

output "sophos_central_aws" {
  description = "Sophos Central Console Connector Role"
  value       = "${aws_iam_role.sophos_central_aws.arn}"
} 