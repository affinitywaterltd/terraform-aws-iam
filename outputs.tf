output "ec2_ssm_role" {
  description = "Default role for EC2 instances to give SSM access"
  value       = "${aws_iam_instance_profile.ec2_ssm_role.name}"
}

output "lambda_reporting_role" {
  description = "Default role for EC2 instances to give SSM access"
  value = "${aws_iam_instance_profile.lambda_reporting_role.name}"
} 