output "ec2_ssm_role" {
  description = "Default role for EC2 instances to give SSM access"
  value       = "${aws_iam_instance_profile.ec2_ssm_role.name}"
}

output "lambda_report_role" {
  description = "Default role for Lambda Reporting"
  value       = "${aws_iam_role.lambda_reporting_role.arn}"
} 


output "invoke_lambda_role" {
  description = "Default role for Invoking Lambda Functions"
  value       = "${aws_iam_role.invoke_lambda_role.arn}"
} 