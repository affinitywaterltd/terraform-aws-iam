output "ec2_ssm_role" {
  description = "Default role for EC2 instances to give SSM access"
  value       = "${aws_iam_instance_profile.ec2_ssm_role.name}"
}

##### temp output of arn
output "admin_role" {
  value = "${aws_iam_instance_profile.admin_role.arn}"
}
